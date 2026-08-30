#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

namespace {

constexpr useconds_t WATCHDOG_INTERVAL_US = 250000;

bool hasTracerPid() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == nullptr) {
        return false;
    }

    char line[256] = {0};
    bool traced = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = 0;
            if (sscanf(line + 10, "%d", &pid) == 1 && pid != 0) {
                traced = true;
            }
            break;
        }
    }
    fclose(fp);
    return traced;
}

bool isProtectedDexMapping(const char *line) {
    if (line == nullptr) {
        return false;
    }

    // ART uses different labels across Android releases for ByteBuffer-backed DEX files.
    // Restrict this to DEX-specific VMAs; never apply process-wide madvise to the Java heap.
    static const char *dexMarkers[] = {
            "Anonymous-DexFile",
            "InMemoryDexFile",
            "[anon:dalvik-classes",
            "[anon:dalvik-dex"
    };
    for (const char *marker : dexMarkers) {
        if (strstr(line, marker) != nullptr) {
            return true;
        }
    }
    return false;
}

void markMappingDontDump(const char *line) {
#ifndef MADV_DONTDUMP
    (void) line;
#else
    if (!isProtectedDexMapping(line)) {
        return;
    }

#ifdef __LP64__
    unsigned long long start = 0;
    unsigned long long end = 0;
    if (sscanf(line, "%llx-%llx", &start, &end) != 2 || end <= start) {
        return;
    }
    const uintptr_t begin = static_cast<uintptr_t>(start);
    const uintptr_t finish = static_cast<uintptr_t>(end);
#else
    unsigned long start = 0;
    unsigned long end = 0;
    if (sscanf(line, "%lx-%lx", &start, &end) != 2 || end <= start) {
        return;
    }
    const uintptr_t begin = static_cast<uintptr_t>(start);
    const uintptr_t finish = static_cast<uintptr_t>(end);
#endif

    // /proc/self/maps boundaries are page aligned. Failure is intentionally best-effort:
    // some vendor kernels reject advice on special ART mappings, which must not break app start.
    (void) madvise(reinterpret_cast<void *>(begin), finish - begin, MADV_DONTDUMP);
#endif
}

bool hasRuntimeInstrumentationMarker() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return false;
    }

    static const char *markers[] = {
            "frida-agent",
            "frida-gadget",
            "libfrida-gadget",
            "xposed",
            "lsposed",
            "edxp",
            "lsplant",
            "sandhook",
            "yahfa"
    };

    char line[1024] = {0};
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        // Keep ART's protected anonymous/in-memory DEX VMAs out of ordinary dump paths.
        // This complements, rather than replaces, PR_SET_DUMPABLE=0 and per-method wrapping.
        markMappingDontDump(line);

        for (const char *marker : markers) {
            if (strstr(line, marker) != nullptr) {
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
    }
    fclose(fp);
    return found;
}

void lockProcessDumping() {
    (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#ifdef PR_SET_PTRACER
    // Clear any Yama ptracer exception that may have been inherited/installed. This is
    // additive to dumpable=0; a fully privileged/root observer still cannot be ruled out.
    (void) prctl(PR_SET_PTRACER, 0, 0, 0, 0);
#endif
    struct rlimit coreLimit = {0, 0};
    (void) setrlimit(RLIMIT_CORE, &coreLimit);
}

[[noreturn]] void terminateProtectedProcess() {
    // Defensive quarantine only: terminate this protected app process. Never touch
    // user files, device storage, other processes, or hardware state.
    (void) kill(getpid(), SIGKILL);
    _exit(173);
}

void *parallaxHardeningWatchdog(void *) {
    for (;;) {
        lockProcessDumping();
        if (hasTracerPid() || hasRuntimeInstrumentationMarker()) {
            terminateProtectedProcess();
        }
        usleep(WATCHDOG_INTERVAL_US);
    }
}

} // namespace

// Apply process-level dump hardening as soon as the shell library is loaded and keep
// reasserting it during the lifetime of the protected process.
__attribute__((constructor))
static void parallax_harden_process() {
#ifndef DEBUG
    lockProcessDumping();

    pthread_t watchdog{};
    if (pthread_create(&watchdog, nullptr, parallaxHardeningWatchdog, nullptr) == 0) {
        (void) pthread_detach(watchdog);
    }
#endif
}
