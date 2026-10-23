#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <link.h>
#include <mbedtls/sha256.h>

#include "parallax_crypto.h"
#include "parallax_util.h"

namespace {

constexpr useconds_t WATCHDOG_INTERVAL_US = 250000;
constexpr uintptr_t MIN_ANON_REGION_SIZE = 64U * 1024U;
constexpr size_t NATIVE_TEXT_LIMIT = 8U * 1024U * 1024U;

struct NativeTextSeal {
    uint8_t magic[8];
    uint64_t textVirtualAddress;
    uint64_t textSize;
    uint8_t digest[32];
    uint8_t tail[8];
} __attribute__((packed));

__attribute__((used, section(".data.parallax_seal"), aligned(8)))
static const NativeTextSeal g_nativeTextSeal = {
        {'P', 'X', 'H', 'A', 'S', 'H', '0', '1'},
        0,
        0,
        {0},
        {'P', 'X', 'E', 'N', 'D', '0', '0', '1'}
};

[[noreturn]] void terminateProtectedProcess();

bool verifyNativeTextHash() {
    if (g_nativeTextSeal.textSize == 0
        || g_nativeTextSeal.textSize > NATIVE_TEXT_LIMIT) {
        return false;
    }

    Dl_info info{};
    if (dladdr(reinterpret_cast<void *>(&verifyNativeTextHash), &info) == 0
        || info.dli_fbase == nullptr) {
        return false;
    }

    bool sealed = false;
    for (uint8_t byte : g_nativeTextSeal.digest) {
        sealed = sealed || byte != 0;
    }
    if (!sealed) {
        return false;
    }

    const auto *text = reinterpret_cast<const uint8_t *>(
            reinterpret_cast<uintptr_t>(info.dli_fbase)
            + static_cast<uintptr_t>(g_nativeTextSeal.textVirtualAddress));
    uint8_t digest[32] = {0};
    mbedtls_sha256(text,
                   static_cast<size_t>(g_nativeTextSeal.textSize),
                   digest,
                   0);
    return constant_time_equal(digest, g_nativeTextSeal.digest, sizeof(digest));
}

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
    (void) prctl(PR_SET_PTRACER, 0, 0, 0, 0);
#endif
    struct rlimit coreLimit = {0, 0};
    (void) setrlimit(RLIMIT_CORE, &coreLimit);
}

bool hasInjectedExecutableMapping() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return false;
    }

    static const char *suspiciousPaths[] = {
            "/data/local/tmp/",
            "frida",
            "gadget",
            "gum-js",
            "substrate",
            "xposed",
            "magisk"
    };

    char line[1024] = {0};
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        char perms[5] = {0};
        unsigned long long start = 0;
        unsigned long long end = 0;
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3 || perms[2] != 'x') {
            continue;
        }
        (void) start;
        (void) end;
        for (const char *marker : suspiciousPaths) {
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

bool isDexBackedAnonymousName(const char *name) {
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    return strstr(name, "Anonymous-DexFile") != nullptr
           || strstr(name, "InMemoryDexFile") != nullptr;
}

void hardenSensitiveAnonymousMappings() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        return;
    }

    char line[1024] = {0};
    while (fgets(line, sizeof(line), fp) != nullptr) {
        unsigned long long startRaw = 0;
        unsigned long long endRaw = 0;
        char perms[5] = {0};
        char name[512] = {0};

        int fields = sscanf(line,
                            "%llx-%llx %4s %*s %*s %*s %511[^\n]",
                            &startRaw,
                            &endRaw,
                            perms,
                            name);
        if (fields < 3 || endRaw <= startRaw) {
            continue;
        }

        const uintptr_t start = static_cast<uintptr_t>(startRaw);
        const uintptr_t end = static_cast<uintptr_t>(endRaw);
        const uintptr_t length = end - start;
        const bool privateMapping = perms[3] == 'p';
        const bool writable = perms[1] == 'w';
        const bool unnamed = fields < 4 || name[0] == '\0';
        const bool heap = fields >= 4 && strstr(name, "[heap]") != nullptr;
        const bool dex = fields >= 4 && isDexBackedAnonymousName(name);

        if (dex || heap ||
            (unnamed && privateMapping && writable && length >= MIN_ANON_REGION_SIZE)) {
#ifdef MADV_DONTDUMP
            (void) madvise(reinterpret_cast<void *>(start),
                           static_cast<size_t>(length),
                           MADV_DONTDUMP);
#endif
        }

        // A common in-process dumper trick is to fork/clone after the protected DEX has
        // been restored and let the child scrape a stable copy. On kernels that support
        // MADV_WIPEONFORK, make only identified in-memory DEX VMAs become zero-filled in
        // the child. Failure is deliberately ignored for file-backed/unsupported VMAs.
#if defined(MADV_WIPEONFORK)
        if (dex && privateMapping) {
            (void) madvise(reinterpret_cast<void *>(start),
                           static_cast<size_t>(length),
                           MADV_WIPEONFORK);
        }
#endif
    }

    fclose(fp);
}

bool hasSelfMemDescriptor() {
    DIR *dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return false;
    }

    bool found = false;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char linkPath[256] = {0};
        char target[512] = {0};
        int written = snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", entry->d_name);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(linkPath)) {
            continue;
        }

        ssize_t length = readlink(linkPath, target, sizeof(target) - 1);
        if (length <= 0) {
            continue;
        }
        target[length] = '\0';

        // Legitimate Android application code has no reason to hold its own proc-mem
        // device open. This specifically catches injected same-process dump helpers;
        // descriptors belonging to other processes are not visible here.
        if (strcmp(target, "/proc/self/mem") == 0) {
            found = true;
            break;
        }

        char pidMem[64] = {0};
        snprintf(pidMem, sizeof(pidMem), "/proc/%d/mem", getpid());
        if (strcmp(target, pidMem) == 0) {
            found = true;
            break;
        }
    }

    closedir(dir);
    return found;
}

bool processDumpingUnlocked() {
    const int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    return dumpable != 0;
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
        hardenSensitiveAnonymousMappings();

        static unsigned poisonTicks = 0;
        if ((++poisonTicks & 7u) == 0u && !refreshInMemoryDexPoison()) {
            terminateProtectedProcess();
        }

        static unsigned nativeHashTicks = 0;
        if ((++nativeHashTicks & 7u) == 0u && !verifyNativeTextHash()) {
            terminateProtectedProcess();
        }

        if (processDumpingUnlocked()
            || hasTracerPid()
            || hasRuntimeInstrumentationMarker()
            || hasInjectedExecutableMapping()
            || hasSelfMemDescriptor()) {
            terminateProtectedProcess();
        }
        usleep(WATCHDOG_INTERVAL_US);
    }
}

} // namespace

// Apply process-level dump hardening as soon as the shell library is loaded and keep
// reasserting it during the lifetime of the protected process. ART must retain read
// access to InMemoryDexClassLoader buffers, so live DEX pages stay readable inside the
// process while being excluded from normal dump/fork-based extraction paths.
__attribute__((constructor))
static void parallax_harden_process() {
#ifndef DEBUG
    lockProcessDumping();
    hardenSensitiveAnonymousMappings();
    if (!verifyNativeTextHash()) {
        terminateProtectedProcess();
    }

    pthread_t watchdog{};
    if (pthread_create(&watchdog, nullptr, parallaxHardeningWatchdog, nullptr) == 0) {
        (void) pthread_detach(watchdog);
    }
#endif
}
