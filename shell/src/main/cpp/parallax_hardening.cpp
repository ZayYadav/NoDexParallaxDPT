#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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
