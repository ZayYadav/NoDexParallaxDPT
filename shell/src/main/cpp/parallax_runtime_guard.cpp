#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "common/obfuscate.h"

namespace {

std::atomic<bool> g_guard_started{false};
std::atomic<uint64_t> g_code_hash{0};
std::atomic<uint64_t> g_code_hash_guard{0};

static char asciiLower(char value) {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

static bool containsInsensitive(const char *text, const char *needle) {
    if (text == nullptr || needle == nullptr || needle[0] == '\0') {
        return false;
    }
    const size_t textLen = strlen(text);
    const size_t needleLen = strlen(needle);
    if (needleLen > textLen) {
        return false;
    }
    for (size_t i = 0; i + needleLen <= textLen; ++i) {
        size_t j = 0;
        for (; j < needleLen; ++j) {
            if (asciiLower(text[i + j]) != asciiLower(needle[j])) {
                break;
            }
        }
        if (j == needleLen) {
            return true;
        }
    }
    return false;
}

static bool hasStrongMarker(const char *text) {
    static const char *markers[] = {
            AY_OBFUSCATE("frida"),
            AY_OBFUSCATE("gum-js"),
            AY_OBFUSCATE("linjector"),
            AY_OBFUSCATE("xposed"),
            AY_OBFUSCATE("lsposed"),
            AY_OBFUSCATE("edxp"),
            AY_OBFUSCATE("lsplant"),
            AY_OBFUSCATE("sandhook"),
            AY_OBFUSCATE("yahfa"),
            AY_OBFUSCATE("zygisk"),
            AY_OBFUSCATE("riru")
    };
    for (const char *marker : markers) {
        if (containsInsensitive(text, marker)) {
            return true;
        }
    }
    return false;
}

static bool tracerPresent() {
    FILE *fp = fopen(AY_OBFUSCATE("/proc/self/status"), "r");
    if (fp == nullptr) {
        return false;
    }
    const char *key = AY_OBFUSCATE("TracerPid:");
    char line[256] = {0};
    bool traced = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strncmp(line, key, strlen(key)) == 0) {
            int pid = 0;
            traced = sscanf(line + strlen(key), "%d", &pid) == 1 && pid != 0;
            break;
        }
    }
    fclose(fp);
    return traced;
}

static bool suspiciousMaps() {
    FILE *fp = fopen(AY_OBFUSCATE("/proc/self/maps"), "r");
    if (fp == nullptr) {
        return false;
    }
    char line[1024] = {0};
    bool suspicious = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (hasStrongMarker(line)) {
            suspicious = true;
            break;
        }
    }
    fclose(fp);
    return suspicious;
}

static int moduleCallback(struct dl_phdr_info *info, size_t, void *data) {
    if (info == nullptr || data == nullptr || info->dlpi_name == nullptr) {
        return 0;
    }
    auto *found = static_cast<bool *>(data);
    if (info->dlpi_name[0] != '\0' && hasStrongMarker(info->dlpi_name)) {
        *found = true;
        return 1;
    }
    return 0;
}

static bool suspiciousLoadedModules() {
    bool found = false;
    dl_iterate_phdr(moduleCallback, &found);
    return found;
}

static bool suspiciousThreadNames() {
    DIR *dir = opendir(AY_OBFUSCATE("/proc/self/task"));
    if (dir == nullptr) {
        return false;
    }

    int weakMarkers = 0;
    bool strong = false;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[256] = {0};
        int written = snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(path)) {
            continue;
        }
        FILE *fp = fopen(path, "r");
        if (fp == nullptr) {
            continue;
        }
        char name[128] = {0};
        if (fgets(name, sizeof(name), fp) != nullptr) {
            if (containsInsensitive(name, AY_OBFUSCATE("gum-js-loop"))
                || containsInsensitive(name, AY_OBFUSCATE("pool-frida"))
                || containsInsensitive(name, AY_OBFUSCATE("frida"))) {
                strong = true;
            }
            if (containsInsensitive(name, AY_OBFUSCATE("gmain"))
                || containsInsensitive(name, AY_OBFUSCATE("gdbus"))) {
                ++weakMarkers;
            }
        }
        fclose(fp);
        if (strong || weakMarkers >= 2) {
            break;
        }
    }
    closedir(dir);
    return strong || weakMarkers >= 2;
}

static bool suspiciousFileDescriptors() {
    DIR *dir = opendir(AY_OBFUSCATE("/proc/self/fd"));
    if (dir == nullptr) {
        return false;
    }
    bool suspicious = false;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[256] = {0};
        int written = snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(path)) {
            continue;
        }
        char target[512] = {0};
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length <= 0) {
            continue;
        }
        target[length] = '\0';
        if (hasStrongMarker(target)) {
            suspicious = true;
            break;
        }
    }
    closedir(dir);
    return suspicious;
}

static bool suspiciousLoaderEnvironment() {
    const char *preload = getenv(AY_OBFUSCATE("LD_PRELOAD"));
    const char *audit = getenv(AY_OBFUSCATE("LD_AUDIT"));
    return (preload != nullptr && preload[0] != '\0')
           || (audit != nullptr && audit[0] != '\0');
}

__attribute__((noinline, used))
static uint32_t codeSentinel(uint32_t value) {
    value ^= 0xA5C31F27u;
    value = (value << 7u) | (value >> 25u);
    value *= 0x9E3779B1u;
    value ^= value >> 13u;
    value += 0x6D2B79F5u;
    return value ^ (value << 11u);
}

static uint64_t sentinelHash() {
    const uintptr_t address = reinterpret_cast<uintptr_t>(&codeSentinel);
    const auto *bytes = reinterpret_cast<const uint8_t *>(address);
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < 64; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool codeSentinelIntact() {
    const uint64_t expected = g_code_hash.load(std::memory_order_relaxed);
    const uint64_t guard = g_code_hash_guard.load(std::memory_order_relaxed);
    if (expected == 0 || guard != (~expected ^ 0xD6E8FEB86659FD93ULL)) {
        return false;
    }
    return sentinelHash() == expected;
}

[[noreturn]] static void failClosed() {
    kill(getpid(), SIGKILL);
    _exit(173);
}

static bool runtimeStateSuspicious() {
    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return true;
    }
    return tracerPresent()
           || suspiciousMaps()
           || suspiciousLoadedModules()
           || suspiciousThreadNames()
           || suspiciousFileDescriptors()
           || suspiciousLoaderEnvironment()
           || !codeSentinelIntact();
}

static void *runtimeGuardThread(void *) {
    for (;;) {
        if (runtimeStateSuspicious()) {
            failClosed();
        }
        struct timespec ts = {};
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            ts.tv_nsec = 0;
        }
        const long jitterMs = 1100L + static_cast<long>((ts.tv_nsec ^ getpid()) % 1200L);
        struct timespec delay = {jitterMs / 1000L, (jitterMs % 1000L) * 1000000L};
        nanosleep(&delay, nullptr);
    }
    return nullptr;
}

__attribute__((constructor))
static void startRuntimeGuard() {
#ifndef DEBUG
    (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit coreLimit = {0, 0};
    (void) setrlimit(RLIMIT_CORE, &coreLimit);

    const uint64_t hash = sentinelHash();
    g_code_hash.store(hash, std::memory_order_relaxed);
    g_code_hash_guard.store(~hash ^ 0xD6E8FEB86659FD93ULL, std::memory_order_relaxed);

    if (runtimeStateSuspicious()) {
        failClosed();
    }

    bool expected = false;
    if (!g_guard_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    pthread_t thread;
    if (pthread_create(&thread, nullptr, runtimeGuardThread, nullptr) != 0) {
        failClosed();
    }
    pthread_detach(thread);
#endif
}

} // namespace
