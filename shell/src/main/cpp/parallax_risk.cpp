//
// Created by parallax
//

#include "parallax_risk.h"
#include <android/api-level.h>
#include <atomic>
#include <climits>
#include <signal.h>
#include <stdint.h>
#include <string>
#include <sys/system_properties.h>
#include "mbedtls/sha256.h"
#include "mz_crypt.h"
#include "parallax.h"

extern ShellConfig g_shell_config;

namespace {
constexpr jint SECURITY_ROOT = 1;
constexpr jint SECURITY_DEBUGGABLE = 1 << 1;
constexpr jint SECURITY_TRACER = 1 << 2;
constexpr jint SECURITY_HOOK_FRAMEWORK = 1 << 3;
std::atomic<bool> g_risk_thread_started{false};
}

PARALLAX_ENCRYPT NO_INLINE void parallax_crash() {
#ifdef DEBUG
    abort();
#else
    asm volatile(
#ifdef __aarch64__
    "mov x30,#0\t\n"
#elif __arm__
    "mov lr,#0\t\n"
#elif __i386__
    "ret\t\n"
#elif __x86_64__
    "pop %rbp\t\n"
#endif
);
#endif
}

PARALLAX_ENCRYPT void junkCodeDexProtect(JNIEnv *env) {
    const char *className = AY_OBFUSCATE(JUNK_CLASS_FULL_NAME);
    jclass klass = parallax::jni::FindClass(env, className);
    if(klass == nullptr) {
        parallax_crash();
    }
}

static bool propertyEquals(const char *name, const char *expected) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name, value);
    return len > 0 && strcmp(value, expected) == 0;
}

static bool propertyContains(const char *name, const char *needle) {
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name, value);
    return len > 0 && strstr(value, needle) != nullptr;
}

static bool pathContainsExecutableSu() {
    const char *pathEnv = getenv("PATH");
    if (pathEnv == nullptr || pathEnv[0] == '\0') {
        return false;
    }

    std::string path(pathEnv);
    size_t start = 0;
    while (start <= path.size()) {
        size_t end = path.find(':', start);
        std::string dir = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!dir.empty()) {
            std::string candidate = dir + "/su";
            if (access(candidate.c_str(), X_OK) == 0) {
                return true;
            }
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return false;
}

static bool detectRootEnvironment() {
    if (getuid() == 0 || geteuid() == 0) {
        return true;
    }

    static const char *rootPaths[] = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/debug_ramdisk/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/data/adb/magisk",
            "/data/adb/ksu",
            "/data/adb/ap"
    };

    for (const char *path : rootPaths) {
        if (access(path, F_OK) == 0) {
            return true;
        }
    }

    if (pathContainsExecutableSu()) {
        return true;
    }

    // Strict policy by design: engineering/test builds are unsupported for protected apps.
    if (propertyContains("ro.build.tags", "test-keys")
        || propertyEquals("ro.debuggable", "1")
        || propertyEquals("ro.secure", "0")) {
        return true;
    }

    return false;
}

static bool isApplicationDebuggable(JNIEnv *env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return false;
    }

    jobject appInfo = parallax::jni::CallObjectMethod(env, context,
            "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (appInfo == nullptr) {
        return false;
    }

    jclass appInfoClass = env->GetObjectClass(appInfo);
    if (appInfoClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        parallax::jni::DeleteLocalRef(env, appInfo);
        return false;
    }

    jfieldID flagsField = env->GetFieldID(appInfoClass, "flags", "I");
    if (flagsField == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        parallax::jni::DeleteLocalRef(env, appInfoClass);
        parallax::jni::DeleteLocalRef(env, appInfo);
        return false;
    }

    jint flags = env->GetIntField(appInfo, flagsField);
    parallax::jni::DeleteLocalRef(env, appInfoClass);
    parallax::jni::DeleteLocalRef(env, appInfo);
    return (flags & 0x2) != 0;
}

static bool hasTracerPid() {
    FILE *fp = fopen(AY_OBFUSCATE("/proc/self/status"), "r");
    if (fp == nullptr) {
        return false;
    }

    const char *tracerKey = AY_OBFUSCATE("TracerPid:");
    char line[256] = {0};
    bool traced = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strncmp(line, tracerKey, strlen(tracerKey)) == 0) {
            int pid = 0;
            if (sscanf(line + strlen(tracerKey), "%d", &pid) == 1 && pid != 0) {
                traced = true;
            }
            break;
        }
    }
    fclose(fp);
    return traced;
}

static bool hasHookFrameworkMarker() {
    FILE *fp = fopen(AY_OBFUSCATE("/proc/self/maps"), "r");
    if (fp == nullptr) {
        return false;
    }

    const char *markers[] = {
            AY_OBFUSCATE("frida-agent"),
            AY_OBFUSCATE("libfrida-gadget"),
            AY_OBFUSCATE("frida-gadget"),
            AY_OBFUSCATE("xposed"),
            AY_OBFUSCATE("lsposed"),
            AY_OBFUSCATE("edxp"),
            AY_OBFUSCATE("lsplant"),
            AY_OBFUSCATE("sandhook"),
            AY_OBFUSCATE("yahfa")
    };

    char line[1024] = {0};
    bool detected = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        for (const char *marker : markers) {
            if (strstr(line, marker) != nullptr) {
                detected = true;
                break;
            }
        }
        if (detected) {
            break;
        }
    }
    fclose(fp);
    return detected;
}

static bool classExists(JNIEnv *env, const char *name) {
    if (env == nullptr) {
        return false;
    }
    jclass klass = env->FindClass(name);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    if (klass == nullptr) {
        return false;
    }
    env->DeleteLocalRef(klass);
    return true;
}

static bool hasHookFrameworkClass(JNIEnv *env) {
    return classExists(env, AY_OBFUSCATE("de/robv/android/xposed/XposedBridge"))
           || classExists(env, AY_OBFUSCATE("de/robv/android/xposed/XC_MethodHook"));
}

PARALLAX_ENCRYPT jint securityStatus(JNIEnv *env, jclass, jobject context) {
    jint result = 0;
    if (detectRootEnvironment()) {
        result |= SECURITY_ROOT;
    }
    if (isApplicationDebuggable(env, context)) {
        result |= SECURITY_DEBUGGABLE;
    }
    if (hasTracerPid()) {
        result |= SECURITY_TRACER;
    }
    if (hasHookFrameworkMarker() || hasHookFrameworkClass(env)) {
        result |= SECURITY_HOOK_FRAMEWORK;
    }
    DLOGI("Parallax Protection policy status: 0x%x", result);
    return result;
}

static void *delayedExitThread(void *arg) {
    intptr_t raw = reinterpret_cast<intptr_t>(arg);
    int delayMs = static_cast<int>(raw);
    if (delayMs > 0) {
        usleep(static_cast<useconds_t>(delayMs) * 1000U);
    }
    kill(getpid(), SIGKILL);
    _exit(0);
    return nullptr;
}

PARALLAX_ENCRYPT void scheduleExit(JNIEnv *, jclass, jint delayMs) {
    if (delayMs < 0) {
        delayMs = 0;
    } else if (delayMs > 10000) {
        delayMs = 10000;
    }

    pthread_t thread;
    void *arg = reinterpret_cast<void *>(static_cast<intptr_t>(delayMs));
    if (pthread_create(&thread, nullptr, delayedExitThread, arg) == 0) {
        pthread_detach(thread);
        return;
    }

    kill(getpid(), SIGKILL);
    _exit(0);
}

// Compare in-memory libc .text CRC with on-disk .text CRC; crash if mismatched.
PARALLAX_ENCRYPT NO_INLINE void verifyLibcTextCrc() {
    Dl_info info = {};
    if (dladdr(reinterpret_cast<const void *>(&fopen), &info) == 0
        || info.dli_fbase == nullptr) {
        DLOGW("dladdr libc failed, skip text crc");
        return;
    }

    std::string libc_path;
    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            libc_path.assign(info.dli_fname);
        } else {
            libc_path = find_so_path(info.dli_fname);
        }
    }
    if (libc_path.empty()) {
        libc_path = find_so_path(AY_OBFUSCATE("libc.so"));
    }
    if (libc_path.empty()) {
        DLOGW("cannot resolve libc path, skip text crc");
        return;
    }

    Elf_Shdr shdr = {};
    get_elf_section(&shdr, libc_path.c_str(), AY_OBFUSCATE(".text"));
    if (shdr.sh_size == 0) {
        DLOGW("libc .text section missing or empty, skip text crc");
        return;
    }

    FILE *fp = fopen(libc_path.c_str(), "r");
    if (fp == nullptr) {
        DLOGW("cannot open libc file: %s, skip text crc", libc_path.c_str());
        return;
    }

    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0) {
        DLOGW("fseek libc .text failed, skip text crc");
        fclose(fp);
        return;
    }

    auto *file_buf = static_cast<uint8_t *>(malloc(shdr.sh_size));
    if (file_buf == nullptr) {
        DLOGW("malloc for libc .text failed, skip text crc");
        fclose(fp);
        return;
    }

    size_t nread = fread(file_buf, 1, shdr.sh_size, fp);
    fclose(fp);
    if (nread != shdr.sh_size) {
        DLOGW("fread libc .text incomplete, skip text crc");
        PARALLAX_FREE(file_buf);
        return;
    }

    const auto *mem_base = reinterpret_cast<const uint8_t *>(info.dli_fbase) + shdr.sh_addr;
    if (!isMemReadable(mem_base, shdr.sh_size)) {
        DLOGW("libc .text memory not readable, skip text crc");
        PARALLAX_FREE(file_buf);
        return;
    }

    uint32_t crc_file = 0;
    uint32_t crc_mem = 0;
    size_t remaining = shdr.sh_size;
    size_t offset = 0;
    while (remaining > 0) {
        int32_t chunk = remaining > static_cast<size_t>(INT32_MAX)
                        ? INT32_MAX
                        : static_cast<int32_t>(remaining);
        crc_file = mz_crypt_crc32_update(crc_file, file_buf + offset, chunk);
        crc_mem = mz_crypt_crc32_update(crc_mem, mem_base + offset, chunk);
        offset += static_cast<size_t>(chunk);
        remaining -= static_cast<size_t>(chunk);
    }
    PARALLAX_FREE(file_buf);

    DLOGD("libc .text crc file=%08x mem=%08x size=%u", crc_file, crc_mem,
          static_cast<unsigned>(shdr.sh_size));
    if (crc_file != crc_mem) {
        DLOGW("libc .text crc mismatch, file=%08x mem=%08x", crc_file, crc_mem);
        parallax_crash();
    }
}

PARALLAX_ENCRYPT void detectFrida() {
    const char *pool_frida = AY_OBFUSCATE("pool-frida");
    const char *gmain = AY_OBFUSCATE("gmain");
    const char *gbus = AY_OBFUSCATE("gdbus");
    const char *gum_js_loop = AY_OBFUSCATE("gum-js-loop");

    if (hasHookFrameworkMarker()) {
        DLOGD("found instrumentation/hook framework marker");
        parallax_crash();
    }

    int frida_thread_count = find_in_threads_list(4,
            pool_frida,
            gmain,
            gbus,
            gum_js_loop);
    if (frida_thread_count >= 2) {
        DLOGD("found instrumentation threads");
        parallax_crash();
    }
}

PARALLAX_ENCRYPT void detectDebugger() {
    if (hasTracerPid()) {
        DLOGD("found tracer pid");
        parallax_crash();
    }
}

[[noreturn]] PARALLAX_ENCRYPT void *detectRiskOnThread(__unused void *args) {
    while (true) {
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_FRIDA_DETECT) == 0) {
            detectFrida();
        }
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_CRC_DETECT) == 0) {
            verifyLibcTextCrc();
        }
        if ((g_shell_config.risk_check_flags & FLAG_DISABLE_ANTI_DEBUG) == 0) {
            detectDebugger();
        }
        sleep(5);
    }
}

PARALLAX_ENCRYPT void detectRisk() {
    bool expected = false;
    if (!g_risk_thread_started.compare_exchange_strong(expected, true)) {
        return;
    }

    pthread_t t;
    if (pthread_create(&t, nullptr, detectRiskOnThread, nullptr) == 0) {
        pthread_detach(t);
    } else {
        g_risk_thread_started.store(false);
    }
}

PARALLAX_ENCRYPT void verifyAppSignature(JNIEnv *env, jobject context, const char *expectedSha256) {
    static std::string actual = {};
    if (context == nullptr || expectedSha256 == nullptr || strlen(expectedSha256) == 0) {
        DLOGW("signature check not configured, skip");
        return;
    }

    if(!actual.empty()) {
        if (parallax_strncasecmp(actual.c_str(), expectedSha256, 64) != 0) {
            DLOGW("signature cache verification failed, expected: %s actual: %s", expectedSha256, actual.c_str());
            parallax_crash();
        }
        return;
    }

    jobject pm = parallax::jni::CallObjectMethod(env, context,
            AY_OBFUSCATE("getPackageManager"),
            AY_OBFUSCATE("()Landroid/content/pm/PackageManager;"));
    if (pm == nullptr) {
        DLOGW("getPackageManager failed");
        parallax_crash();
        return;
    }

    jstring packageName = (jstring) parallax::jni::CallObjectMethod(env, context,
            AY_OBFUSCATE("getPackageName"),
            AY_OBFUSCATE("()Ljava/lang/String;"));
    if (packageName == nullptr) {
        DLOGW("getPackageName failed");
        parallax_crash();
        return;
    }

    int api = android_get_device_api_level();
    jint flags = (api >= 28) ? (jint)0x08000000 : (jint)0x40;

    jobject packageInfo = parallax::jni::CallObjectMethod(env, pm,
            AY_OBFUSCATE("getPackageInfo"),
            AY_OBFUSCATE("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"),
            packageName, flags);
    if (packageInfo == nullptr) {
        DLOGW("getPackageInfo failed");
        parallax_crash();
        return;
    }

    jbyteArray certBytes = nullptr;
    if (api >= 28) {
        jobject signingInfo = parallax::jni::GetObjectField(env, packageInfo,
                AY_OBFUSCATE("signingInfo"),
                AY_OBFUSCATE("Landroid/content/pm/SigningInfo;"));
        if (signingInfo == nullptr) {
            DLOGW("signingInfo is null");
            parallax_crash();
            return;
        }
        jobjectArray signaturesArr = (jobjectArray) parallax::jni::CallObjectMethod(env, signingInfo,
                AY_OBFUSCATE("getApkContentsSigners"),
                AY_OBFUSCATE("()[Landroid/content/pm/Signature;"));
        if (signaturesArr == nullptr || env->GetArrayLength(signaturesArr) == 0) {
            DLOGW("getApkContentsSigners returned empty");
            parallax_crash();
            return;
        }
        jobject signature = env->GetObjectArrayElement(signaturesArr, 0);
        certBytes = (jbyteArray) parallax::jni::CallObjectMethod(env, signature,
                AY_OBFUSCATE("toByteArray"), AY_OBFUSCATE("()[B"));
    } else {
        jobjectArray signaturesArr = (jobjectArray) parallax::jni::GetObjectField(env, packageInfo,
                AY_OBFUSCATE("signatures"),
                AY_OBFUSCATE("[Landroid/content/pm/Signature;"));
        if (signaturesArr == nullptr || env->GetArrayLength(signaturesArr) == 0) {
            DLOGW("signatures field is empty");
            parallax_crash();
            return;
        }
        jobject signature = env->GetObjectArrayElement(signaturesArr, 0);
        certBytes = (jbyteArray) parallax::jni::CallObjectMethod(env, signature,
                AY_OBFUSCATE("toByteArray"), AY_OBFUSCATE("()[B"));
    }

    if (certBytes == nullptr) {
        DLOGW("certBytes is null");
        parallax_crash();
        return;
    }

    jsize certLen = env->GetArrayLength(certBytes);
    jbyte *certData = env->GetByteArrayElements(certBytes, nullptr);

    uint8_t sha256Output[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char *>(certData),
                   static_cast<size_t>(certLen), sha256Output, 0);

    env->ReleaseByteArrayElements(certBytes, certData, JNI_ABORT);

    char sha256Hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        snprintf(sha256Hex + i * 2, 3, "%02x", sha256Output[i]);
    }

    actual.assign(sha256Hex);

    if (parallax_strncasecmp(sha256Hex, expectedSha256, 64) != 0) {
        DLOGW("signature verification failed, expected: %s actual: %s", expectedSha256, sha256Hex);
        parallax_crash();
    }
}
