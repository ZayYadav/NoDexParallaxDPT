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
#include "parallax_crypto.h"

extern ShellConfig g_shell_config;
extern uint8_t PARALLAX_UNKNOWN_DATA[];

namespace {
constexpr jint SECURITY_ROOT = 1;
constexpr jint SECURITY_DEBUGGABLE = 1 << 1;
constexpr jint SECURITY_TRACER = 1 << 2;
constexpr jint SECURITY_HOOK_FRAMEWORK = 1 << 3;
constexpr jint SECURITY_PAYLOAD_TAMPER = 1 << 4;
std::atomic<bool> g_risk_thread_started{false};
std::atomic<jint> g_reported_security_state{0};
}

void reportSecurityRisk(jint riskBits) {
    if (riskBits != 0) {
        g_reported_security_state.fetch_or(riskBits, std::memory_order_relaxed);
    }
}

jint getSecurityRiskState() {
    return g_reported_security_state.load(std::memory_order_relaxed);
}

PARALLAX_ENCRYPT jint runtimeSecurityState(JNIEnv *, jclass) {
    return getSecurityRiskState();
}

PARALLAX_ENCRYPT NO_INLINE void parallax_crash() {
    // Legacy callers used to corrupt LR/return state and deliberately crash the process.
    // That is hostile to runtime compatibility and bypasses the protection warning UX.
    // Latch the finding instead; the Java protection poller will block the session and
    // show the fullscreen warning without killing an otherwise healthy app process.
    DLOGW("legacy fatal protection condition converted to runtime security state");
    reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
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
    if (env->ExceptionCheck() || appInfoClass == nullptr) {
        env->ExceptionClear();
        parallax::jni::DeleteLocalRef(env, appInfo);
        return false;
    }

    jfieldID flagsField = env->GetFieldID(appInfoClass, "flags", "I");
    if (env->ExceptionCheck() || flagsField == nullptr) {
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

static uint32_t readBigEndianU32(const uint8_t *data) {
    return (static_cast<uint32_t>(data[0]) << 24)
           | (static_cast<uint32_t>(data[1]) << 16)
           | (static_cast<uint32_t>(data[2]) << 8)
           | static_cast<uint32_t>(data[3]);
}

static int hexNibble(uint8_t value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static bool decodePayloadTag(const uint8_t *comment, size_t commentLength, uint8_t out[32]) {
    static const char prefix[] = "PXH1:";
    constexpr size_t prefixLength = sizeof(prefix) - 1;
    constexpr size_t expectedLength = prefixLength + 64;
    if (comment == nullptr || commentLength != expectedLength
        || memcmp(comment, prefix, prefixLength) != 0) {
        return false;
    }

    for (size_t i = 0; i < 32; ++i) {
        int hi = hexNibble(comment[prefixLength + i * 2]);
        int lo = hexNibble(comment[prefixLength + i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool findZipEocd(const uint8_t *zipData, size_t zipLength, size_t *eocdOffsetOut) {
    if (zipData == nullptr || eocdOffsetOut == nullptr || zipLength < 22) {
        return false;
    }

    constexpr size_t maxCommentLength = 65535;
    const size_t minimumOffset = zipLength > 22 + maxCommentLength
                                 ? zipLength - (22 + maxCommentLength)
                                 : 0;
    size_t offset = zipLength - 22;
    while (true) {
        if (zipData[offset] == 0x50
            && zipData[offset + 1] == 0x4b
            && zipData[offset + 2] == 0x05
            && zipData[offset + 3] == 0x06) {
            uint16_t commentLength = static_cast<uint16_t>(zipData[offset + 20])
                                     | (static_cast<uint16_t>(zipData[offset + 21]) << 8);
            if (offset + 22 + commentLength == zipLength) {
                *eocdOffsetOut = offset;
                return true;
            }
        }
        if (offset == minimumOffset) {
            break;
        }
        --offset;
    }
    return false;
}

static bool verifyProtectedDexPayload(JNIEnv *env) {
    if (env == nullptr) {
        return false;
    }

    void *packageAddress = nullptr;
    size_t packageSize = 0;
    load_package(env, &packageAddress, &packageSize);
    if (packageAddress == nullptr || packageSize == 0) {
        DLOGW("cannot load package for protected DEX verification");
        return false;
    }

    auto entry = read_zip_file_entry(packageAddress, packageSize,
                                     AY_OBFUSCATE(COMBINE_DEX_FILES_NAME_IN_ZIP));
    unload_package(packageAddress, packageSize);
    if (!entry.has_value()) {
        DLOGW("protected bootstrap DEX entry missing");
        return false;
    }

    auto [entryData, entrySize] = entry.value();
    bool verified = false;
    do {
        if (entrySize < 4) {
            break;
        }

        uint32_t zipLength = readBigEndianU32(entryData + entrySize - 4);
        if (zipLength == 0 || entrySize <= static_cast<size_t>(zipLength) + 4) {
            break;
        }

        const uint8_t *zipData = entryData + (entrySize - zipLength - 4);
        size_t eocdOffset = 0;
        if (!findZipEocd(zipData, zipLength, &eocdOffset)) {
            break;
        }

        uint16_t commentLength = static_cast<uint16_t>(zipData[eocdOffset + 20])
                                 | (static_cast<uint16_t>(zipData[eocdOffset + 21]) << 8);
        const uint8_t *comment = zipData + eocdOffset + 22;
        uint8_t actualTag[32] = {0};
        if (!decodePayloadTag(comment, commentLength, actualTag)) {
            break;
        }

        const char *authLabel = AY_OBFUSCATE("Parallax/dex/authentication/v1");
        auto authenticationKey = hmac_sha256(
                PARALLAX_UNKNOWN_DATA,
                16,
                reinterpret_cast<const uint8_t *>(authLabel),
                strlen(authLabel));
        if (authenticationKey.size() != 32) {
            break;
        }

        // Builder authenticates the ZIP prefix through byte 19 of EOCD. The two-byte
        // comment-length field and comment itself are excluded so the tag can live in the
        // ZIP comment without changing the authenticated prefix.
        auto expectedTag = hmac_sha256(authenticationKey.data(), authenticationKey.size(),
                                       zipData, eocdOffset + 20);
        if (expectedTag.size() != 32) {
            break;
        }

        verified = constant_time_equal(expectedTag.data(), actualTag, 32);
    } while (false);

    delete[] entryData;
    if (!verified) {
        DLOGW("protected DEX payload authentication failed");
    }
    return verified;
}

PARALLAX_ENCRYPT jint securityStatus(JNIEnv *env, jclass, jobject context) {
    jint result = getSecurityRiskState();
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
    if (!verifyProtectedDexPayload(env)) {
        result |= SECURITY_PAYLOAD_TAMPER;
    }
    reportSecurityRisk(result & (SECURITY_TRACER | SECURITY_HOOK_FRAMEWORK | SECURITY_PAYLOAD_TAMPER));
    DLOGI("Parallax Protection policy status: 0x%x", result);
    return result;
}

PARALLAX_ENCRYPT void scheduleExit(JNIEnv *, jclass, jint delayMs) {
    // Kept for JNI ABI compatibility with older bootstrap code. Deliberate SIGKILL is no
    // longer part of the protection policy; latch a blocked state and let the warning UI
    // own the user-visible response.
    DLOGW("scheduleExit(%d) ignored; runtime protection state latched", delayMs);
    reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
}

// Compare in-memory libc .text CRC with on-disk .text CRC; report if mismatched.
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
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
    }
}

PARALLAX_ENCRYPT void detectFrida() {
    const char *pool_frida = AY_OBFUSCATE("pool-frida");
    const char *gmain = AY_OBFUSCATE("gmain");
    const char *gbus = AY_OBFUSCATE("gdbus");
    const char *gum_js_loop = AY_OBFUSCATE("gum-js-loop");

    if (hasHookFrameworkMarker()) {
        DLOGD("found instrumentation/hook framework marker");
        reportSecurityRisk(PARALLAX_SECURITY_HOOK_FRAMEWORK_BIT);
    }

    int frida_thread_count = find_in_threads_list(4,
            pool_frida,
            gmain,
            gbus,
            gum_js_loop);
    if (frida_thread_count >= 2) {
        DLOGD("found instrumentation threads");
        reportSecurityRisk(PARALLAX_SECURITY_HOOK_FRAMEWORK_BIT);
    }
}

PARALLAX_ENCRYPT void detectDebugger() {
    if (hasTracerPid()) {
        DLOGD("found tracer pid");
        reportSecurityRisk(PARALLAX_SECURITY_TRACER_BIT);
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
