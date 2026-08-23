#include <jni.h>
#include <cstdio>
#include <cstring>
#include <sys/system_properties.h>

#include "common/obfuscate.h"

namespace {

constexpr jint NATIVE_TRACER = 1;
constexpr jint NATIVE_VIRTUAL = 2;
constexpr jint NATIVE_HOOK_FRAMEWORK = 4;

bool hasTracer() {
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
            if (sscanf(line + strlen(key), "%d", &pid) == 1 && pid != 0) {
                traced = true;
            }
            break;
        }
    }
    fclose(fp);
    return traced;
}

bool hasHookFrameworkMarker() {
    FILE *fp = fopen(AY_OBFUSCATE("/proc/self/maps"), "r");
    if (fp == nullptr) {
        return false;
    }

    const char *frida_agent = AY_OBFUSCATE("frida-agent");
    const char *frida_gadget = AY_OBFUSCATE("libfrida-gadget");
    const char *xposed = AY_OBFUSCATE("xposed");
    const char *lsposed = AY_OBFUSCATE("lsposed");
    const char *edxp = AY_OBFUSCATE("edxp");
    const char *lsplant = AY_OBFUSCATE("lsplant");
    const char *sandhook = AY_OBFUSCATE("sandhook");
    const char *yahfa = AY_OBFUSCATE("yahfa");

    char line[1024] = {0};
    bool detected = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, frida_agent) != nullptr
            || strstr(line, frida_gadget) != nullptr
            || strstr(line, xposed) != nullptr
            || strstr(line, lsposed) != nullptr
            || strstr(line, edxp) != nullptr
            || strstr(line, lsplant) != nullptr
            || strstr(line, sandhook) != nullptr
            || strstr(line, yahfa) != nullptr) {
            detected = true;
            break;
        }
    }
    fclose(fp);
    return detected;
}

bool propertyContains(const char *key, const char *needle) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, value) <= 0) {
        return false;
    }
    return strstr(value, needle) != nullptr;
}

bool isVirtualEnvironment() {
    char qemu[PROP_VALUE_MAX] = {0};
    if (__system_property_get(AY_OBFUSCATE("ro.kernel.qemu"), qemu) > 0
        && strcmp(qemu, AY_OBFUSCATE("1")) == 0) {
        return true;
    }

    if (propertyContains(AY_OBFUSCATE("ro.hardware"), AY_OBFUSCATE("goldfish"))
        || propertyContains(AY_OBFUSCATE("ro.hardware"), AY_OBFUSCATE("ranchu"))) {
        return true;
    }

    int hints = 0;
    if (propertyContains(AY_OBFUSCATE("ro.product.model"), AY_OBFUSCATE("sdk_gphone"))
        || propertyContains(AY_OBFUSCATE("ro.product.model"), AY_OBFUSCATE("Emulator"))) {
        hints++;
    }
    if (propertyContains(AY_OBFUSCATE("ro.product.name"), AY_OBFUSCATE("sdk_gphone"))
        || propertyContains(AY_OBFUSCATE("ro.product.name"), AY_OBFUSCATE("emulator"))) {
        hints++;
    }
    if (propertyContains(AY_OBFUSCATE("ro.build.fingerprint"), AY_OBFUSCATE("generic"))
        || propertyContains(AY_OBFUSCATE("ro.build.fingerprint"), AY_OBFUSCATE("emulator"))) {
        hints++;
    }
    return hints >= 2;
}

} // namespace

extern "C"
JNIEXPORT jint JNICALL
Java_com_parallax_shell_ParallaxBhaiya_nativeEnvironmentState(JNIEnv *, jclass) {
    jint result = 0;
    if (hasTracer()) {
        result |= NATIVE_TRACER;
    }
    if (isVirtualEnvironment()) {
        result |= NATIVE_VIRTUAL;
    }
    if (hasHookFrameworkMarker()) {
        result |= NATIVE_HOOK_FRAMEWORK;
    }
    return result;
}
