#include "parallax_vm.h"
#include "parallax.h"

#include <string>

extern ShellConfig g_shell_config;

bool registerHighValueVmMethods(JNIEnv *env) {
    if (env == nullptr || g_shell_config.jni_class_name.empty()) return false;
    std::string className = g_shell_config.jni_class_name;
    const size_t slash = className.find_last_of('/');
    if (slash == std::string::npos) return false;
    className.resize(slash + 1);
    className += "Parallax16";

    jclass bridge = env->FindClass(className.c_str());
    if (bridge == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    static JNINativeMethod methods[] = {
            {const_cast<char *>("hvi0"), const_cast<char *>("(I)I"), (void *) highValueVmI0},
            {const_cast<char *>("hvi1"), const_cast<char *>("(II)I"), (void *) highValueVmI1},
            {const_cast<char *>("hvi2"), const_cast<char *>("(III)I"), (void *) highValueVmI2},
            {const_cast<char *>("hvi3"), const_cast<char *>("(IIII)I"), (void *) highValueVmI3},
            {const_cast<char *>("hvi4"), const_cast<char *>("(IIIII)I"), (void *) highValueVmI4},
            {const_cast<char *>("hvv0"), const_cast<char *>("(I)V"), (void *) highValueVmV0},
            {const_cast<char *>("hvv1"), const_cast<char *>("(II)V"), (void *) highValueVmV1},
            {const_cast<char *>("hvv2"), const_cast<char *>("(III)V"), (void *) highValueVmV2},
            {const_cast<char *>("hvv3"), const_cast<char *>("(IIII)V"), (void *) highValueVmV3},
            {const_cast<char *>("hvv4"), const_cast<char *>("(IIIII)V"), (void *) highValueVmV4},
    };
    return env->RegisterNatives(bridge, methods,
            static_cast<jint>(sizeof(methods) / sizeof(methods[0]))) == JNI_OK;
}
