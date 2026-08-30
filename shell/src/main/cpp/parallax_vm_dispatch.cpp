#include "parallax_vm.h"

#include <cstdint>

// VM4 method ids use bit 30. Classic VM ids remain in the low positive range.
// The marker is internal to protected APKs and keeps the existing JNI trampoline ABI stable.
namespace {
constexpr uint32_t kVm4MethodBit = 0x40000000u;

inline bool isVm4Method(jint methodId) {
    return (static_cast<uint32_t>(methodId) & kVm4MethodBit) != 0u;
}
}

void loadHighValueVmClassic(JNIEnv *env);
jint highValueVmClassicI0(JNIEnv *env, jclass, jint methodId);
jint highValueVmClassicI1(JNIEnv *env, jclass, jint methodId, jint a0);
jint highValueVmClassicI2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
jint highValueVmClassicI3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
jint highValueVmClassicI4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);
void highValueVmClassicV0(JNIEnv *env, jclass, jint methodId);
void highValueVmClassicV1(JNIEnv *env, jclass, jint methodId, jint a0);
void highValueVmClassicV2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
void highValueVmClassicV3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
void highValueVmClassicV4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);

void loadHighValueVm4(JNIEnv *env);
jint highValueVm4I0(JNIEnv *env, jclass, jint methodId);
jint highValueVm4I1(JNIEnv *env, jclass, jint methodId, jint a0);
jint highValueVm4I2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
jint highValueVm4I3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
jint highValueVm4I4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);
void highValueVm4V0(JNIEnv *env, jclass, jint methodId);
void highValueVm4V1(JNIEnv *env, jclass, jint methodId, jint a0);
void highValueVm4V2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
void highValueVm4V3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
void highValueVm4V4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);

void loadHighValueVm(JNIEnv *env) {
    loadHighValueVmClassic(env);
    loadHighValueVm4(env);
}

jint highValueVmI0(JNIEnv *env, jclass cls, jint id) {
    return isVm4Method(id) ? highValueVm4I0(env, cls, id) : highValueVmClassicI0(env, cls, id);
}

jint highValueVmI1(JNIEnv *env, jclass cls, jint id, jint a0) {
    return isVm4Method(id) ? highValueVm4I1(env, cls, id, a0) : highValueVmClassicI1(env, cls, id, a0);
}

jint highValueVmI2(JNIEnv *env, jclass cls, jint id, jint a0, jint a1) {
    return isVm4Method(id) ? highValueVm4I2(env, cls, id, a0, a1)
                           : highValueVmClassicI2(env, cls, id, a0, a1);
}

jint highValueVmI3(JNIEnv *env, jclass cls, jint id, jint a0, jint a1, jint a2) {
    return isVm4Method(id) ? highValueVm4I3(env, cls, id, a0, a1, a2)
                           : highValueVmClassicI3(env, cls, id, a0, a1, a2);
}

jint highValueVmI4(JNIEnv *env, jclass cls, jint id, jint a0, jint a1, jint a2, jint a3) {
    return isVm4Method(id) ? highValueVm4I4(env, cls, id, a0, a1, a2, a3)
                           : highValueVmClassicI4(env, cls, id, a0, a1, a2, a3);
}

void highValueVmV0(JNIEnv *env, jclass cls, jint id) {
    if (isVm4Method(id)) highValueVm4V0(env, cls, id);
    else highValueVmClassicV0(env, cls, id);
}

void highValueVmV1(JNIEnv *env, jclass cls, jint id, jint a0) {
    if (isVm4Method(id)) highValueVm4V1(env, cls, id, a0);
    else highValueVmClassicV1(env, cls, id, a0);
}

void highValueVmV2(JNIEnv *env, jclass cls, jint id, jint a0, jint a1) {
    if (isVm4Method(id)) highValueVm4V2(env, cls, id, a0, a1);
    else highValueVmClassicV2(env, cls, id, a0, a1);
}

void highValueVmV3(JNIEnv *env, jclass cls, jint id, jint a0, jint a1, jint a2) {
    if (isVm4Method(id)) highValueVm4V3(env, cls, id, a0, a1, a2);
    else highValueVmClassicV3(env, cls, id, a0, a1, a2);
}

void highValueVmV4(JNIEnv *env, jclass cls, jint id, jint a0, jint a1, jint a2, jint a3) {
    if (isVm4Method(id)) highValueVm4V4(env, cls, id, a0, a1, a2, a3);
    else highValueVmClassicV4(env, cls, id, a0, a1, a2, a3);
}
