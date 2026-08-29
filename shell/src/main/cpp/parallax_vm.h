#ifndef PARALLAX_HIGH_VALUE_VM_H
#define PARALLAX_HIGH_VALUE_VM_H

#include <jni.h>

// Registers the tiny Parallax16 JNI trampoline class after the encrypted shell config has
// resolved the runtime shell package name.
bool registerHighValueVmMethods(JNIEnv *env);

// Loads the optional AES-GCM sealed assets/Parallax.vm payload. Missing payload is valid
// when the high-value VM tier was not requested. Authentication/format failures are not.
void loadHighValueVm(JNIEnv *env);

jint highValueVmI0(JNIEnv *env, jclass, jint methodId);
jint highValueVmI1(JNIEnv *env, jclass, jint methodId, jint a0);
jint highValueVmI2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
jint highValueVmI3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
jint highValueVmI4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);

void highValueVmV0(JNIEnv *env, jclass, jint methodId);
void highValueVmV1(JNIEnv *env, jclass, jint methodId, jint a0);
void highValueVmV2(JNIEnv *env, jclass, jint methodId, jint a0, jint a1);
void highValueVmV3(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2);
void highValueVmV4(JNIEnv *env, jclass, jint methodId, jint a0, jint a1, jint a2, jint a3);

#endif // PARALLAX_HIGH_VALUE_VM_H
