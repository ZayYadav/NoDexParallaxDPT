#ifndef PARALLAX_HIGH_VALUE_VM_H
#define PARALLAX_HIGH_VALUE_VM_H

#include <jni.h>

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

jlong highValueVmJ0(JNIEnv *env, jclass, jint methodId);
jlong highValueVmJ1(JNIEnv *env, jclass, jint methodId, jlong a0);
jlong highValueVmJ2(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1);
jlong highValueVmJ3(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1, jlong a2);
jlong highValueVmJ4(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1, jlong a2, jlong a3);

void highValueVmVJ0(JNIEnv *env, jclass, jint methodId);
void highValueVmVJ1(JNIEnv *env, jclass, jint methodId, jlong a0);
void highValueVmVJ2(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1);
void highValueVmVJ3(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1, jlong a2);
void highValueVmVJ4(JNIEnv *env, jclass, jint methodId, jlong a0, jlong a1, jlong a2, jlong a3);

jfloat highValueVmF0(JNIEnv *env, jclass, jint methodId);
jfloat highValueVmF1(JNIEnv *env, jclass, jint methodId, jfloat a0);
jfloat highValueVmF2(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1);
jfloat highValueVmF3(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1, jfloat a2);
jfloat highValueVmF4(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1, jfloat a2, jfloat a3);

void highValueVmVF0(JNIEnv *env, jclass, jint methodId);
void highValueVmVF1(JNIEnv *env, jclass, jint methodId, jfloat a0);
void highValueVmVF2(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1);
void highValueVmVF3(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1, jfloat a2);
void highValueVmVF4(JNIEnv *env, jclass, jint methodId, jfloat a0, jfloat a1, jfloat a2, jfloat a3);

jdouble highValueVmD0(JNIEnv *env, jclass, jint methodId);
jdouble highValueVmD1(JNIEnv *env, jclass, jint methodId, jdouble a0);
jdouble highValueVmD2(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1);
jdouble highValueVmD3(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1, jdouble a2);
jdouble highValueVmD4(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1, jdouble a2, jdouble a3);

void highValueVmVd0(JNIEnv *env, jclass, jint methodId);
void highValueVmVd1(JNIEnv *env, jclass, jint methodId, jdouble a0);
void highValueVmVd2(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1);
void highValueVmVd3(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1, jdouble a2);
void highValueVmVd4(JNIEnv *env, jclass, jint methodId, jdouble a0, jdouble a1, jdouble a2, jdouble a3);

#endif // PARALLAX_HIGH_VALUE_VM_H
