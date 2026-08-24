//
// Created by parallax
//

#ifndef PARALLAX_PARALLAX_RISK_H
#define PARALLAX_PARALLAX_RISK_H

#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <jni.h>

#include "parallax_util.h"
#include "parallax_log.h"
#include "parallax_jni.h"
#include "linux_syscall_support.h"
#include "common/obfuscate.h"

constexpr jint PARALLAX_SECURITY_TRACER_BIT = 1 << 2;
constexpr jint PARALLAX_SECURITY_HOOK_FRAMEWORK_BIT = 1 << 3;
constexpr jint PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT = 1 << 4;
constexpr jint PARALLAX_SECURITY_RUNTIME_TAMPER_BIT = 1 << 5;

void parallax_crash();
void detectFrida();
void detectDebugger();
void detectRisk();
void junkCodeDexProtect(JNIEnv *env);
void verifyAppSignature(JNIEnv *env, jobject context, const char *expectedSha256);
void verifyLibcTextCrc();

// Runtime detectors report into this shared state instead of terminating the process.
// The Java bootstrap polls it and presents the non-cancelable protection UI.
void reportSecurityRisk(jint riskBits);
jint getSecurityRiskState();
jint runtimeSecurityState(JNIEnv *env, jclass);

// Defensive policy exposed to the Java bootstrap.
jint securityStatus(JNIEnv *env, jclass, jobject context);
void scheduleExit(JNIEnv *env, jclass, jint delayMs);

#endif //PARALLAX_PARALLAX_RISK_H
