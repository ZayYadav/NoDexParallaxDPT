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

void parallax_crash();
void detectFrida();
void detectDebugger();
void detectRisk();
void junkCodeDexProtect(JNIEnv *env);
void verifyAppSignature(JNIEnv *env, jobject context, const char *expectedSha256);
void verifyLibcTextCrc();

// Defensive policy exposed to the single Java bootstrap. These checks intentionally
// cover device/app policy (root and debuggable state), not additional analysis-evasion.
jint securityStatus(JNIEnv *env, jclass, jobject context);
void scheduleExit(JNIEnv *env, jclass, jint delayMs);

#endif //PARALLAX_PARALLAX_RISK_H
