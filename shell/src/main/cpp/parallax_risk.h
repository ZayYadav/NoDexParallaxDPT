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

#endif //PARALLAX_PARALLAX_RISK_H
