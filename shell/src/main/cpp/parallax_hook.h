//
// Created by parallax
//

#ifndef PARALLAX_PARALLAX_HOOK_H
#define PARALLAX_PARALLAX_HOOK_H
#include <iostream>
#include <cstdint>
#include <sys/mman.h>
#include <android/api-level.h>
#include <cstdint>
#include "parallax_util.h"
#include "parallax.h"
#include "dex/dex_file.h"
#include "common/parallax_log.h"
#include "common/parallax_macro.h"
#include "common/obfuscate.h"
#include "dobby.h"


void parallax_hook();

static void* (*g_originDefineClassV22)(void* thiz,
        void* self,
        const char* descriptor,
        size_t hash,
        void* class_loader,
        const void* dex_file,
        const void* dex_class_def);

static void* (*g_originDefineClassV21)(void* thiz,
                                    const char* descriptor,
                                    void* class_loader,
                                    const void* dex_file,
                                    const void* dex_class_def);


static void (*g_originLoadClassV23)(void* thiz,
                                       const void* self,
                                       const void* dex_file,
                                       const void* dex_class_def,
                                       const char* klass);
bool hook_LoadClass();
bool hook_DefineClass();
void hook_mmap();
void hook_execve();
void hook_write();
#endif //PARALLAX_PARALLAX_HOOK_H
