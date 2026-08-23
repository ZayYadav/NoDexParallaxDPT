//
// Created by parallax
//

#include "java_lang_Class.h"

using namespace parallax::reflect;

jstring java_lang_Class::getName() {
    return static_cast<jstring>(jni::CallObjectMethod(m_env, m_obj, "getName",
                                                      "()Ljava/lang/String;"));
}