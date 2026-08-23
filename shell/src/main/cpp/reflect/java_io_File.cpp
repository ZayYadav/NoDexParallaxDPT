//
// Created by parallax
//

#include "java_io_File.h"

using namespace parallax::reflect;

jstring java_io_File::getName() {
    return static_cast<jstring>(jni::CallObjectMethod(m_env, m_obj, "getName",
                                                      "()Ljava/lang/String;"));
}
