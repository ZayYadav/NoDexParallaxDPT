//
// Created by parallax
//

#ifndef PARALLAX_REFLECT_H
#define PARALLAX_REFLECT_H

#include <jni.h>
#include <string>
#include "parallax_jni.h"
#include "parallax_log.h"

namespace parallax::reflect {
        class Reflect {
        protected:
            JNIEnv *m_env = nullptr;
            jobject m_obj = nullptr;

            virtual const char *getClassName() = 0;

        public:
            jobject getInstance() {
                if (m_obj != nullptr) {
                    return m_obj;
                }
                return nullptr;
            }
            jclass getClass() {
                if (m_obj == nullptr) {
                    return jni::FindClass(m_env, getClassName());
                } else {
                    return m_env->GetObjectClass(m_obj);
                }
            }

        };
    }

#endif //PARALLAX_REFLECT_H
