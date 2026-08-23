//
// Created by parallax
//

#ifndef PARALLAX_JAVA_LANG_CLASS_H
#define PARALLAX_JAVA_LANG_CLASS_H

#include "parallax_reflect.h"
#include "../parallax_jni.h"

namespace parallax::reflect {

        class java_lang_Class : Reflect{
        public:
            java_lang_Class(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
        public:
            jstring getName();
        protected:
            const char * getClassName() override {
                return "java/lang/Class";
            }

        };

    } // reflect

#endif //PARALLAX_JAVA_LANG_CLASS_H
