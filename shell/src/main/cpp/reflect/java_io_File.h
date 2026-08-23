//
// Created by parallax
//

#ifndef PARALLAX_JAVA_IO_FILE_H
#define PARALLAX_JAVA_IO_FILE_H

#include "parallax_reflect.h"
#include "../parallax_jni.h"

namespace parallax::reflect{
        class java_io_File : public Reflect{
        private:
            const char *className = "java/io/File";
        public:
            java_io_File(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
            java_io_File(JNIEnv *env,jstring pathname){
                this->m_env = env;
                jclass FileClass = jni::FindClass(env,className);
                this->m_obj = jni::NewObject(env,
                                             FileClass,
                                             "(Ljava/lang/String;)V",
                                             pathname);
            }
            jstring getName();
        protected:
            const char *getClassName() override {
                return className;
            }
        };
    }

#endif //PARALLAX_JAVA_IO_FILE_H
