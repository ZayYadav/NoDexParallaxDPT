//
// Created by parallax
//

#ifndef PARALLAX_DALVIK_SYSTEM_BASEDEXCLASSLOADER_H
#define PARALLAX_DALVIK_SYSTEM_BASEDEXCLASSLOADER_H
#include "parallax_reflect.h"
#include "../parallax_jni.h"


namespace parallax::reflect {
        class dalvik_system_BaseDexClassLoader : public Reflect {
        private:
            const jni::JNINativeField path_list_field = {"pathList",
                                                         "Ldalvik/system/DexPathList;"};
        public:
            dalvik_system_BaseDexClassLoader(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
            jobjectArray getPathList();
            void setPathList(jobject pathList);

        protected:
            const char *getClassName() override {
                return "dalvik/system/BaseDexClassLoader";
            }
        };
    }
#endif //PARALLAX_DALVIK_SYSTEM_BASEDEXCLASSLOADER_H
