//
// Created by parallax
//

#ifndef PARALLAX_ANDROID_APP_LOADEDAPK_H
#define PARALLAX_ANDROID_APP_LOADEDAPK_H
#include "parallax_reflect.h"
#include "../parallax_jni.h"

namespace parallax::reflect {

        class android_app_LoadedApk : Reflect {
            jni::JNINativeField m_application_field = {"mApplication",
                                                   "Landroid/app/Application;"};

            jni::JNINativeField m_application_info_field = {"mApplicationInfo",
                                                            "Landroid/content/pm/ApplicationInfo;"};


        public:
            android_app_LoadedApk(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
        public:
            void setApplication(jobject application);
            void setApplicationInfo(jobject applicationInfo);
            jobject getApplicationInfo();
            jobject makeApplication(jboolean forceDefaultAppClass, jobject instrumentation);
        protected:
            const char * getClassName() override{
                return "android/app/LoadedApk";
            }
        };

    } // reflect

#endif //PARALLAX_ANDROID_APP_LOADEDAPK_H
