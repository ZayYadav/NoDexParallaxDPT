//
// Created by parallax
//

#ifndef PARALLAX_ANDROID_APP_CONTEXTIMPL_H
#define PARALLAX_ANDROID_APP_CONTEXTIMPL_H

#include "parallax_reflect.h"
#include "../parallax_jni.h"

namespace parallax::reflect {

        class android_app_ContextImpl : public Reflect{
            private:
            jni::JNINativeField m_outer_context_field = {"mOuterContext",
                                                               "Landroid/content/Context;"};
        public:
            void setOuterContext(jobject context);

            android_app_ContextImpl(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
        protected:
            const char * getClassName() override {
                return "android/app/Application";
            }
        };

    } // reflect

#endif //PARALLAX_ANDROID_APP_CONTEXTIMPL_H
