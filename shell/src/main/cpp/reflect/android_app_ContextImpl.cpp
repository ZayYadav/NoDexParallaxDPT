//
// Created by parallax
//

#include "android_app_ContextImpl.h"

using namespace parallax::reflect;

void android_app_ContextImpl::setOuterContext(jobject context) {
    parallax::jni::SetObjectField(m_env,m_obj,&m_outer_context_field,context);
}