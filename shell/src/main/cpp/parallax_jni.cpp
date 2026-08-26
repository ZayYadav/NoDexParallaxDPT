//
// Created by parallax
//

#include "parallax_jni.h"

namespace parallax::jni {
namespace {

inline bool clearPendingException(JNIEnv *env) {
    if (env != nullptr && env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}

} // namespace

jobject makeBoolean(JNIEnv *env, jboolean value) {
    jclass booleanClass = jni::FindClass(env, "java/lang/Boolean");
    if (booleanClass == nullptr) return nullptr;
    jobject result = jni::NewObject(env, booleanClass, "(Z)V", value);
    DeleteLocalRef(env, booleanClass);
    return result;
}

jobject makeInteger(JNIEnv *env, jint value) {
    jclass integerClass = jni::FindClass(env, "java/lang/Integer");
    if (integerClass == nullptr) return nullptr;
    jobject result = jni::NewObject(env, integerClass, "(I)V", value);
    DeleteLocalRef(env, integerClass);
    return result;
}

jobject GetObjectField(JNIEnv *env, jobject obj, const JNINativeField *jniNativeField) {
    if (jniNativeField == nullptr) return nullptr;
    return jni::GetObjectField(env, obj, jniNativeField->name, jniNativeField->signature);
}

jobject GetObjectField(JNIEnv *env, jobject obj, const char *field_name, const char *sig) {
    if (env == nullptr || obj == nullptr || field_name == nullptr || sig == nullptr) {
        return nullptr;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return nullptr;
    }
    jfieldID fid = env->GetFieldID(klass, field_name, sig);
    if (fid == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return nullptr;
    }
    jobject value = env->GetObjectField(obj, fid);
    if (clearPendingException(env)) {
        value = nullptr;
    }
    DeleteLocalRef(env, klass);
    return value;
}

jobject GetStaticObjectField(JNIEnv *env, jclass klass, const JNINativeField *jniNativeField) {
    if (jniNativeField == nullptr) return nullptr;
    return jni::GetStaticObjectField(env, klass, jniNativeField->name,
                                     jniNativeField->signature);
}

jobject GetStaticObjectField(JNIEnv *env, jclass klass, const char *field_name, const char *sig) {
    if (env == nullptr || klass == nullptr || field_name == nullptr || sig == nullptr) {
        return nullptr;
    }
    jfieldID fid = env->GetStaticFieldID(klass, field_name, sig);
    if (fid == nullptr || clearPendingException(env)) {
        return nullptr;
    }
    jobject value = env->GetStaticObjectField(klass, fid);
    if (clearPendingException(env)) {
        return nullptr;
    }
    return value;
}

void SetObjectField(JNIEnv *env, jobject obj, const JNINativeField *jniNativeField, jobject value) {
    if (jniNativeField == nullptr) return;
    SetObjectField(env, obj, jniNativeField->name, jniNativeField->signature, value);
}

void SetObjectField(JNIEnv *env, jobject obj, const char *field_name, const char *sig,
                    jobject value) {
    if (env == nullptr || obj == nullptr || field_name == nullptr || sig == nullptr) {
        return;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return;
    }
    jfieldID fid = env->GetFieldID(klass, field_name, sig);
    if (fid == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return;
    }
    // Setting an object field to null is valid and is required by parts of the
    // Application swap. Never treat a null value as a JNI failure.
    env->SetObjectField(obj, fid, value);
    clearPendingException(env);
    DeleteLocalRef(env, klass);
}

void SetStaticObjectField(JNIEnv *env, jclass klass, const JNINativeField *jniNativeField,
                          jobject value) {
    if (jniNativeField == nullptr) return;
    SetStaticObjectField(env, klass, jniNativeField->name, jniNativeField->signature, value);
}

void SetStaticObjectField(JNIEnv *env, jclass klass, const char *field_name, const char *sig,
                          jobject value) {
    if (env == nullptr || klass == nullptr || field_name == nullptr || sig == nullptr) {
        return;
    }
    jfieldID fid = env->GetStaticFieldID(klass, field_name, sig);
    if (fid == nullptr || clearPendingException(env)) {
        return;
    }
    env->SetStaticObjectField(klass, fid, value);
    clearPendingException(env);
}

jclass FindClass(JNIEnv *env, const char *class_name) {
    if (env == nullptr || class_name == nullptr || class_name[0] == '\0') {
        return nullptr;
    }
    jclass cls = env->FindClass(class_name);
    if (cls == nullptr || clearPendingException(env)) {
        return nullptr;
    }
    return cls;
}

jobject NewObject(JNIEnv *env, jclass klass, const char *sig, ...) {
    if (env == nullptr || klass == nullptr || sig == nullptr) {
        return nullptr;
    }
    jmethodID methodId = env->GetMethodID(klass, "<init>", sig);
    if (methodId == nullptr || clearPendingException(env)) {
        return nullptr;
    }
    va_list args;
    va_start(args, sig);
    jobject obj = env->NewObjectV(klass, methodId, args);
    va_end(args);
    if (obj == nullptr || clearPendingException(env)) {
        return nullptr;
    }
    return obj;
}

jobject CallObjectMethod(JNIEnv *env, jobject obj, const char *name, const char *sig, ...) {
    if (env == nullptr || obj == nullptr || name == nullptr || sig == nullptr) {
        return nullptr;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return nullptr;
    }
    jmethodID methodId = env->GetMethodID(klass, name, sig);
    if (methodId == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return nullptr;
    }
    va_list args;
    va_start(args, sig);
    jobject result = env->CallObjectMethodV(obj, methodId, args);
    va_end(args);
    if (clearPendingException(env)) {
        result = nullptr;
    }
    DeleteLocalRef(env, klass);
    return result;
}

jobject CallStaticObjectMethod(JNIEnv *env, jclass cls, const char *name, const char *sig, ...) {
    if (env == nullptr || cls == nullptr || name == nullptr || sig == nullptr) {
        return nullptr;
    }
    jmethodID methodId = env->GetStaticMethodID(cls, name, sig);
    if (methodId == nullptr || clearPendingException(env)) {
        return nullptr;
    }
    va_list args;
    va_start(args, sig);
    jobject result = env->CallStaticObjectMethodV(cls, methodId, args);
    va_end(args);
    if (clearPendingException(env)) {
        return nullptr;
    }
    return result;
}

jint CallIntMethod(JNIEnv *env, jobject obj, const char *name, const char *sig,
                   jint defVal, ...) {
    if (env == nullptr || obj == nullptr || name == nullptr || sig == nullptr) {
        return defVal;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return defVal;
    }
    jmethodID methodId = env->GetMethodID(klass, name, sig);
    if (methodId == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return defVal;
    }
    va_list args;
    va_start(args, defVal);
    jint result = env->CallIntMethodV(obj, methodId, args);
    va_end(args);
    if (clearPendingException(env)) {
        result = defVal;
    }
    DeleteLocalRef(env, klass);
    return result;
}

jboolean CallBooleanMethod(JNIEnv *env, jobject obj, const char *name, const char *sig,
                           uint32_t defVal, ...) {
    const jboolean fallback = defVal != 0 ? JNI_TRUE : JNI_FALSE;
    if (env == nullptr || obj == nullptr || name == nullptr || sig == nullptr) {
        return fallback;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return fallback;
    }
    jmethodID methodId = env->GetMethodID(klass, name, sig);
    if (methodId == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return fallback;
    }
    va_list args;
    va_start(args, defVal);
    jboolean result = env->CallBooleanMethodV(obj, methodId, args);
    va_end(args);
    if (clearPendingException(env)) {
        result = fallback;
    }
    DeleteLocalRef(env, klass);
    return result;
}

void CallVoidMethod(JNIEnv *env, jobject obj, const char *name, const char *sig, ...) {
    if (env == nullptr || obj == nullptr || name == nullptr || sig == nullptr) {
        return;
    }
    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return;
    }
    jmethodID methodId = env->GetMethodID(klass, name, sig);
    if (methodId == nullptr || clearPendingException(env)) {
        DeleteLocalRef(env, klass);
        return;
    }
    va_list args;
    va_start(args, sig);
    env->CallVoidMethodV(obj, methodId, args);
    va_end(args);
    clearPendingException(env);
    DeleteLocalRef(env, klass);
}

void DeleteLocalRef(JNIEnv *env, jobject obj) {
    if (env != nullptr && obj != nullptr) {
        env->DeleteLocalRef(obj);
        clearPendingException(env);
    }
}

} // namespace parallax::jni
