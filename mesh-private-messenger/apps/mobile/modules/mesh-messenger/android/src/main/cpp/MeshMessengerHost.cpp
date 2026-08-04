#include <jni.h>

#include <cstdint>
#include <limits>
#include <mutex>

#include "libmessenger_mobile.h"

namespace {
constexpr int32_t kInvalidInput = 1;
constexpr int32_t kNotFound = 2;
constexpr int32_t kPlatformFailure = 3;
constexpr int32_t kOutputTooLarge = 4;
constexpr int32_t kJavaFailure = 5;

JavaVM *g_vm = nullptr;
jclass g_store_class = nullptr;
jmethodID g_put = nullptr;
jmethodID g_get = nullptr;
jmethodID g_delete = nullptr;
std::mutex g_store_lock;

JNIEnv *CurrentEnvironment(bool *attached) {
  *attached = false;
  if (g_vm == nullptr) return nullptr;
  JNIEnv *environment = nullptr;
  jint status = g_vm->GetEnv(reinterpret_cast<void **>(&environment), JNI_VERSION_1_6);
  if (status == JNI_OK) return environment;
  if (status != JNI_EDETACHED) return nullptr;
#if defined(__ANDROID__)
  if (g_vm->AttachCurrentThread(&environment, nullptr) != JNI_OK) return nullptr;
#else
  if (g_vm->AttachCurrentThread(reinterpret_cast<void **>(&environment), nullptr) != JNI_OK) return nullptr;
#endif
  *attached = true;
  return environment;
}

void ReleaseEnvironment(bool attached) {
  if (attached) g_vm->DetachCurrentThread();
}

jbyteArray RequestBytes(JNIEnv *environment, const uint8_t *input,
                        uint64_t input_length) {
  if ((input == nullptr && input_length != 0) ||
      input_length > static_cast<uint64_t>(std::numeric_limits<jsize>::max())) {
    return nullptr;
  }
  auto request = environment->NewByteArray(static_cast<jsize>(input_length));
  if (request != nullptr && input_length != 0) {
    environment->SetByteArrayRegion(request, 0, static_cast<jsize>(input_length),
                                    reinterpret_cast<const jbyte *>(input));
  }
  return request;
}

int32_t JavaStatus(JNIEnv *environment) {
  if (!environment->ExceptionCheck()) return MESH_LIBRARY_OK;
  environment->ExceptionClear();
  return kJavaFailure;
}

int32_t SecureStorePut(void *, const uint8_t *input, uint64_t input_length,
                       uint8_t *, uint64_t, uint64_t *output_length) {
  if (output_length == nullptr) return kInvalidInput;
  *output_length = 0;
  std::lock_guard<std::mutex> guard(g_store_lock);
  if (g_store_class == nullptr || g_put == nullptr) return kPlatformFailure;
  bool attached;
  JNIEnv *environment = CurrentEnvironment(&attached);
  if (environment == nullptr) return kPlatformFailure;
  jbyteArray request = RequestBytes(environment, input, input_length);
  if (request == nullptr) {
    ReleaseEnvironment(attached);
    return kInvalidInput;
  }
  jint status = environment->CallStaticIntMethod(g_store_class, g_put, request);
  environment->DeleteLocalRef(request);
  int32_t java_status = JavaStatus(environment);
  ReleaseEnvironment(attached);
  return java_status == MESH_LIBRARY_OK ? status : java_status;
}

int32_t SecureStoreGet(void *, const uint8_t *input, uint64_t input_length,
                       uint8_t *output, uint64_t output_capacity,
                       uint64_t *output_length) {
  if (output == nullptr || output_length == nullptr) return kInvalidInput;
  *output_length = 0;
  std::lock_guard<std::mutex> guard(g_store_lock);
  if (g_store_class == nullptr || g_get == nullptr) return kPlatformFailure;
  bool attached;
  JNIEnv *environment = CurrentEnvironment(&attached);
  if (environment == nullptr) return kPlatformFailure;
  jbyteArray request = RequestBytes(environment, input, input_length);
  if (request == nullptr) {
    ReleaseEnvironment(attached);
    return kInvalidInput;
  }
  auto result = static_cast<jbyteArray>(
      environment->CallStaticObjectMethod(g_store_class, g_get, request));
  environment->DeleteLocalRef(request);
  int32_t java_status = JavaStatus(environment);
  if (java_status != MESH_LIBRARY_OK) {
    ReleaseEnvironment(attached);
    return java_status;
  }
  if (result == nullptr) {
    ReleaseEnvironment(attached);
    return kNotFound;
  }
  jsize result_length = environment->GetArrayLength(result);
  if (static_cast<uint64_t>(result_length) > output_capacity) {
    environment->DeleteLocalRef(result);
    ReleaseEnvironment(attached);
    return kOutputTooLarge;
  }
  if (result_length != 0) {
    environment->GetByteArrayRegion(result, 0, result_length,
                                    reinterpret_cast<jbyte *>(output));
  }
  environment->DeleteLocalRef(result);
  java_status = JavaStatus(environment);
  ReleaseEnvironment(attached);
  if (java_status != MESH_LIBRARY_OK) return java_status;
  *output_length = static_cast<uint64_t>(result_length);
  return MESH_LIBRARY_OK;
}

int32_t SecureStoreDelete(void *, const uint8_t *input, uint64_t input_length,
                          uint8_t *, uint64_t, uint64_t *output_length) {
  if (output_length == nullptr) return kInvalidInput;
  *output_length = 0;
  std::lock_guard<std::mutex> guard(g_store_lock);
  if (g_store_class == nullptr || g_delete == nullptr) return kPlatformFailure;
  bool attached;
  JNIEnv *environment = CurrentEnvironment(&attached);
  if (environment == nullptr) return kPlatformFailure;
  jbyteArray request = RequestBytes(environment, input, input_length);
  if (request == nullptr) {
    ReleaseEnvironment(attached);
    return kInvalidInput;
  }
  jint status = environment->CallStaticIntMethod(g_store_class, g_delete, request);
  environment->DeleteLocalRef(request);
  int32_t java_status = JavaStatus(environment);
  ReleaseEnvironment(attached);
  return java_status == MESH_LIBRARY_OK ? status : java_status;
}

void ClearStore(JNIEnv *environment) {
  if (g_store_class != nullptr) environment->DeleteGlobalRef(g_store_class);
  g_store_class = nullptr;
  g_put = nullptr;
  g_get = nullptr;
  g_delete = nullptr;
}
}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  g_vm = vm;
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jint JNICALL
Java_expo_modules_meshmessenger_MeshMessengerHost_registerSecureStore(
    JNIEnv *environment, jclass) {
  std::lock_guard<std::mutex> guard(g_store_lock);
  ClearStore(environment);
  jclass local = environment->FindClass(
      "expo/modules/meshmessenger/MeshMessengerSecureStore");
  if (local == nullptr) {
    environment->ExceptionClear();
    return kJavaFailure;
  }
  g_store_class = static_cast<jclass>(environment->NewGlobalRef(local));
  environment->DeleteLocalRef(local);
  if (g_store_class == nullptr) return kJavaFailure;
  g_put = environment->GetStaticMethodID(g_store_class, "put", "([B)I");
  g_get = environment->GetStaticMethodID(g_store_class, "get", "([B)[B");
  g_delete = environment->GetStaticMethodID(g_store_class, "delete", "([B)I");
  if (g_put == nullptr || g_get == nullptr || g_delete == nullptr) {
    environment->ExceptionClear();
    ClearStore(environment);
    return kJavaFailure;
  }

  MeshLibraryHostCallbacksV1 callbacks = {};
  callbacks.abi_version = MESH_LIBRARY_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.secure_store_put = SecureStorePut;
  callbacks.secure_store_get = SecureStoreGet;
  callbacks.secure_store_delete = SecureStoreDelete;
  jint status = mesh_library_register_host_callbacks(&callbacks);
  if (status != MESH_LIBRARY_OK) ClearStore(environment);
  return status;
}

extern "C" JNIEXPORT void JNICALL
Java_expo_modules_meshmessenger_MeshMessengerHost_unregisterSecureStore(
    JNIEnv *environment, jclass) {
  std::lock_guard<std::mutex> guard(g_store_lock);
  ClearStore(environment);
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *) {
  JNIEnv *environment = nullptr;
  if (vm->GetEnv(reinterpret_cast<void **>(&environment), JNI_VERSION_1_6) == JNI_OK) {
    std::lock_guard<std::mutex> guard(g_store_lock);
    ClearStore(environment);
  }
  g_vm = nullptr;
}
