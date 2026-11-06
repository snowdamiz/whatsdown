#include <jni.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>

#include "libmessenger_mobile.h"
#include "MeshMessengerCallbackThread.h"

namespace {
constexpr int32_t kInvalidInput = 1;
constexpr int32_t kNotFound = 2;
constexpr int32_t kPlatformFailure = 3;
constexpr int32_t kOutputTooLarge = 4;
constexpr int32_t kJavaFailure = 5;
constexpr size_t kMaximumPushFrameLength = 4362;
constexpr size_t kMaximumRpcTLSRootsLength = 82002;
constexpr char kRawPushSelector[] = "expo/raw/v1";
constexpr char kConfigPushSelector[] = "expo/config/v1";
constexpr char kCounterConfigSelector[] = "messenger/network-counter/v1";
constexpr char kSecurityConfigSelector[] = "messenger/config/v1";
constexpr char kNetworkConfigSelector[] = "messenger/network/v1";
constexpr char kOhttpConfigSelector[] = "messenger/ohttp/v1";
constexpr char kIssuerTLSSelector[] = "messenger/issuer-tls-root/v1";
constexpr char kRpcTLSSelector[] = "messenger/rpc-tls-roots/v1";
constexpr char kLightningSelector[] = "messenger/lightning/v1";
constexpr char kCreditPurposeSelector[] = "messenger/credits/v1";
constexpr char kWalletPinsSelector[] = "messenger/wallet/v1";

JavaVM *g_vm = nullptr;
jclass g_store_class = nullptr;
jclass g_push_class = nullptr;
jmethodID g_put = nullptr;
jmethodID g_get = nullptr;
jmethodID g_delete = nullptr;
jmethodID g_consume_push_material = nullptr;
jmethodID g_build_push_config = nullptr;
jmethodID g_build_security_config = nullptr;
jmethodID g_build_network_config = nullptr;
jmethodID g_build_ohttp_config = nullptr;
jmethodID g_counter_config = nullptr;
jmethodID g_lightning_network = nullptr;
jmethodID g_issuer_tls_root = nullptr;
jmethodID g_rpc_tls_roots = nullptr;
jmethodID g_credit_purpose = nullptr;
jmethodID g_wallet_pins = nullptr;
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

int32_t ZeroByteArray(JNIEnv *environment, jbyteArray bytes, jsize length) {
  jbyte *data = environment->GetByteArrayElements(bytes, nullptr);
  if (data == nullptr) return JavaStatus(environment);
  volatile jbyte *cursor = data;
  for (jsize index = 0; index < length; ++index) cursor[index] = 0;
  environment->ReleaseByteArrayElements(bytes, data, 0);
  return JavaStatus(environment);
}

int32_t SecureStorePutOnJvmThread(void *, const uint8_t *input, uint64_t input_length,
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

int32_t SecureStoreGetOnJvmThread(void *, const uint8_t *input, uint64_t input_length,
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

int32_t SecureStoreDeleteOnJvmThread(void *, const uint8_t *input, uint64_t input_length,
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

int32_t PushGetTokenOnJvmThread(void *, const uint8_t *input, uint64_t input_length,
                     uint8_t *output, uint64_t output_capacity,
                     uint64_t *output_length) {
  if (input == nullptr || output == nullptr || output_length == nullptr) {
    return kInvalidInput;
  }
  *output_length = 0;
  bool consume = input_length == sizeof(kRawPushSelector) - 1 &&
                 std::memcmp(input, kRawPushSelector,
                             sizeof(kRawPushSelector) - 1) == 0;
  bool read_config = input_length == sizeof(kConfigPushSelector) - 1 &&
                     std::memcmp(input, kConfigPushSelector,
                                 sizeof(kConfigPushSelector) - 1) == 0;
  bool read_counter_config = input_length == sizeof(kCounterConfigSelector) - 1 &&
      std::memcmp(input, kCounterConfigSelector, sizeof(kCounterConfigSelector) - 1) == 0;
  bool read_security_config =
      input_length == sizeof(kSecurityConfigSelector) - 1 &&
      std::memcmp(input, kSecurityConfigSelector,
                  sizeof(kSecurityConfigSelector) - 1) == 0;
  bool read_lightning = input_length == sizeof(kLightningSelector) - 1 &&
      std::memcmp(input, kLightningSelector, sizeof(kLightningSelector) - 1) == 0;
  bool read_credit_purpose = input_length == sizeof(kCreditPurposeSelector) - 1 &&
      std::memcmp(input, kCreditPurposeSelector, sizeof(kCreditPurposeSelector) - 1) == 0;
  bool read_wallet_pins = input_length == sizeof(kWalletPinsSelector) - 1 &&
      std::memcmp(input, kWalletPinsSelector, sizeof(kWalletPinsSelector) - 1) == 0;
  bool read_network_config = input_length == sizeof(kNetworkConfigSelector) - 1 &&
      std::memcmp(input, kNetworkConfigSelector, sizeof(kNetworkConfigSelector) - 1) == 0;
  bool read_ohttp_config = input_length == sizeof(kOhttpConfigSelector) - 1 &&
      std::memcmp(input, kOhttpConfigSelector, sizeof(kOhttpConfigSelector) - 1) == 0;
  bool read_issuer_tls = input_length == sizeof(kIssuerTLSSelector) - 1 &&
      std::memcmp(input, kIssuerTLSSelector, sizeof(kIssuerTLSSelector) - 1) == 0;
  bool read_rpc_tls = input_length == sizeof(kRpcTLSSelector) - 1 &&
      std::memcmp(input, kRpcTLSSelector, sizeof(kRpcTLSSelector) - 1) == 0;
  if (!read_ohttp_config && !read_counter_config && !read_issuer_tls && !read_rpc_tls && !consume && !read_config && !read_security_config && !read_credit_purpose && !read_wallet_pins && !read_network_config && !read_lightning) return kInvalidInput;
  std::lock_guard<std::mutex> guard(g_store_lock);
  jmethodID method = consume ? g_consume_push_material
                             : read_config ? g_build_push_config
                                           : read_ohttp_config ? g_build_ohttp_config : read_counter_config ? g_counter_config : read_issuer_tls ? g_issuer_tls_root : read_rpc_tls ? g_rpc_tls_roots : read_lightning ? g_lightning_network : read_credit_purpose ? g_credit_purpose : read_wallet_pins ? g_wallet_pins : read_network_config ? g_build_network_config : g_build_security_config;
  if (g_push_class == nullptr || method == nullptr) {
    return kPlatformFailure;
  }
  bool attached;
  JNIEnv *environment = CurrentEnvironment(&attached);
  if (environment == nullptr) return kPlatformFailure;
  auto result = static_cast<jbyteArray>(environment->CallStaticObjectMethod(
      g_push_class, method));
  int32_t java_status = JavaStatus(environment);
  if (java_status != MESH_LIBRARY_OK) {
    ReleaseEnvironment(attached);
    return java_status;
  }
  if (result == nullptr) {
    ReleaseEnvironment(attached);
    return read_rpc_tls ? kPlatformFailure : kNotFound;
  }

  jsize result_length = environment->GetArrayLength(result);
  int32_t status = MESH_LIBRARY_OK;
  if (result_length < (read_rpc_tls ? 2 : 1) ||
      static_cast<size_t>(result_length) > (read_ohttp_config ? 600 : read_counter_config ? 24576 : read_issuer_tls ? 67591 : read_rpc_tls ? kMaximumRpcTLSRootsLength : read_network_config ? 8240 : kMaximumPushFrameLength)) {
    status = kInvalidInput;
  } else if (static_cast<uint64_t>(result_length) > output_capacity) {
    status = kOutputTooLarge;
  } else {
    environment->GetByteArrayRegion(result, 0, result_length,
                                    reinterpret_cast<jbyte *>(output));
    status = JavaStatus(environment);
    if (status == MESH_LIBRARY_OK) {
      *output_length = static_cast<uint64_t>(result_length);
    }
  }

  if (consume && result_length > 0) {
    int32_t zero_status = ZeroByteArray(environment, result, result_length);
    if (status == MESH_LIBRARY_OK && zero_status != MESH_LIBRARY_OK) {
      *output_length = 0;
      status = zero_status;
    }
  }
  environment->DeleteLocalRef(result);
  ReleaseEnvironment(attached);
  return status;
}

using HostCallback = int32_t (*)(void *, const uint8_t *, uint64_t, uint8_t *, uint64_t, uint64_t *);

int32_t CallOnJvmThread(HostCallback callback, void *context,
                       const uint8_t *input, uint64_t input_length,
                       uint8_t *output, uint64_t output_capacity,
                       uint64_t *output_length) {
  if (output_length != nullptr) *output_length = 0;
  return MeshMessengerRunCallbackOnNativeStack([&] {
    return callback(context, input, input_length, output, output_capacity, output_length);
  });
}

int32_t SecureStorePut(void *context, const uint8_t *input, uint64_t input_length,
                       uint8_t *output, uint64_t output_capacity, uint64_t *output_length) {
  return CallOnJvmThread(SecureStorePutOnJvmThread, context, input, input_length, output, output_capacity, output_length);
}

int32_t SecureStoreGet(void *context, const uint8_t *input, uint64_t input_length,
                       uint8_t *output, uint64_t output_capacity, uint64_t *output_length) {
  return CallOnJvmThread(SecureStoreGetOnJvmThread, context, input, input_length, output, output_capacity, output_length);
}

int32_t SecureStoreDelete(void *context, const uint8_t *input, uint64_t input_length,
                          uint8_t *output, uint64_t output_capacity, uint64_t *output_length) {
  return CallOnJvmThread(SecureStoreDeleteOnJvmThread, context, input, input_length, output, output_capacity, output_length);
}

int32_t PushGetToken(void *context, const uint8_t *input, uint64_t input_length,
                     uint8_t *output, uint64_t output_capacity, uint64_t *output_length) {
  return CallOnJvmThread(PushGetTokenOnJvmThread, context, input, input_length, output, output_capacity, output_length);
}

void ClearStore(JNIEnv *environment) {
  if (g_store_class != nullptr) environment->DeleteGlobalRef(g_store_class);
  if (g_push_class != nullptr) environment->DeleteGlobalRef(g_push_class);
  g_store_class = nullptr;
  g_push_class = nullptr;
  g_put = nullptr;
  g_get = nullptr;
  g_delete = nullptr;
  g_consume_push_material = nullptr;
  g_build_push_config = nullptr;
  g_build_security_config = nullptr;
  g_build_network_config = nullptr;
  g_build_ohttp_config = nullptr;
  g_counter_config = nullptr;
  g_credit_purpose = nullptr;
  g_lightning_network = nullptr;
  g_issuer_tls_root = nullptr;
  g_rpc_tls_roots = nullptr;
  g_wallet_pins = nullptr;
}
}  // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  g_vm = vm;
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jint JNICALL
Java_expo_modules_meshmessenger_MeshMessengerHost_registerHostCallbacks(
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
  local = environment->FindClass(
      "expo/modules/meshmessenger/MeshMessengerPushMaterial");
  if (local == nullptr) {
    environment->ExceptionClear();
    ClearStore(environment);
    return kJavaFailure;
  }
  g_push_class = static_cast<jclass>(environment->NewGlobalRef(local));
  environment->DeleteLocalRef(local);
  if (g_push_class == nullptr) {
    ClearStore(environment);
    return kJavaFailure;
  }
  g_consume_push_material =
      environment->GetStaticMethodID(g_push_class, "consume", "()[B");
  g_build_push_config =
      environment->GetStaticMethodID(g_push_class, "buildConfig", "()[B");
  g_build_security_config =
      environment->GetStaticMethodID(g_push_class, "securityConfig", "()[B");
  g_build_network_config =
      environment->GetStaticMethodID(g_push_class, "networkConfig", "()[B");
  g_build_ohttp_config = environment->GetStaticMethodID(g_push_class, "ohttpConfig", "()[B");
  g_counter_config = environment->GetStaticMethodID(g_push_class, "networkCounterConfig", "()[B");
  g_issuer_tls_root = environment->GetStaticMethodID(g_push_class, "issuerTLSRoot", "()[B");
  g_rpc_tls_roots = environment->GetStaticMethodID(g_push_class, "rpcTLSRoots", "()[B");
  g_lightning_network = environment->GetStaticMethodID(g_push_class, "lightningNetwork", "()[B");
  g_credit_purpose = environment->GetStaticMethodID(g_push_class, "creditPurpose", "()[B");
  g_wallet_pins = environment->GetStaticMethodID(g_push_class, "walletPins", "()[B");
  if (g_consume_push_material == nullptr || g_build_push_config == nullptr ||
      g_build_security_config == nullptr || g_counter_config == nullptr || g_build_network_config == nullptr || g_build_ohttp_config == nullptr || g_issuer_tls_root == nullptr || g_rpc_tls_roots == nullptr || g_lightning_network == nullptr || g_credit_purpose == nullptr || g_wallet_pins == nullptr) {
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
  callbacks.push_get_token = PushGetToken;
  jint status = mesh_library_register_host_callbacks(&callbacks);
  if (status != MESH_LIBRARY_OK) ClearStore(environment);
  return status;
}

extern "C" JNIEXPORT void JNICALL
Java_expo_modules_meshmessenger_MeshMessengerHost_unregisterHostCallbacks(
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
