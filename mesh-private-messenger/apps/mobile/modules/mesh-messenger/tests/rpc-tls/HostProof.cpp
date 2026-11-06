#include <jni.h>
#include <algorithm>
#include <array>
#include <cstring>
#include "libmessenger_mobile.h"

static MeshLibraryHostCallbacksV1 callbacks;

extern "C" int32_t mesh_library_register_host_callbacks(const MeshLibraryHostCallbacksV1 *value) {
  callbacks = *value;
  return 0;
}

extern "C" JNIEXPORT void JNICALL
Java_expo_modules_meshmessenger_RpcTLSHostProof_checkRead(
    JNIEnv *environment, jclass, jint capacity, jint expected_status, jbyteArray expected) {
  constexpr uint8_t marker = 0xa5;
  std::array<uint8_t, 82004> output;
  output.fill(marker);
  const auto fail = [&](const char *message) {
    environment->ThrowNew(environment->FindClass("java/lang/AssertionError"), message);
  };
  if (capacity < 0 || capacity > 82002 || callbacks.push_get_token == nullptr) {
    fail("invalid proof setup");
    return;
  }
  constexpr uint8_t selector[] = "messenger/rpc-tls-roots/v1";
  uint64_t length = 999;
  const int32_t status = callbacks.push_get_token(nullptr, selector, sizeof(selector) - 1,
      output.data() + 1, static_cast<uint64_t>(capacity), &length);
  if (status != expected_status || length > static_cast<uint64_t>(capacity) || (status != 0 && length != 0)) {
    fail("RPC JNI status/length mismatch");
    return;
  }
  if (status == 0) {
    const jsize size = environment->GetArrayLength(expected);
    if (length != static_cast<uint64_t>(size)) { fail("RPC JNI length mismatch"); return; }
    std::array<jbyte, 82002> bytes;
    environment->GetByteArrayRegion(expected, 0, size, bytes.data());
    if (std::memcmp(output.data() + 1, bytes.data(), length) != 0) { fail("RPC JNI bytes mismatch"); return; }
  }
  if (output.front() != marker ||
      !std::all_of(output.begin() + 1 + length, output.end(), [](uint8_t byte) { return byte == marker; })) {
    fail("RPC JNI output guard overwritten");
  }
}
