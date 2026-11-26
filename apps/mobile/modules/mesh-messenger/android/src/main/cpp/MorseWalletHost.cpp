#include <jni.h>

#include <cstdint>
#include <string>
#include <vector>

#include "morse_wallet.h"

// JNI for the in-app wallet (MorseWalletModule.kt): one wallet-core call per request
// frame. The request copy and the response are wiped before this returns; the Kotlin
// side wipes its own arrays.

namespace {
void Wipe(std::vector<uint8_t> &bytes) {
  volatile uint8_t *cursor = bytes.data();
  for (size_t index = 0; index < bytes.size(); ++index) cursor[index] = 0;
}
}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_meshmessenger_MorseWalletNative_call(JNIEnv *environment, jclass,
                                                       jbyteArray request) {
  jsize length = environment->GetArrayLength(request);
  std::vector<uint8_t> bytes(static_cast<size_t>(length));
  environment->GetByteArrayRegion(request, 0, length, reinterpret_cast<jbyte *>(bytes.data()));
  MorseWalletBytes response{nullptr, 0};
  int32_t status = morse_wallet_call(bytes.data(), bytes.size(), &response);
  Wipe(bytes);
  if (status != MORSE_WALLET_OK) {
    std::string code = status == MORSE_WALLET_ERR_APPLICATION && response.data != nullptr
                           ? std::string(reinterpret_cast<const char *>(response.data), response.len)
                           : "wallet_failed";
    morse_wallet_free_bytes(&response);
    environment->ThrowNew(environment->FindClass("java/lang/IllegalStateException"), code.c_str());
    return nullptr;
  }
  jbyteArray result = environment->NewByteArray(static_cast<jsize>(response.len));
  if (result != nullptr && response.len != 0) {
    environment->SetByteArrayRegion(result, 0, static_cast<jsize>(response.len),
                                    reinterpret_cast<const jbyte *>(response.data));
  }
  morse_wallet_free_bytes(&response);
  return result;
}
