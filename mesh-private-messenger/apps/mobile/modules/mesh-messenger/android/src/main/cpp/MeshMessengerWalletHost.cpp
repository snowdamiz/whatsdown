#include <jni.h>
#include <array>
#include <cstdint>
#include <cstring>
#include "morse_wallet_core.h"

namespace {
struct Context {
  JNIEnv *env;
  jclass type;
  jmethodID acquire, load, replace, release, authorize;
};
void Wipe(uint8_t *data, size_t size) {
  volatile uint8_t *cursor = data;
  while (size-- != 0) *cursor++ = 0;
}
bool Failed(JNIEnv *env) {
  if (!env->ExceptionCheck()) return false;
  env->ExceptionClear();
  return true;
}
void WipeArray(JNIEnv *env, jbyteArray bytes) {
  if (bytes == nullptr) return;
  std::array<jbyte, 64> zeros{};
  const jsize size = env->GetArrayLength(bytes);
  for (jsize offset = 0; offset < size; offset += static_cast<jsize>(zeros.size())) {
    const jsize count = size - offset < static_cast<jsize>(zeros.size())
                            ? size - offset : static_cast<jsize>(zeros.size());
    env->SetByteArrayRegion(bytes, offset, count, zeros.data());
  }
}
int32_t Acquire(void *raw) {
  auto &ctx = *static_cast<Context *>(raw);
  const jint status = ctx.env->CallStaticIntMethod(ctx.type, ctx.acquire);
  return Failed(ctx.env) ? MORSE_WALLET_STORAGE : status;
}
int32_t Release(void *raw) {
  auto &ctx = *static_cast<Context *>(raw);
  const jint status = ctx.env->CallStaticIntMethod(ctx.type, ctx.release);
  return Failed(ctx.env) ? MORSE_WALLET_STORAGE : status;
}
int32_t Load(void *raw, uint8_t *record, uint64_t capacity, uint64_t *written) {
  if (written == nullptr) return MORSE_WALLET_STORAGE;
  *written = 0;
  auto &ctx = *static_cast<Context *>(raw);
  auto bytes = static_cast<jbyteArray>(ctx.env->CallStaticObjectMethod(ctx.type, ctx.load));
  if (Failed(ctx.env)) return MORSE_WALLET_STORAGE;
  if (bytes == nullptr) return MORSE_WALLET_NOT_FOUND;
  const jsize size = ctx.env->GetArrayLength(bytes);
  int32_t result = MORSE_WALLET_STORAGE;
  if (record != nullptr && size == MORSE_WALLET_RECORD_BYTES && capacity >= static_cast<uint64_t>(size)) {
    ctx.env->GetByteArrayRegion(bytes, 0, size, reinterpret_cast<jbyte *>(record));
    if (!Failed(ctx.env)) { *written = size; result = MORSE_WALLET_OK; }
  }
  WipeArray(ctx.env, bytes);
  const bool failed = Failed(ctx.env);
  ctx.env->DeleteLocalRef(bytes);
  if (failed) { *written = 0; return MORSE_WALLET_STORAGE; }
  return result;
}
int32_t Replace(void *raw, const uint8_t *record, uint64_t length) {
  if (record == nullptr || length != MORSE_WALLET_RECORD_BYTES) return MORSE_WALLET_STORAGE;
  auto &ctx = *static_cast<Context *>(raw);
  jbyteArray bytes = ctx.env->NewByteArray(MORSE_WALLET_RECORD_BYTES);
  if (bytes == nullptr || Failed(ctx.env)) return MORSE_WALLET_STORAGE;
  ctx.env->SetByteArrayRegion(bytes, 0, MORSE_WALLET_RECORD_BYTES, reinterpret_cast<const jbyte *>(record));
  jint status = MORSE_WALLET_STORAGE;
  if (!Failed(ctx.env)) status = ctx.env->CallStaticIntMethod(ctx.type, ctx.replace, bytes);
  const bool failed = Failed(ctx.env);
  WipeArray(ctx.env, bytes);
  const bool wipe_failed = Failed(ctx.env);
  ctx.env->DeleteLocalRef(bytes);
  return failed || wipe_failed ? MORSE_WALLET_STORAGE : status;
}
int32_t Authorize(void *raw, uint32_t operation, const uint8_t *intent, uint64_t length) {
  if (intent == nullptr || !((operation == MORSE_WALLET_CREATE && length == 32) ||
      (operation == MORSE_WALLET_SIGN_QUOTE && length == 288) ||
        (operation == MORSE_WALLET_MOVE_BOUNTY && length == 198))) return MORSE_WALLET_CANCELLED;
  auto &ctx = *static_cast<Context *>(raw);
  jbyteArray bytes = ctx.env->NewByteArray(static_cast<jsize>(length));
  if (bytes == nullptr || Failed(ctx.env)) return MORSE_WALLET_CANCELLED;
  ctx.env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(length), reinterpret_cast<const jbyte *>(intent));
  jint status = MORSE_WALLET_CANCELLED;
  if (!Failed(ctx.env)) status = ctx.env->CallStaticIntMethod(ctx.type, ctx.authorize, static_cast<jint>(operation), bytes);
  const bool failed = Failed(ctx.env);
  ctx.env->DeleteLocalRef(bytes);
  return failed ? MORSE_WALLET_CANCELLED : status;
}
} // namespace

// Private presentation-only JNI entry. Never registered as a Mesh or JS
// operation; the Rust helper has no storage or signing capabilities.
extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_meshmessenger_MeshMessengerWalletStore_authorizationText(
    JNIEnv *env, jclass, jint operation, jbyteArray intent) {
  if (intent == nullptr) {
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "wallet_authorization_text_invalid");
    return nullptr;
  }
  const jsize length = env->GetArrayLength(intent);
  if (!((operation == MORSE_WALLET_CREATE && length == 32) ||
        (operation == MORSE_WALLET_SIGN_QUOTE && length == 288) ||
        (operation == MORSE_WALLET_MOVE_BOUNTY && length == 198))) {
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "wallet_authorization_text_invalid");
    return nullptr;
  }
  std::array<uint8_t, 288> request{};
  std::array<uint8_t, 2048> output{};
  env->GetByteArrayRegion(intent, 0, length, reinterpret_cast<jbyte *>(request.data()));
  if (env->ExceptionCheck()) return nullptr;
  uint64_t written = 0;
  const int32_t status = morse_wallet_authorization_text(static_cast<uint32_t>(operation),
      request.data(), static_cast<uint64_t>(length), output.data(), output.size(), &written);
  Wipe(request.data(), request.size());
  if (status != MORSE_WALLET_OK || written == 0 || written > output.size()) {
    Wipe(output.data(), output.size());
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "wallet_authorization_text_invalid");
    return nullptr;
  }
  jbyteArray result = env->NewByteArray(static_cast<jsize>(written));
  if (result != nullptr) env->SetByteArrayRegion(result, 0, static_cast<jsize>(written), reinterpret_cast<const jbyte *>(output.data()));
  Wipe(output.data(), output.size());
  return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_expo_modules_meshmessenger_MeshMessengerWalletStore_invoke(
    JNIEnv *env, jclass type, jint operation, jbyteArray input) {
  if (input == nullptr || operation < MORSE_WALLET_CREATE || operation > MORSE_WALLET_MOVE_BOUNTY) {
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "wallet_invalid_request");
    return nullptr;
  }
  Context ctx{env, type,
    env->GetStaticMethodID(type, "acquire", "()I"), env->GetStaticMethodID(type, "load", "()[B"),
    env->GetStaticMethodID(type, "replace", "([B)I"), env->GetStaticMethodID(type, "release", "()I"),
    env->GetStaticMethodID(type, "authorize", "(I[B)I")};
  const jmethodID config = env->GetStaticMethodID(type, "configuredPins", "()[B");
  if (Failed(env) || ctx.acquire == nullptr || ctx.load == nullptr || ctx.replace == nullptr ||
      ctx.release == nullptr || ctx.authorize == nullptr || config == nullptr) {
    env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "wallet_native_configuration_failed");
    return nullptr;
  }
  auto pins = static_cast<jbyteArray>(env->CallStaticObjectMethod(type, config));
  if (Failed(env) || pins == nullptr || env->GetArrayLength(pins) != 33) {
    if (pins != nullptr) env->DeleteLocalRef(pins);
    env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "wallet_configuration_missing");
    return nullptr;
  }
  std::array<uint8_t, 33> pinned{};
  env->GetByteArrayRegion(pins, 0, pinned.size(), reinterpret_cast<jbyte *>(pinned.data()));
  env->DeleteLocalRef(pins);
  const jsize size = env->GetArrayLength(input);
  if (Failed(env) || size > 256) {
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "wallet_invalid_request");
    return nullptr;
  }
  std::array<uint8_t, 256> request{};
  if (size != 0) env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte *>(request.data()));
  if (Failed(env)) return nullptr;
  MorseWalletCallbacksV1 callbacks{};
  callbacks.abi_version = MORSE_WALLET_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.context = &ctx;
  callbacks.acquire = Acquire; callbacks.load = Load; callbacks.replace = Replace;
  callbacks.release = Release; callbacks.authorize = Authorize;
  std::memcpy(callbacks.usdc_mint, pinned.data(), 32);
  callbacks.purpose = pinned[32];
  std::array<uint8_t, MORSE_WALLET_MAX_PACKET_BYTES> output{};
  uint64_t written = 0;
  const int32_t status = morse_wallet_call(&callbacks, static_cast<uint32_t>(operation),
      request.data(), static_cast<uint64_t>(size), output.data(), output.size(), &written);
  Wipe(request.data(), request.size());
  if (status != MORSE_WALLET_OK || written > output.size()) {
    Wipe(output.data(), output.size());
    char reason[] = "wallet_native_error_0";
    reason[sizeof(reason) - 2] = status >= 0 && status <= 9 ? static_cast<char>('0' + status) : '?';
    env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), reason);
    return nullptr;
  }
  jbyteArray result = env->NewByteArray(static_cast<jsize>(written));
  if (result != nullptr) env->SetByteArrayRegion(result, 0, static_cast<jsize>(written), reinterpret_cast<const jbyte *>(output.data()));
  Wipe(output.data(), output.size());
  return result;
}
