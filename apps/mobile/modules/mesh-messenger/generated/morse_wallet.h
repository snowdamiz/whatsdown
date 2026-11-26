/* Morse wallet-core C ABI. Frame format: packages/wallet-core/README.md ("C ABI"). */
#ifndef MORSE_WALLET_H
#define MORSE_WALLET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MORSE_WALLET_FRAME_VERSION 1
#define MORSE_WALLET_OK 0
#define MORSE_WALLET_ERR_INVALID_ARGUMENT 1
#define MORSE_WALLET_ERR_PANIC 4
#define MORSE_WALLET_ERR_APPLICATION 9

typedef struct MorseWalletBytes {
  uint8_t *data;
  uint64_t len;
} MorseWalletBytes;

/* Runs one request frame (at most 65,536 bytes). Stateless and thread-safe. On return
 * *response holds the response frame (MORSE_WALLET_OK) or a UTF-8 error code
 * (MORSE_WALLET_ERR_APPLICATION); release it with morse_wallet_free_bytes either way. */
int32_t morse_wallet_call(const uint8_t *request, uint64_t request_len, MorseWalletBytes *response);

/* Wipes and frees returned bytes, then sets data to NULL and len to 0. */
void morse_wallet_free_bytes(MorseWalletBytes *bytes);

#ifdef __cplusplus
}
#endif

#endif
