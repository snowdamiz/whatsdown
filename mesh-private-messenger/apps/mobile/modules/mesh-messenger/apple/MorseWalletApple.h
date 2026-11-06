#ifndef MORSE_WALLET_APPLE_H
#define MORSE_WALLET_APPLE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Native callers supply only bundled pins and their private app directory.
 * No credential record is exposed by this interface. */
int32_t MorseWalletAppleCall(const char *service, const char *directory,
                            const uint8_t pins[34], uint32_t operation,
                            const uint8_t *input, uint64_t input_length,
                            uint8_t *output, uint64_t capacity, uint64_t *written);
#ifdef __cplusplus
}
#endif
#endif
