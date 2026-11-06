#ifndef MORSE_DESKTOP_WALLET_H
#define MORSE_DESKTOP_WALLET_H
#include "PrivateJob.h"
#include <stdint.h>
int32_t MorseDesktopWalletCall(void *protection, MDPrivateScope scope,
 const char *service, const char *directory, const uint8_t pins[34], uint32_t operation,
 const uint8_t *input, uint64_t input_length, uint8_t *output, uint64_t capacity, uint64_t *written);
#endif
