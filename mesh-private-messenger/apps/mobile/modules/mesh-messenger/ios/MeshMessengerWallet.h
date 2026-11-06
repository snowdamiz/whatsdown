#ifndef MESH_MESSENGER_WALLET_H
#define MESH_MESSENGER_WALLET_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int32_t MeshMessengerWalletCall(uint32_t operation, const uint8_t *input,
                               uint64_t length, uint8_t *output,
                               uint64_t capacity, uint64_t *written);
#ifdef __cplusplus
}
#endif
#endif
