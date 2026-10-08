#ifndef MESH_MESSENGER_SECURE_STORE_H
#define MESH_MESSENGER_SECURE_STORE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t MeshMessengerRegisterAppleHostCallbacks(void);
int32_t MeshMessengerCacheApplePushToken(const uint8_t *application_id,
                                         uint64_t application_id_length,
                                         const uint8_t *token,
                                         uint64_t token_length,
                                         bool development);
void MeshMessengerClearApplePushToken(void);
/* Mesh runtime: core size limit 0 for the rest of the process. Release hosts call
 * it at startup (see MeshMessengerSecureStore.m for the fallback). */
void mesh_rt_disable_core_dumps(void);

#ifdef __cplusplus
}
#endif

#endif
