#ifndef MORSE_DESKTOP_POLICY_BRIDGE_H
#define MORSE_DESKTOP_POLICY_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Internal native ABI only, never an IPC. Open runs off main and obtains the
// app-lifetime anchored OS owner guard BEFORE policy construction. The caller
// retains the resulting context through Core/controller/UI retirement.
void *MDNativePolicyOpen(const char *bundle_identifier, const char *app_data_directory, int32_t *failure);
bool MDNativePolicyCurrent(void *context);
// Native-only retained directory capability. Caller owns returned CLOEXEC FD;
// -1 on refusal. It is duplicated from the anchored process owner, never a path.
int MDNativePolicyDuplicateOwnedDirectory(void *context);
int32_t MDNativePolicyRead(void *context, uint8_t install[16], uint64_t *sequence, uint32_t *policy);
int32_t MDNativePolicyTransition(void *context, const uint8_t previous_install[16], uint64_t previous_sequence,
    uint32_t previous_policy, uint32_t desired, uint8_t install[16], uint64_t *sequence, uint32_t *policy);
void MDNativePolicyRetain(void *context);
void MDNativePolicyRelease(void *context);
#ifdef __cplusplus
}
#endif
#endif
