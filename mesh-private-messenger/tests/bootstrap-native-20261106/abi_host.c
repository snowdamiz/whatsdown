#include "libbootstrap.h"
#include <stddef.h>
#include <string.h>

size_t bootstrap_host_callbacks_size(void) {
  return sizeof(MeshLibraryHostCallbacksV1);
}

int32_t bootstrap_host_call(const char *symbol, const uint8_t *input,
                            uint64_t length, MeshLibraryBytes *output) {
#define CALL(name)                                                             \
  if (strcmp(symbol, #name) == 0)                                              \
    return name(input, length, output)
  CALL(mesh_messenger_create_account);
  CALL(mesh_messenger_directory_entry);
  CALL(mesh_messenger_directory_resolve);
  CALL(mesh_messenger_anchor_check);
  CALL(bootstrap_generate);
  CALL(bootstrap_lookup_response);
  CALL(bootstrap_cache_snapshot);
  CALL(bootstrap_schedule_snapshot);
  CALL(bootstrap_tls_control);
#undef CALL
  return MESH_LIBRARY_ERR_INVALID_ARGUMENT;
}
