#ifndef LIBMESSENGER_MOBILE_H
#define LIBMESSENGER_MOBILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MESH_LIBRARY_ABI_VERSION 1
#define MESH_LIBRARY_OK 0
#define MESH_LIBRARY_ERR_INVALID_ARGUMENT 1
#define MESH_LIBRARY_ERR_NOT_INITIALIZED 2
#define MESH_LIBRARY_ERR_BUSY 3
#define MESH_LIBRARY_ERR_PANIC 4
#define MESH_LIBRARY_ERR_HOST_CALLBACK 5
#define MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE 6
#define MESH_LIBRARY_ERR_ABI 7
#define MESH_LIBRARY_ERR_CALLBACK_MISSING 8
#define MESH_LIBRARY_ERR_APPLICATION 9

typedef struct MeshLibraryBytes {
  uint8_t *data;
  uint64_t len;
} MeshLibraryBytes;

typedef int32_t (*MeshLibraryHostCallback)(void *context, const uint8_t *input, uint64_t input_len, uint8_t *output, uint64_t output_capacity, uint64_t *output_len);

typedef struct MeshLibraryHostCallbacksV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  void *context;
  MeshLibraryHostCallback secure_store_put;
  MeshLibraryHostCallback secure_store_get;
  MeshLibraryHostCallback secure_store_delete;
  MeshLibraryHostCallback push_get_token;
  MeshLibraryHostCallback background_schedule;
  MeshLibraryHostCallback network_state;
  MeshLibraryHostCallback monotonic_clock;
  MeshLibraryHostCallback wall_clock;
  MeshLibraryHostCallback log_redacted;
} MeshLibraryHostCallbacksV1;

int32_t mesh_library_init(void);
int32_t mesh_library_shutdown(void);
int32_t mesh_library_register_host_callbacks(const MeshLibraryHostCallbacksV1 *callbacks);
void mesh_library_free_returned_bytes(MeshLibraryBytes *bytes);
int32_t mesh_messenger_initialize(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_validate_outer(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_store_envelope(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_create_account(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_load_profile(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_replenish_prekeys(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_reconcile_prekeys(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_create_link_request(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_device_link_sas(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_authorize_device_link_for_set(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_complete_device_link(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_inspect_device_set(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_create_device_revocation(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_receive_initial(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_send_fanout(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_key_package(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_create(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_add(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_remove(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_send(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_receive(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_list(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_inspect(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_group_history(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_receive_message(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_update_conversation(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_push_intent(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_push_action_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_push_status(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_list_conversations(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_load_history(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_safety_number(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_import_contact(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_directory_entry(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_directory_lookup(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_transparency_lookup(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_verify_transparency(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_privacy_submission(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_mailbox_fetch(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_process_delivery_batch(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_outbox_list(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
int32_t mesh_messenger_outbox_ack(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);

#ifdef __cplusplus
}
#endif

#endif
