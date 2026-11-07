#ifndef PROOF_H
#define PROOF_H

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
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_inbox_proof_caller_pc(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_inbox_proof_batch_selection(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_inbox_proof_path_selection(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_inbox_proof_whole_argument(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_inbox_proof_wire_argument(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_initialize(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_validate_outer(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_store_envelope(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_create_account(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_load_profile(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_create_signup_draft(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_signup_draft_state(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_action_recovery(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_signup_policy(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_signup_policy_view(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_signup_draft_rename(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_signup_draft_free(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_signup_draft_free_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_signup(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_signup_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_register_signup_policy(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_receipt(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_part(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_part_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_prune(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_preview(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachments(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_download_plan(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_replenish_prekeys(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_reconcile_prekeys(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_create_link_request(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_device_link_sas(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_authorize_device_link_for_set(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_complete_device_link(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_inspect_device_set(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_create_device_revocation(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_account_deletion(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_erase_account(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_device_departure(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_forget_on_proof(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_receive_initial(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_prepare_fanout_prekeys(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_send_fanout(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_key_package(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_invite(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_invitation_accept(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_invitation_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_invitation_decline(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_invitations(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_create(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_add(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_remove(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_send(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_receive(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_list(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_inspect(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_history(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_forget(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_receive_message(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_update_conversation(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_intent(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_action_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_status(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_list_conversations(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 16794632 bytes. */
int32_t mesh_messenger_load_history(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_safety_number(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_import_contact(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_directory_entry(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_directory_lookup(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_transparency_lookup(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_register_request(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_renew_devices(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_resolve_request(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_resolve_plan(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_verify_transparency(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_transparency_fork(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_status(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_set_enabled(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_commit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_unavailable(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_status(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_cancel(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_commit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_bounty_transfer_submit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_anchor_check(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_fork_filing(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_privacy_submission(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_mailbox_fetch(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_mailbox_synchronize(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_mailbox_stream_open(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_mailbox_stream_poll(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_mailbox_stream_close(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_process_delivery_batch(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_outbox_list(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_outbox_drain(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_outbox_ack(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_outbox_fail(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_outbox_page(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_journal_load(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_journal_save(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_presentation_load(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_presentation_save(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_seal_chunk(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_discover_online(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_purchase_continue(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_payment_handoff(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_action_continue(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_signup_policy_online(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_discovery(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_admit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_prepare_again(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_quote(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_payment(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_finalize(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_purchases(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_balance(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_reserve(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_reservation(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_retention(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_retention_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_receipt(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_payment_url(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_payment_signature(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_wallet_quote(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_wallet_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_wallet_commit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_wallet_submit(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_candidate(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_preview(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_recover(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_receipt(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_inventory(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_postage_policy_view(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_postage_policy_prepare(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_postage_continue(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_postage_policy_publish(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_directory_register(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_prekeys_synchronize(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_grant(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_upload(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_credit_attachment_delete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_fetch_chunk(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 16830000 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_upload(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_attachment_discard(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_directory_resolve(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_flow_intent(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_flow_complete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_push_flow_send(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40243 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_push_flow_begin(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 4154 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_push_flow_validate(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40238 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_account_delete(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40238 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_account_discard(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40238 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_account_capabilities(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 309364 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_devices_renew(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 309384 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_device_revoke(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40498 bytes. Response/error limit: 262144 bytes. */
int32_t mesh_messenger_journal_load_bound(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 302646 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_journal_save_bound(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 88740 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_fanout_send(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_network_counter(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 1048576 bytes. Response/error limit: 1048576 bytes. */
int32_t mesh_messenger_group_policy(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 42004 bytes. Response/error limit: 16801001 bytes. */
int32_t mesh_messenger_backup_create(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 16841207 bytes. Response/error limit: 8192 bytes. */
int32_t mesh_messenger_backup_preview(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 16841239 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_backup_import(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40239 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_backup_list(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40271 bytes. Response/error limit: 4096 bytes. */
int32_t mesh_messenger_backup_remove(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40271 bytes. Response/error limit: 8192 bytes. */
int32_t mesh_messenger_backup_overview(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40313 bytes. Response/error limit: 135168 bytes. */
int32_t mesh_messenger_backup_page(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40239 bytes. Response/error limit: 46 bytes. */
int32_t mesh_messenger_backup_pending_state(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 44371 bytes. Response/error limit: 16796869 bytes. */
int32_t mesh_messenger_backup_pending_resume(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40271 bytes. Response/error limit: 34 bytes. */
int32_t mesh_messenger_backup_pending_discard(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40239 bytes. Response/error limit: 32 bytes. */
int32_t mesh_messenger_backup_pending_repair(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);
/* Request limit: 40271 bytes. Response/error limit: 16777225 bytes. */
int32_t mesh_messenger_view_once_consume(const uint8_t *request, uint64_t request_len, MeshLibraryBytes *response);

#ifdef __cplusplus
}
#endif

#endif
