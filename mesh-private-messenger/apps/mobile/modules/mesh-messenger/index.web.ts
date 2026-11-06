// Desktop uses the same exported ABI as the generated mobile bindings.
import { invokeMesh, invokeWallet as desktopWallet } from "../../src/desktop";
const native = { invoke: invokeMesh };

export const initialize = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_initialize', request);
export const validate_outer = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_validate_outer', request);
export const persist_envelope = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_store_envelope', request);
export const create_account_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_account', request);
export const load_profile_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_load_profile', request);
export const replenish_prekeys_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_replenish_prekeys', request);
export const reconcile_prekeys_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_reconcile_prekeys', request);
export const create_link_request_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_link_request', request);
export const device_link_sas_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_device_link_sas', request);
export const authorize_device_link_for_set_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_authorize_device_link_for_set', request);
export const complete_device_link_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_complete_device_link', request);
export const inspect_device_set_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_inspect_device_set', request);
export const receive_initial_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_initial', request);
export const group_key_package_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_key_package', request);
export const group_invitation_complete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_invitation_complete', request);
export const group_invitation_decline_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_invitation_decline', request);
export const group_invitations_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_invitations', request);
export const group_forget_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_forget', request);
export const group_create_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_create', request);
export const group_add_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_add', request);
export const group_remove_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_remove', request);
export const group_send_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_send', request);
export const group_receive_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_receive', request);
export const group_list_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_list', request);
export const group_inspect_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_inspect', request);
export const group_history_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_history', request);
export const receive_message_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_message', request);
export const update_conversation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_update_conversation', request);
export const push_flow_complete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_push_flow_complete', request);
export const push_status_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_push_status', request);
export const list_conversations_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_list_conversations', request);
export const load_history_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_load_history', request);
export const safety_number_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_safety_number', request);
export const import_contact_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_import_contact', request);
export const directory_entry_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_entry', request);
export const directory_lookup_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_lookup', request);
export const transparency_lookup_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_transparency_lookup', request);
export const register_request_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_register_request', request);
export const resolve_request_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_resolve_request', request);
export const verify_transparency_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_verify_transparency', request);
export const resolve_plan_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_resolve_plan', request);
export const transparency_fork_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_transparency_fork', request);
export const anchor_check_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_anchor_check', request);
export const fork_filing_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_fork_filing', request);
export const mailbox_synchronize_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_synchronize', request);
export const mailbox_fetch_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_fetch', request);
export const mailbox_stream_open_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_stream_open', request);
export const mailbox_stream_poll_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_stream_poll', request);
export const mailbox_stream_close_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_stream_close', request);
export const process_delivery_batch_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_process_delivery_batch', request);

export const primePushToken = async (_request: Uint8Array): Promise<void> => { throw new Error("Desktop uses live updates while open"); };
export const clearPushToken = async (_request: Uint8Array): Promise<void> => {};
export const onPushRegistrationChanged = (_listener: () => void): (() => void) => () => {};

export const presentation_load_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_presentation_load', request);
export const presentation_save_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_presentation_save', request);
export const attachment_prepare_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_prepare', request);
export const attachment_seal_chunk_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_seal_chunk', request);

export const credit_discovery_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_discovery', request);
export const credit_admit_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_admit', request);
export const credit_prepare_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_prepare', request);
export const credit_quote_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_quote', request);
export const credit_payment_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_payment', request);
export const credit_finalize_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_finalize', request);
export const credit_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_recover', request);
export const credit_purchases_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_purchases', request);
export const credit_balance_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_balance', request);
export const credit_reserve_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_reserve', request);
export const credit_reservation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_reservation', request);

export const credit_retention_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_retention', request);
export const credit_retention_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_retention_recover', request);
export const credit_receipt_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_receipt', request);

export const credit_payment_url_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_payment_url', request);
export const credit_payment_signature_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_payment_signature', request);

export const credit_wallet_quote_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_wallet_quote', request);

export const invokeWallet = (operation: number, request: Uint8Array): Promise<Uint8Array> => desktopWallet(operation, request);
export const credit_prepare_again_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_prepare_again', request);
export const create_signup_draft_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_signup_draft', request);
export const signup_draft_state_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_signup_draft_state', request);
export const signup_draft_rename_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_signup_draft_rename', request);
export const signup_draft_free_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_signup_draft_free', request);
export const credit_signup_policy_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_signup_policy', request);
export const credit_signup_policy_view_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_signup_policy_view', request);
export const credit_signup_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_signup', request);
export const credit_signup_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_signup_recover', request);
export const credit_action_recovery_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_action_recovery', request);
export const register_signup_policy_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_register_signup_policy', request);
export const signup_draft_free_complete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_signup_draft_free_complete', request);
export const credit_attachment_prepare_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_prepare', request);
export const credit_attachment_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_recover', request);
export const credit_attachment_receipt_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_receipt', request);
export const credit_attachment_part_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_part', request);
export const credit_attachment_part_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_part_recover', request);
export const credit_attachment_prune_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_prune', request);

export const credit_attachment_preview_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_preview', request);
export const credit_attachments_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachments', request);
export const attachment_download_plan_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_download_plan', request);

export const bounty_status_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_bounty_status', request);
export const credit_postage_candidate_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_candidate', request);
export const credit_postage_preview_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_preview', request);
export const credit_postage_prepare_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_prepare', request);
export const credit_postage_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_recover', request);
export const credit_postage_receipt_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_receipt', request);
export const credit_postage_inventory_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_inventory', request);
export const postage_policy_view_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_postage_policy_view', request);
export const postage_policy_prepare_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_postage_policy_prepare', request);

export const bounty_transfer_status_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_bounty_transfer_status', request);
export const bounty_transfer_recover_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_bounty_transfer_recover', request);
export const bounty_transfer_cancel_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_bounty_transfer_cancel', request);

export const credit_discover_online_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_discover_online', request);
export const credit_purchase_continue_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_purchase_continue', request);

export const credit_action_continue_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_action_continue', request);
export const credit_signup_policy_online_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_signup_policy_online', request);

export const credit_postage_continue_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_postage_continue', request);
export const postage_policy_publish_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_postage_policy_publish', request);

export const directory_register_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_register', request);
export const prekeys_synchronize_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_prekeys_synchronize', request);

export const credit_attachment_grant_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_grant', request);

export const credit_attachment_upload_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_upload', request);

export const credit_attachment_complete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_complete', request);

export const credit_attachment_delete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_credit_attachment_delete', request);

export const attachment_fetch_chunk_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_fetch_chunk', request);

export const attachment_upload_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_upload', request);
export const attachment_discard_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_attachment_discard', request);
export const directory_resolve_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_resolve', request);

export const outbox_drain_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_outbox_drain', request);

export const push_flow_send_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_push_flow_send', request);

export const push_flow_begin_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_push_flow_begin', request);
export const account_delete_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_account_delete', request);
export const account_discard_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_account_discard', request);
export const account_capabilities_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_account_capabilities', request);
export const devices_renew_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_devices_renew', request);
export const device_revoke_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_device_revoke', request);

export const journal_load_bound_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_journal_load_bound', request);
export const journal_save_bound_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_journal_save_bound', request);

export const fanout_send_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_fanout_send', request);

export const network_counter_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_network_counter', request);

export const group_policy_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_group_policy', request);
// Desktop retains its existing native authority until the separate AL2 contract.
export const isLegacyDesktopBridge = true;
