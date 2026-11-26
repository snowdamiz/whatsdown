package mesh

object MeshLibrary {
    init {
        System.loadLibrary("messenger_mobile")
        val status = initializeNative()
        check(status == 0) { "Mesh library initialization failed (status=$status)" }
    }

    @JvmStatic fun ensureInitialized() = Unit
    @JvmStatic private external fun initializeNative(): Int
    @JvmStatic external fun shutdownNative(): Int
    @JvmStatic external fun initialize(request: ByteArray): ByteArray
    @JvmStatic external fun validate_outer(request: ByteArray): ByteArray
    @JvmStatic external fun persist_envelope(request: ByteArray): ByteArray
    @JvmStatic external fun create_account_export(request: ByteArray): ByteArray
    @JvmStatic external fun load_profile_export(request: ByteArray): ByteArray
    @JvmStatic external fun replenish_prekeys_export(request: ByteArray): ByteArray
    @JvmStatic external fun reconcile_prekeys_export(request: ByteArray): ByteArray
    @JvmStatic external fun create_link_request_export(request: ByteArray): ByteArray
    @JvmStatic external fun device_link_sas_export(request: ByteArray): ByteArray
    @JvmStatic external fun authorize_device_link_for_set_export(request: ByteArray): ByteArray
    @JvmStatic external fun complete_device_link_export(request: ByteArray): ByteArray
    @JvmStatic external fun inspect_device_set_export(request: ByteArray): ByteArray
    @JvmStatic external fun create_device_revocation_export(request: ByteArray): ByteArray
    @JvmStatic external fun account_deletion_export(request: ByteArray): ByteArray
    @JvmStatic external fun erase_account_export(request: ByteArray): ByteArray
    @JvmStatic external fun device_departure_export(request: ByteArray): ByteArray
    @JvmStatic external fun forget_on_proof_export(request: ByteArray): ByteArray
    @JvmStatic external fun receive_initial_export(request: ByteArray): ByteArray
    @JvmStatic external fun prepare_fanout_prekeys_export(request: ByteArray): ByteArray
    @JvmStatic external fun send_fanout_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_key_package_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_invite_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_invitation_accept_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_invitation_complete_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_invitation_decline_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_invitations_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_create_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_add_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_remove_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_send_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_receive_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_list_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_inspect_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_history_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_forget_export(request: ByteArray): ByteArray
    @JvmStatic external fun receive_message_export(request: ByteArray): ByteArray
    @JvmStatic external fun update_conversation_export(request: ByteArray): ByteArray
    @JvmStatic external fun push_intent_export(request: ByteArray): ByteArray
    @JvmStatic external fun push_action_complete_export(request: ByteArray): ByteArray
    @JvmStatic external fun push_status_export(request: ByteArray): ByteArray
    @JvmStatic external fun list_conversations_export(request: ByteArray): ByteArray
    @JvmStatic external fun load_history_export(request: ByteArray): ByteArray
    @JvmStatic external fun safety_number_export(request: ByteArray): ByteArray
    @JvmStatic external fun import_contact_export(request: ByteArray): ByteArray
    @JvmStatic external fun directory_entry_export(request: ByteArray): ByteArray
    @JvmStatic external fun directory_lookup_export(request: ByteArray): ByteArray
    @JvmStatic external fun transparency_lookup_export(request: ByteArray): ByteArray
    @JvmStatic external fun register_request_export(request: ByteArray): ByteArray
    @JvmStatic external fun renew_devices_export(request: ByteArray): ByteArray
    @JvmStatic external fun oblivious_encapsulate_export(request: ByteArray): ByteArray
    @JvmStatic external fun oblivious_decapsulate_export(request: ByteArray): ByteArray
    @JvmStatic external fun resolve_request_export(request: ByteArray): ByteArray
    @JvmStatic external fun verify_transparency_export(request: ByteArray): ByteArray
    @JvmStatic external fun transparency_anchor_requests_export(request: ByteArray): ByteArray
    @JvmStatic external fun transparency_anchor_proof_export(request: ByteArray): ByteArray
    @JvmStatic external fun anchor_check_export(request: ByteArray): ByteArray
    @JvmStatic external fun gossip_check_export(request: ByteArray): ByteArray
    @JvmStatic external fun trust_alarm_details_export(request: ByteArray): ByteArray
    @JvmStatic external fun wallet_rpc_urls_export(request: ByteArray): ByteArray
    @JvmStatic external fun network_status_export(request: ByteArray): ByteArray
    @JvmStatic external fun privacy_submission_export(request: ByteArray): ByteArray
    @JvmStatic external fun mailbox_fetch_export(request: ByteArray): ByteArray
    @JvmStatic external fun process_delivery_batch_export(request: ByteArray): ByteArray
    @JvmStatic external fun outbox_list_export(request: ByteArray): ByteArray
    @JvmStatic external fun outbox_ack_export(request: ByteArray): ByteArray
    @JvmStatic external fun outbox_fail_export(request: ByteArray): ByteArray
    @JvmStatic external fun outbox_page_export(request: ByteArray): ByteArray
    @JvmStatic external fun journal_load_export(request: ByteArray): ByteArray
    @JvmStatic external fun journal_save_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_begin_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_confirm_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_status_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_prepare_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_part_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_finish_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_disable_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_slots_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_begin_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_chunk_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_finish_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_identity_export(request: ByteArray): ByteArray
    @JvmStatic external fun backup_restore_account_export(request: ByteArray): ByteArray
    @JvmStatic external fun presentation_load_export(request: ByteArray): ByteArray
    @JvmStatic external fun presentation_save_export(request: ByteArray): ByteArray
    @JvmStatic external fun attachment_prepare_export(request: ByteArray): ByteArray
    @JvmStatic external fun attachment_seal_chunk_export(request: ByteArray): ByteArray
    @JvmStatic external fun attachment_open_chunk_export(request: ByteArray): ByteArray
    @JvmStatic external fun expiry_purge_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_timer_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_timer_state_export(request: ByteArray): ByteArray
    @JvmStatic external fun send_view_once_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_send_view_once_export(request: ByteArray): ByteArray
    @JvmStatic external fun open_view_once_export(request: ByteArray): ByteArray
    @JvmStatic external fun group_open_view_once_export(request: ByteArray): ByteArray
    @JvmStatic external fun safety_code_export(request: ByteArray): ByteArray
    @JvmStatic external fun safety_code_check_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_status_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_refresh_keys_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_quote_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_issue_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_postage_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_postage_quote_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_retention_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_signup_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_register_at_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_spend_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_settle_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_inbox_policy_export(request: ByteArray): ByteArray
    @JvmStatic external fun credits_group_handover_export(request: ByteArray): ByteArray
}
