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
    @JvmStatic external fun create_link_request_export(request: ByteArray): ByteArray
    @JvmStatic external fun device_link_sas_export(request: ByteArray): ByteArray
    @JvmStatic external fun authorize_device_link_export(request: ByteArray): ByteArray
    @JvmStatic external fun authorize_device_link_for_set_export(request: ByteArray): ByteArray
    @JvmStatic external fun complete_device_link_export(request: ByteArray): ByteArray
    @JvmStatic external fun inspect_device_set_export(request: ByteArray): ByteArray
    @JvmStatic external fun create_device_revocation_export(request: ByteArray): ByteArray
    @JvmStatic external fun start_conversation_export(request: ByteArray): ByteArray
    @JvmStatic external fun receive_initial_export(request: ByteArray): ByteArray
    @JvmStatic external fun send_fanout_export(request: ByteArray): ByteArray
    @JvmStatic external fun send_message_export(request: ByteArray): ByteArray
    @JvmStatic external fun receive_message_export(request: ByteArray): ByteArray
    @JvmStatic external fun update_conversation_export(request: ByteArray): ByteArray
    @JvmStatic external fun list_conversations_export(request: ByteArray): ByteArray
    @JvmStatic external fun load_history_export(request: ByteArray): ByteArray
    @JvmStatic external fun safety_number_export(request: ByteArray): ByteArray
    @JvmStatic external fun import_contact_export(request: ByteArray): ByteArray
    @JvmStatic external fun directory_entry_export(request: ByteArray): ByteArray
    @JvmStatic external fun directory_lookup_export(request: ByteArray): ByteArray
    @JvmStatic external fun mailbox_fetch_export(request: ByteArray): ByteArray
    @JvmStatic external fun process_delivery_batch_export(request: ByteArray): ByteArray
}
