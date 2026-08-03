package expo.modules.meshmessenger

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import mesh.MeshLibrary

class MeshMessengerModule : Module() {
    private val lock = Any()
    private var started = false

    override fun definition() = ModuleDefinition {
        Name("MeshMessenger")

        AsyncFunction("invoke") { symbol: String, request: ByteArray ->
            synchronized(lock) {
                startIfNeeded()
                when (symbol) {
                    "mesh_messenger_initialize" -> MeshLibrary.initialize(request)
                    "mesh_messenger_validate_outer" -> MeshLibrary.validate_outer(request)
                    "mesh_messenger_store_envelope" -> MeshLibrary.persist_envelope(request)
                    "mesh_messenger_create_account" -> MeshLibrary.create_account_export(request)
                    "mesh_messenger_load_profile" -> MeshLibrary.load_profile_export(request)
                    "mesh_messenger_replenish_prekeys" -> MeshLibrary.replenish_prekeys_export(request)
                    "mesh_messenger_create_link_request" -> MeshLibrary.create_link_request_export(request)
                    "mesh_messenger_device_link_sas" -> MeshLibrary.device_link_sas_export(request)
                    "mesh_messenger_authorize_device_link" -> MeshLibrary.authorize_device_link_export(request)
                    "mesh_messenger_authorize_device_link_for_set" -> MeshLibrary.authorize_device_link_for_set_export(request)
                    "mesh_messenger_complete_device_link" -> MeshLibrary.complete_device_link_export(request)
                    "mesh_messenger_inspect_device_set" -> MeshLibrary.inspect_device_set_export(request)
                    "mesh_messenger_create_device_revocation" -> MeshLibrary.create_device_revocation_export(request)
                    "mesh_messenger_start_conversation" -> MeshLibrary.start_conversation_export(request)
                    "mesh_messenger_receive_initial" -> MeshLibrary.receive_initial_export(request)
                    "mesh_messenger_send_fanout" -> MeshLibrary.send_fanout_export(request)
                    "mesh_messenger_send_message" -> MeshLibrary.send_message_export(request)
                    "mesh_messenger_receive_message" -> MeshLibrary.receive_message_export(request)
                    "mesh_messenger_update_conversation" -> MeshLibrary.update_conversation_export(request)
                    "mesh_messenger_list_conversations" -> MeshLibrary.list_conversations_export(request)
                    "mesh_messenger_load_history" -> MeshLibrary.load_history_export(request)
                    "mesh_messenger_safety_number" -> MeshLibrary.safety_number_export(request)
                    "mesh_messenger_import_contact" -> MeshLibrary.import_contact_export(request)
                    "mesh_messenger_directory_entry" -> MeshLibrary.directory_entry_export(request)
                    "mesh_messenger_directory_lookup" -> MeshLibrary.directory_lookup_export(request)
                    "mesh_messenger_transparency_lookup" -> MeshLibrary.transparency_lookup_export(request)
                    "mesh_messenger_verify_transparency" -> MeshLibrary.verify_transparency_export(request)
                    "mesh_messenger_privacy_submission" -> MeshLibrary.privacy_submission_export(request)
                    "mesh_messenger_mailbox_fetch" -> MeshLibrary.mailbox_fetch_export(request)
                    "mesh_messenger_process_delivery_batch" -> MeshLibrary.process_delivery_batch_export(request)
                    "mesh_messenger_outbox_list" -> MeshLibrary.outbox_list_export(request)
                    "mesh_messenger_outbox_ack" -> MeshLibrary.outbox_ack_export(request)
                    else -> throw IllegalArgumentException("unknown_export")
                }
            }
        }

        OnDestroy {
            synchronized(lock) {
                if (started) {
                    MeshMessengerHost.unregisterSecureStore()
                    MeshLibrary.shutdownNative()
                    started = false
                }
            }
        }
    }

    private fun startIfNeeded() {
        if (started) return
        val context = appContext.reactContext
            ?: throw IllegalStateException("React context is unavailable")
        MeshMessengerSecureStore.install(context)
        MeshLibrary.ensureInitialized()
        val status = MeshMessengerHost.registerSecureStore()
        check(status == 0) { "Secure-store registration failed (status=$status)" }
        started = true
    }
}

internal object MeshMessengerHost {
    @JvmStatic external fun registerSecureStore(): Int
    @JvmStatic external fun unregisterSecureStore()
}
