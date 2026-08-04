package expo.modules.meshmessenger

import com.google.firebase.messaging.FirebaseMessaging
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.notifications.service.delegates.FirebaseMessagingDelegate.Companion.addTokenListener
import expo.modules.notifications.service.delegates.FirebaseMessagingDelegate.Companion.removeTokenListener
import expo.modules.notifications.tokens.interfaces.FirebaseTokenListener
import java.nio.ByteBuffer
import mesh.MeshLibrary

class MeshMessengerModule : Module(), FirebaseTokenListener {
    private val lock = Any()
    private val pushLock = Any()
    private var started = false
    private var pushEnabled = false

    override fun definition() = ModuleDefinition {
        Name("MeshMessenger")

        Events("onPushRegistrationChanged")

        OnCreate {
            addTokenListener(this@MeshMessengerModule)
        }

        AsyncFunction("primePushToken") { promise: Promise ->
            val instance = firebaseMessaging(promise) ?: return@AsyncFunction
            synchronized(pushLock) { pushEnabled = true }
            instance.isAutoInitEnabled = true
            instance.token.addOnCompleteListener { task ->
                if (!task.isSuccessful) {
                    promise.reject(
                        "E_PUSH_REGISTRATION_FAILED",
                        "Fetching the FCM token failed.",
                        task.exception,
                    )
                    return@addOnCompleteListener
                }
                val token = task.result
                if (token == null || !cachePushToken(token)) {
                    promise.reject(
                        "E_PUSH_REGISTRATION_FAILED",
                        "FCM returned invalid registration material.",
                        null,
                    )
                    return@addOnCompleteListener
                }
                promise.resolve(null)
            }
        }

        AsyncFunction("clearPushToken") { promise: Promise ->
            synchronized(pushLock) {
                pushEnabled = false
                MeshMessengerPushMaterial.clear()
            }
            val instance = firebaseMessaging(promise) ?: return@AsyncFunction
            instance.isAutoInitEnabled = false
            instance.deleteToken().addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    promise.resolve(null)
                } else {
                    promise.reject(
                        "E_PUSH_UNREGISTRATION_FAILED",
                        "Deleting the FCM token failed.",
                        task.exception,
                    )
                }
            }
        }

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
                    "mesh_messenger_reconcile_prekeys" -> MeshLibrary.reconcile_prekeys_export(request)
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
                    "mesh_messenger_push_bind_prepare" -> MeshLibrary.push_bind_prepare_export(request)
                    "mesh_messenger_push_unbind_prepare" -> MeshLibrary.push_unbind_prepare_export(request)
                    "mesh_messenger_push_update_commit" -> MeshLibrary.push_update_commit_export(request)
                    "mesh_messenger_push_status" -> MeshLibrary.push_status_export(request)
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
            removeTokenListener(this@MeshMessengerModule)
            synchronized(pushLock) {
                pushEnabled = false
                MeshMessengerPushMaterial.clear()
            }
            synchronized(lock) {
                if (started) {
                    MeshMessengerHost.unregisterHostCallbacks()
                    MeshLibrary.shutdownNative()
                    started = false
                }
            }
        }
    }

    override fun onNewToken(token: String) {
        if (cachePushToken(token)) {
            runCatching { sendEvent("onPushRegistrationChanged", emptyMap<String, Any?>()) }
        }
    }

    private fun startIfNeeded() {
        if (started) return
        val context = appContext.reactContext
            ?: throw IllegalStateException("React context is unavailable")
        MeshMessengerSecureStore.install(context)
        MeshLibrary.ensureInitialized()
        val status = MeshMessengerHost.registerHostCallbacks()
        check(status == 0) { "Host callback registration failed (status=$status)" }
        started = true
    }

    private fun cachePushToken(token: String): Boolean = synchronized(pushLock) {
        if (!pushEnabled) return@synchronized false
        val applicationID = appContext.reactContext?.applicationContext?.packageName
            ?: return@synchronized false
        MeshMessengerPushMaterial.cache(applicationID, token)
    }

    private fun firebaseMessaging(promise: Promise): FirebaseMessaging? = try {
        FirebaseMessaging.getInstance()
    } catch (error: IllegalStateException) {
        promise.reject(
            "E_PUSH_REGISTRATION_FAILED",
            "Firebase Messaging is not configured.",
            error,
        )
        null
    }
}

internal object MeshMessengerHost {
    @JvmStatic external fun registerHostCallbacks(): Int
    @JvmStatic external fun unregisterHostCallbacks()
}

internal object MeshMessengerPushMaterial {
    private const val MAX_APPLICATION_ID_BYTES = 255
    private const val MAX_TOKEN_BYTES = 4096
    private const val MAX_FRAME_BYTES = 4362
    private var frame: ByteArray? = null

    @Synchronized
    fun cache(applicationID: String, token: String): Boolean {
        val applicationIDBytes = applicationID.toByteArray(Charsets.UTF_8)
        val tokenBytes = token.toByteArray(Charsets.UTF_8)
        if (applicationIDBytes.size !in 1..MAX_APPLICATION_ID_BYTES ||
            tokenBytes.size !in 1..MAX_TOKEN_BYTES
        ) {
            tokenBytes.fill(0)
            return false
        }
        val size = 11 + applicationIDBytes.size + tokenBytes.size
        if (size > MAX_FRAME_BYTES) {
            tokenBytes.fill(0)
            return false
        }
        val replacement = ByteBuffer.allocate(size)
            .put(1.toByte())
            .put(2.toByte())
            .put(0.toByte())
            .putInt(applicationIDBytes.size)
            .put(applicationIDBytes)
            .putInt(tokenBytes.size)
            .put(tokenBytes)
            .array()
        tokenBytes.fill(0)
        frame?.fill(0)
        frame = replacement
        return true
    }

    @JvmStatic
    @Synchronized
    fun consume(): ByteArray? = frame.also { frame = null }

    @Synchronized
    fun clear() {
        frame?.fill(0)
        frame = null
    }
}
