package expo.modules.meshmessenger

import com.google.firebase.messaging.FirebaseMessaging
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.bridge.ReactContext
import expo.modules.kotlin.Promise
import expo.modules.kotlin.functions.Coroutine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
    @Volatile private var destroyed = false
    @Volatile private var registrationReady = false
    private var didRegister = false
    private var registeredContext = java.lang.ref.WeakReference<expo.modules.kotlin.AppContext>(null)
    private var removeProtectedBinding: (() -> Unit)? = null
    @Volatile private var runtimeOwner: RuntimeOwner? = null
    private var removeRuntimeListener: (() -> Unit)? = null
    private class RuntimeOwner(
        val nativeContext: expo.modules.kotlin.AppContext,
        val reactContext: ReactContext,
        val application: ReactApplication,
        val host: ReactHost,
    ) { @Volatile var retired = false }
    private var pushEpoch: String? = null
    private var removeAppLockObserver: (() -> Unit)? = null
    private var removeInboxObserver: (() -> Unit)? = null
    private var removeRevokeObserver: (() -> Unit)? = null
    private companion object {
        // A React reload cannot overlap old token deletion with a new module's registration.
        val pushOperations = MeshMessengerPushSerialQueue()
        val moduleLifecycle = Any()
        @Volatile var currentModule = java.lang.ref.WeakReference<MeshMessengerModule>(null)
    }

    override fun definition() = ModuleDefinition {
        Name("MeshMessenger")

        Events("onPushRegistrationChanged", "onAppLockChanged", "onAppLockInboxOpen")

        OnCreate { synchronized(moduleLifecycle) {
            check(!destroyed) { "module_unavailable" }
            val nativeContext = appContext
            check(nativeContext.registry.getModule("MeshMessenger") === this@MeshMessengerModule) { "module_unavailable" }
            // A registry in a retired React runtime cannot establish process ownership.
            val nativeOwner = captureRuntimeOwner(nativeContext)
            if (currentModule.get() === this@MeshMessengerModule) {
                check(isCurrentModule() && registeredContext.get() === nativeContext) { "module_unavailable" }
                return@synchronized
            }
            // A delayed create callback is never a new native registration.
            check(!didRegister) { "module_unavailable" }
            didRegister = true
            val previous = currentModule.get()
            currentModule = java.lang.ref.WeakReference(null)
            if (previous != null) {
                previous.registrationReady = false
                previous.removeRuntimeOwner()
                previous.removeObservers()
                synchronized(previous.pushLock) { previous.pushEnabled = false; previous.pushEpoch = null }
                MeshMessengerPushMaterial.clear()
                MeshMessengerAppLock.invalidate("module_replaced", false)
            }
            val application = requireNotNull(appContext.reactContext).applicationContext as android.app.Application
            MeshMessengerAppLock.install(application)
            registeredContext = java.lang.ref.WeakReference(nativeContext)
            runtimeOwner = nativeOwner
            currentModule = java.lang.ref.WeakReference(this@MeshMessengerModule)
            try {
            val beforeDestroy: () -> Unit = { synchronized(moduleLifecycle) {
                // Already queued callbacks from a retired owner cannot revoke its successor.
                if (currentModule.get() === this@MeshMessengerModule && runtimeOwner === nativeOwner &&
                    registeredContext.get() === nativeContext && !destroyed && !nativeOwner.retired) {
                    nativeOwner.retired = true
                    registrationReady = false
                    MeshMessengerAppLock.invalidate("react_runtime_destroyed", false)
                    synchronized(pushLock) { pushEnabled = false; pushEpoch = null }
                    MeshMessengerPushMaterial.clear()
                }
            } }
            removeRuntimeListener = { nativeOwner.host.removeBeforeDestroyListener(beforeDestroy) }
            nativeOwner.host.addBeforeDestroyListener(beforeDestroy)
            check(runtimeMatches(nativeOwner)) { "module_unavailable" }
            removeProtectedBinding = MeshMessengerProtectedFiles.bind({ expected ->
                moduleScoped(expected) { synchronized(lock) {
                    MeshMessengerAppLock.requireEpoch(expected); startIfNeeded()
                    MeshLibrary.load_profile_export(java.io.File(appContext.persistentFilesDirectory,"morse.db").path.toByteArray(Charsets.UTF_8))
                } }
            }, appContext.persistentFilesDirectory)
            removeAppLockObserver = MeshMessengerAppLock.observe { state -> if (isCurrentModule()) runCatching { sendEvent("onAppLockChanged",state) } }
            removeInboxObserver = MeshMessengerAppLock.observeInbox { if (isCurrentModule()) runCatching { sendEvent("onAppLockInboxOpen",emptyMap<String,Any>()) } }
            removeRevokeObserver = MeshMessengerAppLock.onRevoke { synchronized(pushLock) { if (isCurrentModule()) { pushEpoch = null; pushEnabled = false; MeshMessengerPushMaterial.clear() } } }
            MeshMessengerLockedNotifications.consumeIntent(appContext.currentActivity?.intent)
            addTokenListener(this@MeshMessengerModule)
            MeshMessengerScreenSecurity.protect(appContext.currentActivity)
            MeshMessengerWalletStore.setActivity(appContext.currentActivity)
            check(runtimeMatches(nativeOwner)) { "module_unavailable" }
            registrationReady = true
            } catch (error: Throwable) {
                registrationReady = false
                currentModule = java.lang.ref.WeakReference(null)
                removeRuntimeOwner()
                removeObservers()
                removeProtectedBinding?.invoke(); removeProtectedBinding = null
                registeredContext.clear()
                removeTokenListener(this@MeshMessengerModule)
                MeshMessengerAppLock.invalidate("module_setup_failed", false)
                throw error
            }
        } }

        OnActivityEntersForeground { synchronized(moduleLifecycle) {
            if (isCurrentModule()) {
                MeshMessengerScreenSecurity.protect(appContext.currentActivity)
                MeshMessengerWalletStore.setActivity(appContext.currentActivity)
            }
        } }

        OnActivityEntersBackground { synchronized(moduleLifecycle) { if (isCurrentModule()) MeshMessengerWalletStore.clearActivity() } }
        OnActivityDestroys { synchronized(moduleLifecycle) { if (isCurrentModule()) MeshMessengerWalletStore.clearActivity() } }

        AsyncFunction("primePushToken") { _: ByteArray -> rejectUnscopedUnit() }
        AsyncFunction("clearPushToken") { _: ByteArray -> rejectUnscopedUnit() }
        AsyncFunction("wallet") { _: Int, _: ByteArray -> rejectUnscopedBytes() }
        AsyncFunction("openCreditPayment") { _: ByteArray -> rejectUnscopedUnit() }
        AsyncFunction("invoke") { _: String, _: ByteArray -> rejectUnscopedBytes() }
        AsyncFunction("getAppLockState") { moduleStateCall { MeshMessengerAppLock.state() } }
        AsyncFunction("authenticateAppLock") Coroutine { expected: String -> withContext(Dispatchers.IO) { moduleCall { requireModuleActivity(); MeshMessengerAppLock.authenticate(expected) } } }
        AsyncFunction("setAppLockEnabled") Coroutine { enabled: Boolean, expected: String -> withContext(Dispatchers.IO) { moduleCall { requireModuleActivity(); MeshMessengerAppLock.authenticate(expected,enabled) } } }
        AsyncFunction("cancelAppLockAuthentication") { requestId: String -> moduleStateCall { MeshMessengerAppLock.cancel(requestId) } }
        AsyncFunction("lockApp") { moduleStateCall { MeshMessengerAppLock.lock() } }
        Function("checkAppLockScope") { expected: String -> moduleStateCall { moduleScoped(expected) { Unit } } }
        Function("consumeAppLockInboxIntent") { expected: String -> moduleStateCall { moduleScoped(expected) { MeshMessengerAppLock.consumeInbox(expected) } } }
        Function("consumeAppLockNotificationIntent") { expected: String ->
            moduleStateCall { moduleScoped(expected) { MeshMessengerAppLock.consumeNotificationIntent(expected,requireModuleActivity()) } }
        }
        AsyncFunction("activateAppLockScope") Coroutine { expected: String -> withContext(Dispatchers.Main) { moduleStateCall { requireModuleActivity(); MeshMessengerAppLock.activate(expected) } } }
        AsyncFunction("protectedFile") Coroutine { operation: String, frame: String, bytes: ByteArray, expected: String ->
            withContext(Dispatchers.IO) { moduleScoped(expected) { MeshMessengerProtectedFiles.dispatch(operation,frame,bytes,expected) } }
        }
        AsyncFunction("publishMessageNotice") Coroutine { frame: String, expected: String -> withContext(Dispatchers.IO) { moduleScoped(expected) { MeshMessengerLockedNotifications.publish(frame,expected) } } }
        AsyncFunction("copyProtectedText") Coroutine { text: String, expected: String ->
            require(text.toByteArray(Charsets.UTF_8).size <= 131_072) { "invalid_clipboard_text" }
            withContext(Dispatchers.Main) { moduleStateCall { moduleScoped(expected) { requireModuleActivity(); MeshMessengerAppLock.copyProtectedText(text,expected) } } }
        }
        AsyncFunction("publishEncryptedWakeup") { moduleCall { MeshMessengerLockedNotifications.genericWakeup() } }
        Function("readLegacyPreference") { profile: ByteArray, kind: String, expected: String -> moduleScoped(expected) { MeshMessengerProtectedFiles.readLegacy(profile,kind,expected) } }
        Function("removeLegacyPreference") { profile: ByteArray, kind: String, expected: String -> moduleScoped(expected) { MeshMessengerProtectedFiles.removeLegacy(profile,kind,expected); Unit } }
        Function("forgetLegacyPreferences") { account: String, expected: String -> moduleScoped(expected) { MeshMessengerProtectedFiles.forgetLegacy(account,expected); Unit } }
        OnNewIntent { intent -> synchronized(moduleLifecycle) { if (isCurrentModule()) MeshMessengerLockedNotifications.consumeIntent(intent) } }
        OnActivityResult { activity, payload -> synchronized(moduleLifecycle) {
            if (isCurrentModule() && appContext.currentActivity === activity &&
                !MeshMessengerAppLock.activityResult(activity,payload.requestCode,payload.resultCode,payload.data))
                MeshMessengerProtectedFiles.activityResult(activity,payload.requestCode,payload.resultCode,payload.data)
        } }
        AsyncFunction("primePushTokenScoped") { request: ByteArray, expected: String, promise: Promise ->
            val action = request.copyOf()
            pushOperations.enqueue { finished ->
                try {
                    withPushAction(action, 2, expected) {
                        val instance = FirebaseMessaging.getInstance()
                        synchronized(pushLock) { MeshMessengerAppLock.requireEpoch(expected); pushEnabled = true; pushEpoch = expected }
                        instance.isAutoInitEnabled = true
                        instance.token.addOnCompleteListener { task ->
                            try {
                                check(task.isSuccessful) { "FCM token registration failed" }
                                withPushAction(action, 2, expected) {
                                    val token = task.result
                                    check(token != null && cachePushToken(token, expected)) { "Invalid FCM registration material" }
                                }
                                MeshMessengerAppLock.requireEpoch(expected)
                                promise.resolve(null)
                            } catch (error: Exception) {
                                promise.reject("E_PUSH_REGISTRATION_FAILED", error.message, error)
                            } finally { finished() }
                        }
                    }
                } catch (error: Exception) {
                    promise.reject("E_PUSH_REGISTRATION_FAILED", error.message, error)
                    finished()
                }
            }
        }

        AsyncFunction("clearPushTokenScoped") { request: ByteArray, expected: String, promise: Promise ->
            val action = request.copyOf()
            pushOperations.enqueue { finished ->
                try {
                    withPushAction(action, 5, expected) {
                        val instance = FirebaseMessaging.getInstance()
                        synchronized(pushLock) {
                            pushEnabled = false
                            MeshMessengerPushMaterial.clear()
                        }
                        instance.isAutoInitEnabled = false
                        instance.deleteToken().addOnCompleteListener { task ->
                            try {
                                check(task.isSuccessful) { "FCM token deletion failed" }
                                withPushAction(action, 5, expected) { }
                                MeshMessengerAppLock.requireEpoch(expected)
                                promise.resolve(null)
                            } catch (error: Exception) {
                                promise.reject("E_PUSH_UNREGISTRATION_FAILED", error.message, error)
                            } finally { finished() }
                        }
                    }
                } catch (error: Exception) {
                    promise.reject("E_PUSH_UNREGISTRATION_FAILED", error.message, error)
                    finished()
                }
            }
        }

        AsyncFunction("walletScoped") Coroutine { operation: Int, request: ByteArray, expected: String ->
            withContext(Dispatchers.IO) {
            moduleScoped(expected) {
            synchronized(lock) {
                MeshMessengerAppLock.requireEpoch(expected)
                startIfNeeded()
                val context = appContext.reactContext ?: error("React context is unavailable")
                // Wallet configuration is optional: free messaging startup
                // must succeed when purpose or mint pins are absent.
                if (operation != 7 || !request.contentEquals(byteArrayOf(0))) {
                    MeshMessengerWalletStore.install(context)
                    MeshMessengerWalletStore.setActivity(appContext.currentActivity)
                }
            }
            walletInvoke(operation, request)
            }
            }
        }

        AsyncFunction("openCreditPaymentScoped") Coroutine { request: ByteArray, expected: String ->
            val address = withContext(Dispatchers.IO) {
                moduleScoped(expected) {
                val fields = walletFields(request, 2)
                require(fields[0].contentEquals(java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8)) && fields[1].size == 32) { "invalid_database_path" }
                val result = synchronized(lock) {
                    MeshMessengerAppLock.requireEpoch(expected)
                    startIfNeeded()
                    MeshLibrary.credit_payment_handoff_export(request)
                }
                val text = result.toString(Charsets.UTF_8)
                require((text.startsWith("solana:") && result.size <= 4096 || Regex("lightning:[A-Za-z0-9]{1,7089}").matches(text)) && text.none { it.code < 32 || it.code == 127 }) { "invalid_payment_url" }
                text
                }
            }
            withContext(Dispatchers.Main) { moduleStateCall {
                val activity = requireModuleActivity()
                MeshMessengerAppLock.publication(expected)
                try { activity.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(address))) }
                catch (_: android.content.ActivityNotFoundException) { error("external_wallet_unavailable") }
                MeshMessengerAppLock.requireEpoch(expected)
            } }
        }

        AsyncFunction("invokeScoped") { symbol: String, request: ByteArray, expected: String ->
            moduleScoped(expected) {
                if (!symbol.startsWith("mesh_messenger_backup_")) invokeCore(symbol,request)
                else {
                    val owner = requireModuleActivity()
                    val result = invokeCore(symbol,request)
                    try { check(requireModuleActivity() === owner) { "scoped_client_required" } }
                    catch (error: Throwable) { result.fill(0); throw error }
                    result
                }
            }
        }

        OnDestroy { synchronized(moduleLifecycle) {
            if (destroyed) return@synchronized
            destroyed = true
            registrationReady = false
            val ownsRegistration = currentModule.get() === this@MeshMessengerModule
            if (ownsRegistration) currentModule = java.lang.ref.WeakReference(null)
            removeRuntimeOwner()
            removeObservers()
            removeProtectedBinding?.invoke(); removeProtectedBinding = null
            registeredContext.clear()
            removeTokenListener(this@MeshMessengerModule)
            synchronized(pushLock) { pushEnabled = false; pushEpoch = null }
            if (ownsRegistration) {
                MeshMessengerPushMaterial.clear()
                MeshMessengerAppLock.invalidate("module_destroyed",false)
                MeshMessengerWalletStore.clearActivity()
            }
            // Only the native registration owner may retire shared callbacks.
            // The process-wide Mesh runtime itself survives React reloads.
            synchronized(lock) {
                if (started && ownsRegistration) MeshMessengerHost.unregisterHostCallbacks()
                started = false
            }
        } }
    }

    private fun removeObservers() {
        removeAppLockObserver?.invoke(); removeAppLockObserver = null
        removeInboxObserver?.invoke(); removeInboxObserver = null
        removeRevokeObserver?.invoke(); removeRevokeObserver = null
    }

    private fun captureRuntimeOwner(nativeContext: expo.modules.kotlin.AppContext): RuntimeOwner {
        val react = nativeContext.reactContext as? ReactContext ?: error("module_unavailable")
        val application = react.applicationContext as? ReactApplication ?: error("module_unavailable")
        val host = application.reactHost ?: error("module_unavailable")
        return RuntimeOwner(nativeContext, react, application, host).also {
            check(runtimeMatches(it)) { "module_unavailable" }
        }
    }

    private fun runtimeMatches(owner: RuntimeOwner): Boolean = runCatching {
        !owner.retired && owner.nativeContext === appContext &&
            owner.nativeContext.registry.getModule("MeshMessenger") === this &&
            owner.nativeContext.reactContext === owner.reactContext &&
            owner.reactContext.applicationContext === owner.application &&
            owner.application.reactHost === owner.host && owner.host.currentReactContext === owner.reactContext
    }.getOrDefault(false)

    private fun removeRuntimeOwner() {
        runtimeOwner?.retired = true
        runtimeOwner = null
        val remove = removeRuntimeListener
        removeRuntimeListener = null
        // A detached callback is already harmless even if native host cleanup fails.
        runCatching { remove?.invoke() }
    }

    private fun isCurrentModule(): Boolean {
        val registered = registeredContext.get() ?: return false
        val owner = runtimeOwner ?: return false
        return registrationReady && !destroyed && currentModule.get() === this && registered === appContext &&
            registered === owner.nativeContext && runtimeMatches(owner)
    }

    private fun requireModule() { check(isCurrentModule()) { "module_unavailable" } }

    private fun requireModuleActivity(): android.app.Activity {
        requireModule()
        return requireNotNull(appContext.currentActivity) { "app_lock_unavailable" }.also {
            check(it === MeshMessengerAppLock.currentActivity()) { "app_lock_unavailable" }
        }
    }

    private fun <T> moduleCall(body: () -> T): T {
        requireModule()
        val value = body()
        try { requireModule() }
        catch (error: Throwable) { if (value is ByteArray) value.fill(0); throw error }
        return value
    }

    private fun <T> moduleStateCall(body: () -> T): T = synchronized(moduleLifecycle) { moduleCall(body) }

    private fun <T> moduleScoped(expected: String, body: () -> T): T =
        moduleCall { MeshMessengerAppLock.scoped(expected, body) }

    private fun rejectUnscopedBytes(): ByteArray = error("scoped_client_required")
    private fun rejectUnscopedUnit(): Unit = error("scoped_client_required")

    private fun invokeCore(symbol: String, request: ByteArray): ByteArray = run {
            if (symbol.startsWith("mesh_messenger_backup_")) {
                MeshMessengerBackupRequest.validate(symbol, request,
                    java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8))
            }
            if (MeshMessengerCreditRequest.requiresValidation(symbol)) {
                MeshMessengerCreditRequest.validate(symbol, request,
                    java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8))
            }

            if (symbol.startsWith("mesh_messenger_mailbox_stream_") || symbol in listOf("mesh_messenger_mailbox_synchronize", "mesh_messenger_directory_register", "mesh_messenger_prekeys_synchronize")) {
                val path = if (symbol.endsWith("_open") || symbol.endsWith("_synchronize") || symbol == "mesh_messenger_directory_register") request else walletFields(request, 2)[0]
                require(path.contentEquals(java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8))) { "invalid_database_path" }
            }
            if (symbol.startsWith("mesh_messenger_bounty_transfer_")) {
                require(symbol in listOf("mesh_messenger_bounty_transfer_status", "mesh_messenger_bounty_transfer_recover", "mesh_messenger_bounty_transfer_cancel")) { "private_native_export" }
                val path = if (symbol.endsWith("_status")) request else walletFields(request,2)[0]
                require(path.contentEquals(java.io.File(appContext.persistentFilesDirectory,"morse.db").path.toByteArray(Charsets.UTF_8))) { "invalid_database_path" }
            }
            if (symbol in listOf("mesh_messenger_transparency_fork", "mesh_messenger_fork_filing")) {
                val database = java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8)
                require(request.contentEquals(database)) { "invalid_database_path" }
                MeshMessengerBountyBridge.invokeProof(symbol, request, ::bountyMesh, ::bountySDK)
            } else synchronized(lock) {
                val expected = MeshMessengerAppLock.capturedCallEpoch()
                startIfNeeded()
                if (symbol in setOf("mesh_messenger_create_account","mesh_messenger_complete_device_link","mesh_messenger_account_delete","mesh_messenger_account_discard")) MeshMessengerAppLock.accountChanging()
                when (symbol) {
                    "mesh_messenger_backup_create" -> MeshLibrary.backup_create_export(request)
                    "mesh_messenger_backup_preview" -> MeshLibrary.backup_preview_export(request)
                    "mesh_messenger_backup_import" -> MeshLibrary.backup_import_export(request)
                    "mesh_messenger_backup_list" -> MeshLibrary.backup_list_export(request)
                    "mesh_messenger_backup_remove" -> MeshLibrary.backup_remove_export(request)
                    "mesh_messenger_backup_overview" -> MeshLibrary.backup_overview_export(request)
                    "mesh_messenger_backup_page" -> MeshLibrary.backup_page_export(request)
                    "mesh_messenger_backup_pending_state" -> MeshLibrary.backup_pending_state_export(request)
                    "mesh_messenger_backup_pending_resume" -> MeshLibrary.backup_pending_resume_export(request)
                    "mesh_messenger_backup_pending_discard" -> MeshLibrary.backup_pending_discard_export(request)
                    "mesh_messenger_backup_pending_repair" -> MeshLibrary.backup_pending_repair_export(request)
                    "mesh_messenger_credit_discover_online" -> MeshLibrary.credit_discover_online_export(request)
                    "mesh_messenger_credit_purchase_continue" -> MeshLibrary.credit_purchase_continue_export(request)
                    "mesh_messenger_credit_action_continue" -> MeshLibrary.credit_action_continue_export(request)
                    "mesh_messenger_credit_signup_policy_online" -> MeshLibrary.credit_signup_policy_online_export(request)
                    "mesh_messenger_create_signup_draft" -> MeshLibrary.create_signup_draft_export(request)
                    "mesh_messenger_signup_draft_state" -> MeshLibrary.signup_draft_state_export(request)
                    "mesh_messenger_signup_draft_rename" -> MeshLibrary.signup_draft_rename_export(request)
                    "mesh_messenger_signup_draft_free" -> MeshLibrary.signup_draft_free_export(request)
                    "mesh_messenger_signup_draft_free_complete" -> MeshLibrary.signup_draft_free_complete_export(request)
                    "mesh_messenger_credit_signup_policy" -> MeshLibrary.credit_signup_policy_export(request)
                    "mesh_messenger_credit_signup_policy_view" -> MeshLibrary.credit_signup_policy_view_export(request)
                    "mesh_messenger_credit_signup" -> MeshLibrary.credit_signup_export(request)
                    "mesh_messenger_credit_signup_recover" -> MeshLibrary.credit_signup_recover_export(request)
                    "mesh_messenger_credit_action_recovery" -> MeshLibrary.credit_action_recovery_export(request)
                    "mesh_messenger_credit_postage_candidate" -> MeshLibrary.credit_postage_candidate_export(request)
                    "mesh_messenger_credit_postage_preview" -> MeshLibrary.credit_postage_preview_export(request)
                    "mesh_messenger_credit_postage_prepare" -> MeshLibrary.credit_postage_prepare_export(request)
                    "mesh_messenger_credit_postage_recover" -> MeshLibrary.credit_postage_recover_export(request)
                    "mesh_messenger_credit_attachment_grant" -> MeshLibrary.credit_attachment_grant_export(request)
                    "mesh_messenger_credit_attachment_upload" -> MeshLibrary.credit_attachment_upload_export(request)
                    "mesh_messenger_credit_attachment_complete" -> MeshLibrary.credit_attachment_complete_export(request)
                    "mesh_messenger_credit_attachment_delete" -> MeshLibrary.credit_attachment_delete_export(request)
                    "mesh_messenger_attachment_upload" -> MeshLibrary.attachment_upload_export(request)
                    "mesh_messenger_attachment_discard" -> MeshLibrary.attachment_discard_export(request)
                    "mesh_messenger_directory_resolve" -> MeshLibrary.directory_resolve_export(request)
                    "mesh_messenger_attachment_fetch_chunk" -> MeshLibrary.attachment_fetch_chunk_export(request)
                    "mesh_messenger_credit_postage_continue" -> MeshLibrary.credit_postage_continue_export(request)
                    "mesh_messenger_postage_policy_publish" -> MeshLibrary.postage_policy_publish_export(request)
                    "mesh_messenger_credit_postage_receipt" -> MeshLibrary.credit_postage_receipt_export(request)
                    "mesh_messenger_credit_postage_inventory" -> MeshLibrary.credit_postage_inventory_export(request)
                    "mesh_messenger_postage_policy_view" -> MeshLibrary.postage_policy_view_export(request)
                    "mesh_messenger_postage_policy_prepare" -> MeshLibrary.postage_policy_prepare_export(request)
                    "mesh_messenger_bounty_transfer_status" -> MeshLibrary.bounty_transfer_status_export(request)
                    "mesh_messenger_bounty_transfer_recover" -> MeshLibrary.bounty_transfer_recover_export(request)
                    "mesh_messenger_bounty_transfer_cancel" -> MeshLibrary.bounty_transfer_cancel_export(request)
                    "mesh_messenger_credit_attachment_prepare" -> MeshLibrary.credit_attachment_prepare_export(request)
                    "mesh_messenger_credit_attachment_recover" -> MeshLibrary.credit_attachment_recover_export(request)
                    "mesh_messenger_credit_attachment_receipt" -> MeshLibrary.credit_attachment_receipt_export(request)
                    "mesh_messenger_credit_attachment_part" -> MeshLibrary.credit_attachment_part_export(request)
                    "mesh_messenger_credit_attachment_part_recover" -> MeshLibrary.credit_attachment_part_recover_export(request)
                    "mesh_messenger_credit_attachment_preview" -> MeshLibrary.credit_attachment_preview_export(request)
                    "mesh_messenger_credit_attachments" -> MeshLibrary.credit_attachments_export(request)
                    "mesh_messenger_attachment_download_plan" -> MeshLibrary.attachment_download_plan_export(request)
                    "mesh_messenger_credit_attachment_prune" -> MeshLibrary.credit_attachment_prune_export(request)
                    "mesh_messenger_credit_wallet_quote" -> MeshLibrary.credit_wallet_quote_export(request)
                    "mesh_messenger_credit_payment_url" -> MeshLibrary.credit_payment_url_export(request)
                    "mesh_messenger_credit_payment_signature" -> MeshLibrary.credit_payment_signature_export(request)
                    "mesh_messenger_credit_retention" -> MeshLibrary.credit_retention_export(request)
                    "mesh_messenger_credit_retention_recover" -> MeshLibrary.credit_retention_recover_export(request)
                    "mesh_messenger_credit_receipt" -> MeshLibrary.credit_receipt_export(request)
                    "mesh_messenger_credit_discovery" -> MeshLibrary.credit_discovery_export(request)
                    "mesh_messenger_credit_admit" -> MeshLibrary.credit_admit_export(request)
                    "mesh_messenger_credit_prepare" -> MeshLibrary.credit_prepare_export(request)
                    "mesh_messenger_credit_prepare_again" -> MeshLibrary.credit_prepare_again_export(request)
                    "mesh_messenger_credit_quote" -> MeshLibrary.credit_quote_export(request)
                    "mesh_messenger_credit_payment" -> MeshLibrary.credit_payment_export(request)
                    "mesh_messenger_credit_finalize" -> MeshLibrary.credit_finalize_export(request)
                    "mesh_messenger_credit_recover" -> MeshLibrary.credit_recover_export(request)
                    "mesh_messenger_credit_purchases" -> MeshLibrary.credit_purchases_export(request)
                    "mesh_messenger_credit_balance" -> MeshLibrary.credit_balance_export(request)
                    "mesh_messenger_credit_reserve" -> MeshLibrary.credit_reserve_export(request)
                    "mesh_messenger_credit_reservation" -> MeshLibrary.credit_reservation_export(request)
                    "mesh_messenger_initialize" -> MeshLibrary.initialize(request)
                    "mesh_messenger_validate_outer" -> MeshLibrary.validate_outer(request)
                    "mesh_messenger_store_envelope" -> MeshLibrary.persist_envelope(request)
                    "mesh_messenger_create_account" -> MeshLibrary.create_account_export(request)
                    "mesh_messenger_journal_load_bound" -> MeshLibrary.journal_load_bound_export(request)
                    "mesh_messenger_journal_save_bound" -> MeshLibrary.journal_save_bound_export(request)
                    "mesh_messenger_presentation_load" -> MeshLibrary.presentation_load_export(request)
                    "mesh_messenger_presentation_save" -> MeshLibrary.presentation_save_export(request)
                    "mesh_messenger_load_profile" -> MeshLibrary.load_profile_export(request)
                    "mesh_messenger_create_link_request" -> MeshLibrary.create_link_request_export(request)
                    "mesh_messenger_device_link_sas" -> MeshLibrary.device_link_sas_export(request)
                    "mesh_messenger_authorize_device_link_for_set" -> MeshLibrary.authorize_device_link_for_set_export(request)
                    "mesh_messenger_complete_device_link" -> MeshLibrary.complete_device_link_export(request)
                    "mesh_messenger_inspect_device_set" -> MeshLibrary.inspect_device_set_export(request)
                    "mesh_messenger_receive_initial" -> MeshLibrary.receive_initial_export(request)
                    "mesh_messenger_group_invitation_complete" -> MeshLibrary.group_invitation_complete_export(request)
                    "mesh_messenger_group_invitation_decline" -> MeshLibrary.group_invitation_decline_export(request)
                    "mesh_messenger_group_invitations" -> MeshLibrary.group_invitations_export(request)
                    "mesh_messenger_group_forget" -> MeshLibrary.group_forget_export(request)
                    "mesh_messenger_group_key_package" -> MeshLibrary.group_key_package_export(request)
                    "mesh_messenger_group_create" -> MeshLibrary.group_create_export(request)
                    "mesh_messenger_group_add" -> MeshLibrary.group_add_export(request)
                    "mesh_messenger_group_remove" -> MeshLibrary.group_remove_export(request)
                    "mesh_messenger_group_send" -> MeshLibrary.group_send_export(request)
                    "mesh_messenger_group_receive" -> MeshLibrary.group_receive_export(request)
                    "mesh_messenger_group_list" -> MeshLibrary.group_list_export(request)
                    "mesh_messenger_group_inspect" -> MeshLibrary.group_inspect_export(request)
                    "mesh_messenger_group_history" -> MeshLibrary.group_history_export(request)
                    "mesh_messenger_group_policy" -> MeshLibrary.group_policy_export(request)
                    "mesh_messenger_receive_message" -> MeshLibrary.receive_message_export(request)
                    "mesh_messenger_update_conversation" -> MeshLibrary.update_conversation_export(request)
                    "mesh_messenger_push_flow_begin" -> MeshLibrary.push_flow_begin_export(request)
                    "mesh_messenger_account_delete" -> MeshLibrary.account_delete_export(request)
                    "mesh_messenger_account_discard" -> MeshLibrary.account_discard_export(request)
                    "mesh_messenger_account_capabilities" -> MeshLibrary.account_capabilities_export(request)
                    "mesh_messenger_devices_renew" -> MeshLibrary.devices_renew_export(request)
                    "mesh_messenger_device_revoke" -> MeshLibrary.device_revoke_export(request)
                    "mesh_messenger_push_flow_complete" -> MeshLibrary.push_flow_complete_export(request)
                    "mesh_messenger_push_flow_send" -> MeshLibrary.push_flow_send_export(request)
                    "mesh_messenger_fanout_send" -> MeshLibrary.fanout_send_export(request)
                    "mesh_messenger_outbox_drain" -> MeshLibrary.outbox_drain_export(request)
                    "mesh_messenger_push_status" -> MeshLibrary.push_status_export(request)
                    "mesh_messenger_list_conversations" -> MeshLibrary.list_conversations_export(request)
                    "mesh_messenger_load_history" -> MeshLibrary.load_history_export(request)
                    "mesh_messenger_safety_number" -> MeshLibrary.safety_number_export(request)
                    "mesh_messenger_import_contact" -> MeshLibrary.import_contact_export(request)
                    "mesh_messenger_directory_entry" -> MeshLibrary.directory_entry_export(request)
            "mesh_messenger_bounty_status" -> MeshLibrary.bounty_status_export(request)
                    "mesh_messenger_network_counter" -> {
                        require(request.contentEquals(java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8))) { "invalid_database_path" }
                        MeshLibrary.network_counter_export(request)
                    }
                    "mesh_messenger_anchor_check" -> MeshLibrary.anchor_check_export(request)
                    "mesh_messenger_directory_register" -> MeshLibrary.directory_register_export(request)
                    "mesh_messenger_prekeys_synchronize" -> MeshLibrary.prekeys_synchronize_export(request)
                    "mesh_messenger_mailbox_synchronize" -> MeshLibrary.mailbox_synchronize_export(request)
                    "mesh_messenger_mailbox_stream_open" -> MeshLibrary.mailbox_stream_open_export(request)
                    "mesh_messenger_mailbox_stream_poll" -> MeshLibrary.mailbox_stream_poll_export(request)
                    "mesh_messenger_mailbox_stream_close" -> MeshLibrary.mailbox_stream_close_export(request)
                    else -> throw IllegalArgumentException("unknown_export")
                }
            }
            }

    override fun onNewToken(token: String) {
        val expected = synchronized(pushLock) { pushEpoch } ?: return
        if (runCatching { cachePushToken(token, expected) }.getOrDefault(false)) {
            runCatching { sendEvent("onPushRegistrationChanged", emptyMap<String, Any?>()) }
        }
    }

    private fun walletFields(request: ByteArray, count: Int, maximum: Int = 8192): List<ByteArray> {
        require(request.size in 4..maximum) { "invalid_wallet_request" }
        val frame = ByteBuffer.wrap(request)
        require(frame.int == count) { "invalid_wallet_request" }
        val fields = (0 until count).map {
            require(frame.remaining() >= 4) { "invalid_wallet_request" }
            val size = frame.int
            require(size >= 0 && size <= frame.remaining()) { "invalid_wallet_request" }
            ByteArray(size).also { frame.get(it) }
        }
        require(!frame.hasRemaining()) { "invalid_wallet_request" }
        return fields
    }

    private fun walletPacket(fields: List<ByteArray>): ByteArray {
        val frame = ByteBuffer.allocate(4 + fields.sumOf { 4 + it.size }).putInt(fields.size)
        fields.forEach { frame.putInt(it.size).put(it) }
        return frame.array()
    }

    private fun bountyMesh(symbol: String, request: ByteArray): ByteArray = synchronized(lock) {
        MeshMessengerAppLock.capturedCallEpoch()
        startIfNeeded()
        when (symbol) {
            "mesh_messenger_bounty_transfer_prepare" -> MeshLibrary.bounty_transfer_prepare_export(request)
            "mesh_messenger_bounty_transfer_commit" -> MeshLibrary.bounty_transfer_commit_export(request)
            "mesh_messenger_bounty_transfer_submit" -> MeshLibrary.bounty_transfer_submit_export(request)
            "mesh_messenger_bounty_transfer_status" -> MeshLibrary.bounty_transfer_status_export(request)
            "mesh_messenger_bounty_transfer_recover" -> MeshLibrary.bounty_transfer_recover_export(request)
            "mesh_messenger_bounty_transfer_cancel" -> MeshLibrary.bounty_transfer_cancel_export(request)
            "mesh_messenger_bounty_status" -> MeshLibrary.bounty_status_export(request)
            "mesh_messenger_bounty_set_enabled" -> MeshLibrary.bounty_set_enabled_export(request)
            "mesh_messenger_bounty_commit" -> MeshLibrary.bounty_commit_export(request)
            "mesh_messenger_bounty_unavailable" -> MeshLibrary.bounty_unavailable_export(request)
            "mesh_messenger_transparency_fork" -> MeshLibrary.transparency_fork_export(request)
            "mesh_messenger_fork_filing" -> MeshLibrary.fork_filing_export(request)
            else -> error("invalid_bounty_request")
        }
    }

    private fun bountySDK(operation: Int, request: ByteArray): ByteArray {
        MeshMessengerAppLock.capturedCallEpoch()
        synchronized(lock) {
            MeshMessengerAppLock.capturedCallEpoch()
            startIfNeeded()
            val context = appContext.reactContext ?: error("React context is unavailable")
            MeshMessengerWalletStore.install(context)
            MeshMessengerWalletStore.setActivity(appContext.currentActivity)
        }
        return MeshMessengerWalletStore.invoke(operation, request)
    }

    private fun walletMesh(operation: Int, request: ByteArray): ByteArray = synchronized(lock) {
        MeshMessengerAppLock.capturedCallEpoch()
        startIfNeeded()
        when (operation) {
            0 -> MeshLibrary.credit_wallet_prepare_export(request)
            1 -> MeshLibrary.credit_wallet_commit_export(request)
            else -> MeshLibrary.credit_wallet_submit_export(request)
        }
    }

    private fun walletResult(response: ByteArray, id: ByteArray): ByteArray {
        val fields = walletFields(response, 4, 2048)
        require(fields[0].contentEquals(byteArrayOf(1, 77, 87, 82)) && fields[1].contentEquals(id) &&
            fields[2].size == 1 && fields[2][0].toInt() in 0..1 && fields[3].size == 64) { "invalid_wallet_response" }
        return response
    }

    private fun walletInvoke(operation: Int, request: ByteArray): ByteArray {
        if (operation == 7) {
            require(request.size == 1) { "invalid_bounty_request" }
            val database = java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8)
            return MeshMessengerBountyBridge.setEnabled(database, request[0].toInt(), ::bountyMesh, ::bountySDK)
        }
        if (operation == 8) {
            val database=java.io.File(appContext.persistentFilesDirectory,"morse.db").path.toByteArray(Charsets.UTF_8)
            return MeshMessengerBountyBridge.movement(request,database,::bountyMesh,::bountySDK)
        }
        if (operation == 5 || operation == 6) {
            val fields = walletFields(request, 2)
            require(fields[0].contentEquals(java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8)) && fields[1].size == 32) { "invalid_wallet_request" }
            if (operation == 5) {
                val payer = MeshMessengerWalletStore.invoke(2, byteArrayOf())
                require(payer.size == 32) { "invalid_wallet_address" }
                val plan = walletFields(walletMesh(0, walletPacket(listOf(fields[0], fields[1], payer))), 6, 2048)
                require(plan[0].contentEquals(byteArrayOf(1, 77, 87, 80)) && plan[1].contentEquals(fields[1]) &&
                    plan[2].size == 1 && plan[2][0].toInt() in 0..1 && plan[3].size == 224 && plan[4].size == 32 &&
                    (if (plan[2][0].toInt() == 0) plan[5].isEmpty() else plan[5].size == 64)) { "invalid_wallet_response" }
                if (plan[2][0].toInt() == 0) {
                    // Native confirmation runs without the Mesh lock held.
                    val wire = MeshMessengerWalletStore.invoke(3, plan[3] + plan[4])
                    walletResult(walletMesh(1, walletPacket(listOf(fields[0], fields[1], wire))), fields[1])
                }
            }
            return walletResult(walletMesh(2, request), fields[1])
        }
        require(operation in listOf(1, 2) && request.isEmpty()) { "invalid_wallet_request" }
        return MeshMessengerWalletStore.invoke(operation, byteArrayOf())
    }

    private fun startIfNeeded() {
        requireModule()
        if (started) return
        val context = appContext.reactContext
            ?: throw IllegalStateException("React context is unavailable")
        MeshMessengerSecureStore.install(context)
        MeshMessengerPushMaterial.install(context)
        MeshLibrary.ensureInitialized()
        val status = MeshMessengerHost.registerHostCallbacks()
        check(status == 0) { "Host callback registration failed (status=$status)" }
        started = true
    }

    private fun cachePushToken(token: String, expected: String): Boolean = synchronized(pushLock) {
        requireModule()
        MeshMessengerAppLock.requireEpoch(expected)
        if (!pushEnabled || pushEpoch != expected) return@synchronized false
        val applicationID = appContext.reactContext?.applicationContext?.packageName
            ?: return@synchronized false
        MeshMessengerPushMaterial.cache(applicationID, token)
    }

    private fun withPushAction(request: ByteArray, kind: Int, expected: String, work: () -> Unit) {
        moduleScoped(expected) { synchronized(lock) {
            MeshMessengerAppLock.requireEpoch(expected)
            check(!destroyed) { "Push module is unavailable" }
            val database = java.io.File(appContext.persistentFilesDirectory, "morse.db").path.toByteArray(Charsets.UTF_8)
            MeshMessengerCreditRequest.validate("mesh_messenger_push_flow_send", request, database)
            startIfNeeded()
            check(MeshLibrary.push_flow_validate_export(request).contentEquals(byteArrayOf(kind.toByte()))) { "Invalid platform push action" }
            work()
        } }
    }

}

internal object MeshMessengerHost {
    @JvmStatic external fun registerHostCallbacks(): Int
    @JvmStatic external fun unregisterHostCallbacks()
}

internal object MeshMessengerPushMaterial {
    private const val PROJECT_ID_METADATA = "app.morse.mesh.EXPO_PROJECT_ID"
    private const val BROKER_KEY_METADATA = "app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX"
    private const val SECURITY_CONFIG_METADATA = "app.morse.mesh.SECURITY_CONFIG"
    private const val NETWORK_CONFIG_METADATA = "app.morse.mesh.NETWORK_CONFIG"
    private const val OHTTP_CONFIG_METADATA = "app.morse.mesh.OHTTP_CONFIG"
    private const val CREDIT_PURPOSE_METADATA = "app.morse.mesh.CREDIT_PURPOSE"
    private const val CREDIT_MINT_METADATA = "app.morse.mesh.CREDIT_USDC_MINT_HEX"
    private const val MAX_APPLICATION_ID_BYTES = 255
    private const val MAX_TOKEN_BYTES = 4096
    private const val MAX_FRAME_BYTES = 4362
    private var frame: ByteArray? = null
    private var buildConfigFrame: ByteArray? = null
    private var securityConfigFrame: ByteArray? = null
    private var networkConfigFrame: ByteArray? = null
    private var ohttpConfigFrame: ByteArray? = null
    private var networkCounterConfigFrame: ByteArray? = null
    private var lightningNetworkFrame: ByteArray? = null
    private var issuerTLSRootFrame: ByteArray? = null
    private var creditPurposeFrame: ByteArray? = null
    private var walletPinsFrame: ByteArray? = null
    private var buildConfigLoaded = false

    @Suppress("DEPRECATION")
    @Synchronized
    fun install(context: android.content.Context) {
        if (buildConfigLoaded) return
        val metadata = context.packageManager
            .getApplicationInfo(context.packageName, android.content.pm.PackageManager.GET_META_DATA)
            .metaData
        val projectID = metadata?.get(PROJECT_ID_METADATA)?.toString()
        val brokerPublicKeyHex = metadata?.get(BROKER_KEY_METADATA)?.toString()
        buildConfigFrame = if (projectID == null && brokerPublicKeyHex == null) {
            null
        } else {
            "1\n${projectID.orEmpty()}\n${brokerPublicKeyHex.orEmpty()}".toByteArray(Charsets.UTF_8)
        }
        securityConfigFrame = metadata?.get(SECURITY_CONFIG_METADATA)?.toString()
            ?.toByteArray(Charsets.UTF_8)
        networkCounterConfigFrame = metadata?.get("app.morse.mesh.NETWORK_COUNTER_CONFIG")?.toString()?.toByteArray(Charsets.UTF_8)?.takeIf { it.size <= 24576 }
        // This immutable build resource has no JS setter and no runtime off default.
        ohttpConfigFrame = (metadata?.get(OHTTP_CONFIG_METADATA) as? String)
            ?.takeIf { it.length in 1..600 }?.toByteArray(Charsets.UTF_8)
            ?.takeIf { it.size <= 600 }
        networkConfigFrame = metadata?.get(NETWORK_CONFIG_METADATA)?.toString()
            ?.toByteArray(Charsets.UTF_8)
        creditPurposeFrame = when (metadata?.get(CREDIT_PURPOSE_METADATA)?.toString()) {
            "live" -> byteArrayOf(1, 0)
            "test" -> byteArrayOf(1, 1)
            else -> null
        }
        val lightning = listOf("mainnet", "testnet", "regtest", "signet", "simnet").indexOf(metadata?.get("app.morse.mesh.LIGHTNING_NETWORK")?.toString())
        lightningNetworkFrame = if (lightning >= 0) byteArrayOf(1, lightning.toByte()) else null
        val mint = metadata?.get(CREDIT_MINT_METADATA)?.toString()
        walletPinsFrame = if (creditPurposeFrame != null && mint != null && Regex("[0-9a-f]{64}").matches(mint) && mint != "00".repeat(32)) {
            byteArrayOf(1, creditPurposeFrame!![1]) + ByteArray(32) { mint.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } else null
        issuerTLSRootFrame = try {
            MeshMessengerIssuerTLS.read(requireNotNull(context.assets.list(""))) {
                context.assets.open(MeshMessengerIssuerTLS.ASSET)
            }
        } catch (_: Exception) { null } // Read failure stays unavailable; never substitute webPKI.
        buildConfigLoaded = true
    }

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

    @JvmStatic
    @Synchronized
    fun buildConfig(): ByteArray? = buildConfigFrame?.clone()

    @JvmStatic
    @Synchronized
    fun securityConfig(): ByteArray? = securityConfigFrame?.clone()

    @JvmStatic
    @Synchronized
    fun networkCounterConfig(): ByteArray? = networkCounterConfigFrame?.clone()

    @JvmStatic
    @Synchronized
    fun networkConfig(): ByteArray? = networkConfigFrame?.clone()

    @JvmStatic
    @Synchronized
    fun ohttpConfig(): ByteArray? = ohttpConfigFrame?.clone()

    @JvmStatic
    @Synchronized
    fun creditPurpose(): ByteArray? = creditPurposeFrame?.clone()

    @JvmStatic
    @Synchronized
    fun lightningNetwork(): ByteArray? = lightningNetworkFrame?.clone()

    @JvmStatic
    @Synchronized
    fun issuerTLSRoot(): ByteArray? = issuerTLSRootFrame?.clone()

    @JvmStatic
    @Synchronized
    fun walletPins(): ByteArray? = walletPinsFrame?.clone()

    @Synchronized
    fun clear() {
        frame?.fill(0)
        frame = null
    }
}
