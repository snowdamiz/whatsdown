package expo.modules.meshmessenger

import android.app.Activity
import android.app.Application
import android.app.Dialog
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.view.ViewTreeObserver
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.facebook.react.ReactActivity
import java.lang.ref.WeakReference
import java.util.UUID
import java.util.WeakHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Process-native authority. No method accepts a caller-asserted auth result. */
object MeshMessengerAppLock {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val operation = ReentrantLock()
    // Only native state changes and the short clipboard OS publication share
    // this lock. It is never held over policy, networking, or provider IO.
    private val stateLock = ReentrantLock()
    private var restrictiveEvent = UUID.randomUUID().toString()
    private var clearedRestrictiveEvent = restrictiveEvent
    // New admission waits until old native revocation hooks have completed;
    // the hooks themselves run without holding the short state lock.
    private var revoking = 0
    @Volatile private var booting = true
    private val epoch = AtomicReference(UUID.randomUUID().toString())
    private val challenge = AtomicReference<Challenge?>(null)
    private val observers = CopyOnWriteArrayList<(Map<String, Any>) -> Unit>()
    private val revoked = CopyOnWriteArrayList<() -> Unit>()
    private val inboxObservers = CopyOnWriteArrayList<() -> Unit>()
    private val pendingInbox = AtomicBoolean(false)
    private val callEpoch = ThreadLocal<String?>()
    private val covers = WeakHashMap<Activity, NativeCover>()
    private val focusListeners = WeakHashMap<Activity, ViewTreeObserver.OnWindowFocusChangeListener>()
    @Volatile private var application: Application? = null
    @Volatile private var owner = WeakReference<Activity>(null)
    @Volatile private var resumed = false
    @Volatile private var ownedForeground = false
    @Volatile private var record: MeshMessengerAppLockPolicy.Record? = null
    @Volatile private var phase = "booting"
    @Volatile private var fault: String? = null
    @Volatile private var restricted = true
    @Volatile private var activatedEpoch: String? = null
    @Volatile private var account = 0L
    private var nextCredentialCode = 0x4000
    private lateinit var store: MeshMessengerAppLockPolicyPort

    private class Challenge(val owner: Activity, val account: Long, val sequence: Long, val desired: Boolean?, val code: Int) {
        val id = UUID.randomUUID().toString()
        val deadline = SystemClock.elapsedRealtime() + 120_000
        val done = CountDownLatch(1)
        @Volatile var cancelled = false
        @Volatile var approved = false
        var prompt: BiometricPrompt? = null
    }

    @Synchronized fun install(app: Application) {
        if (application != null) return
        application = app
        stateLock.withLock { booting = true; phase = "booting"; restricted = true }
        store = MeshMessengerAppLockPolicy(app)
        MeshMessengerProtectedFiles.install(app)
        MeshMessengerLockedNotifications.install(app)
        app.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity !is ReactActivity) return
                stateLock.withLock {
                    owner = WeakReference(activity); resumed = true
                    ownedForeground = activity.hasWindowFocus() || covers[activity]?.window?.decorView?.hasWindowFocus() == true
                }
                MeshMessengerLockedNotifications.consumeIntent(activity.intent)
                MeshMessengerScreenSecurity.protect(activity)
                if (!focusListeners.containsKey(activity)) {
                    val listener = ViewTreeObserver.OnWindowFocusChangeListener { focused ->
                        if (owner.get() === activity) {
                            stateLock.withLock { ownedForeground = focused || covers[activity]?.window?.decorView?.hasWindowFocus() == true }
                            if (focused) finishIfForeground(challenge.get())
                            else main.post {
                                if (owner.get() === activity && !activity.hasWindowFocus() && covers[activity]?.isShowing != true && challenge.get() == null && !MeshMessengerWalletStore.hasOwnedPrompt()) invalidate("inactive", false)
                            }
                        }
                    }
                    focusListeners[activity] = listener
                    activity.window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(listener)
                }
                val disabled = stateLock.withLock {
                    if (!booting && phase != "error" && record?.policy == "disabled" && !restricted && challenge.get() == null) {
                        phase = "disabled"; true
                    } else false
                }
                if (disabled) emit()
                showCover(activity)
                finishIfForeground(challenge.get())
            }
            override fun onActivityPaused(activity: Activity) {
                if (owner.get() !== activity) return
                val cancelled = stateLock.withLock {
                    resumed = false; ownedForeground = false
                    revokeState(challenge.get()?.owner === activity)
                }
                finishRevocation(cancelled)
            }
            override fun onActivityDestroyed(activity: Activity) {
                covers.remove(activity)?.let { it.handingOff = true; it.dismiss() }
                focusListeners.remove(activity)?.let {
                    activity.window.decorView.viewTreeObserver.removeOnWindowFocusChangeListener(it)
                }
                if (owner.get() === activity) {
                    val cancelled = stateLock.withLock {
                        resumed = false; ownedForeground = false; owner = WeakReference(null)
                        revokeState(false)
                    }
                    finishRevocation(cancelled)
                }
            }
            override fun onActivityCreated(activity: Activity, state: Bundle?) { if (activity is ReactActivity) MeshMessengerLockedNotifications.consumeIntent(activity.intent) }
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
        })
        worker.execute {
            var bootFault = "notification_delegation_unavailable"
            try {
                MeshMessengerLockedNotifications.revokeSystemDelegation()
                bootFault = "policy_unreadable"
                val loaded = store.load()
                MeshMessengerProtectedFiles.cleanOrphans()
                fun commitBoot(noticesDrained: Boolean): Boolean = stateLock.withLock {
                    val effectiveRestriction = loaded.policy != "disabled" || restrictiveEvent != clearedRestrictiveEvent
                    if (effectiveRestriction && !noticesDrained) false else {
                        record = loaded
                        restricted = effectiveRestriction
                        phase = if (restricted) "locked" else "disabled"
                        booting = false
                        true
                    }
                }
                // Decide and commit under the same state lock: a manual lock
                // after the durable read must drain too. Native boot remains
                // covered during IO; unchanged disabled bootstrap keeps notices.
                if (!commitBoot(false)) {
                    MeshMessengerLockedNotifications.drainLegacy()
                    check(commitBoot(true))
                }
            } catch (_: Throwable) { stateLock.withLock { phase = "error"; restricted = true; fault = bootFault; booting = false } }
            emit()
        }
    }


    // Private routes exist only in this native process and are bound to the
    // exact publication state. A null entry is a used UUID tombstone; it keeps
    // no private data and cannot be evicted to make room within the same epoch.
    private data class NoticeAuthority(
        val epoch: String, val account: Long, val record: MeshMessengerAppLockPolicy.Record,
        val owner: WeakReference<Activity>, val scope: String,
    )
    private val issuedNotices = mutableMapOf<String,NoticeAuthority?>()
    private var pendingNotice: Pair<String,NoticeAuthority>? = null
    private val noticeScope = Regex("(?:chat/[a-f0-9]{32}|group/[a-f0-9]{64})")
    private fun matchesNotice(value: NoticeAuthority): Boolean =
        !booting && revoking == 0 && !restrictionActive() && phase == "disabled" &&
            record == value.record && epoch.get() == value.epoch && account == value.account &&
            owner.get() != null && owner.get() === value.owner.get()

    // The only closure admitted here is the short synchronous native OS post.
    // Parsing, builders, IO and asynchronous work stay outside this state lock.
    internal fun publishNativeNotice(expected: String, scope: String, post: (String) -> Unit): String {
        require(scope.length <= 70 && noticeScope.matches(scope)) { "invalid_notice_scope" }
        return stateLock.withLock {
            requireEpoch(expected)
            val activity=notificationActivity(expected)
            check(issuedNotices.size < 128) { "notice_capacity" }
            val id=UUID.randomUUID().toString()
            val authority=NoticeAuthority(expected,account,checkNotNull(record),WeakReference(activity),scope)
            issuedNotices[id]=authority
            try { post(id) }
            catch(error: Throwable) { forgetNativeNotice(id);throw error }
            id
        }
    }
    // Native publisher only: this never grants JS an Activity or route receipt.
    // Disabled background issuance uses the retained live owner, while consume
    // requires the same owner to be resumed and focused.
    internal fun notificationActivity(expected: String): Activity =
        notificationActivityOrNull(expected) ?: error("app_lock_unavailable")
    // Absence is distinct from stale or restricted authority. Only a fresh,
    // admitted disabled action may use the fixed generic headless fallback.
    internal fun notificationActivityOrNull(expected: String): Activity? = stateLock.withLock {
        requireEpoch(expected)
        check(!restrictionActive() && phase == "disabled") { "app_locked" }
        owner.get()?.takeUnless { it.isDestroyed || it.isFinishing }
    }
    internal fun receiveNativeNotice(identifier: String?, activity: Activity) {
        val listeners=stateLock.withLock {
            if(identifier != null && issuedNotices.containsKey(identifier) && issuedNotices[identifier] == null) return@withLock emptyList<() -> Unit>()
            val issued=issuedNotices[identifier]
            pendingNotice=null;pendingInbox.set(true)
            if(identifier != null && issued != null) {
                issuedNotices[identifier]=null
                if(matchesNotice(issued) && owner.get() === activity && !activity.isFinishing && !activity.isDestroyed) {
                    pendingNotice=identifier to issued;pendingInbox.set(false)
                }
            }
            inboxObservers.toList()
        }
        listeners.forEach { runCatching { it() } }
    }
    internal fun forgetNativeNotice(identifier: String) = stateLock.withLock {
        // Retain consumed tombstones so a duplicate cannot displace a later tap.
        if(issuedNotices[identifier] != null) issuedNotices.remove(identifier)
        if(pendingNotice?.first == identifier) { pendingNotice=null;pendingInbox.set(true) }
    }
    internal fun consumeNotificationIntent(expected: String, activity: Activity): String = stateLock.withLock {
        requireEpoch(expected)
        // Observe invalid retained authority before checking the caller's native
        // owner, so an owner that later returns cannot revive that private route.
        if(pendingNotice?.second?.let { !matchesNotice(it) } == true) { pendingNotice=null;pendingInbox.set(true) }
        check(owner.get() === activity && resumed && ownedForeground && !activity.isDestroyed && !activity.isFinishing) { "app_locked" }
        pendingNotice?.let {
            pendingNotice=null
            return@withLock "{\"version\":1,\"kind\":\"scope\",\"scope\":\"${it.second.scope}\"}"
        }
        val kind=if(pendingInbox.getAndSet(false)) "inbox" else "none"
        "{\"version\":1,\"kind\":\"$kind\"}"
    }
    private fun rotateEpochLocked() {
        epoch.set(UUID.randomUUID().toString());activatedEpoch=null
        issuedNotices.clear()
        if(pendingNotice != null) { pendingNotice=null;pendingInbox.set(true) }
    }

    internal fun context(): Context = application ?: error("app_lock_unavailable")
    internal fun currentEpoch(): String = epoch.get()
    internal fun accountGeneration(): Long = account
    internal fun recordInboxOpen() {
        stateLock.withLock { pendingNotice=null;pendingInbox.set(true) }
        inboxObservers.forEach { runCatching { it() } }
    }
    internal fun observeInbox(listener: () -> Unit): () -> Unit { inboxObservers.add(listener); return { inboxObservers.remove(listener) } }
    internal fun consumeInbox(expected: String): Boolean = stateLock.withLock {
        requireEpoch(expected)
        pendingNotice == null && pendingInbox.compareAndSet(true,false)
    }
    internal fun restrictionActive(): Boolean = restricted || record?.policy != "disabled"
    internal fun currentActivity(): Activity = owner.get()?.takeIf { resumed && !it.isDestroyed && !it.isFinishing } ?: error("app_lock_unavailable")
    internal fun state(): Map<String, Any> {
        val capability = if (secureCredential()) "available" else "unavailable"
        return stateLock.withLock { mutableMapOf<String, Any>(
            "version" to 1, "policy" to (record?.policy ?: "unknown"), "phase" to phase,
            "capability" to capability, "epoch" to epoch.get(),
        ).apply { challenge.get()?.let { put("requestId", it.id) }; fault?.let { put("error", it) } } }
    }
    internal fun observe(listener: (Map<String, Any>) -> Unit): () -> Unit { observers.add(listener); return { observers.remove(listener) } }
    internal fun onRevoke(listener: () -> Unit): () -> Unit { revoked.add(listener); return { revoked.remove(listener) } }
    private fun emit() { val value = state(); observers.forEach { runCatching { it(value) } }; onMain { owner.get()?.let(::showCover) } }
    private fun onMain(body: () -> Unit) { if (Looper.myLooper() == Looper.getMainLooper()) body() else main.post(body) }
    private fun secureCredential(): Boolean = runCatching {
        (context().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
    }.getOrDefault(false)

    internal fun requireEpoch(expected: String) = stateLock.withLock {
        check(expected == epoch.get()) { "stale_epoch" }
        check(!booting && revoking == 0 && record != null && phase != "booting" && phase != "error") { "app_lock_unavailable" }
        if (restrictionActive()) check(record?.policy == "enabled" && phase == "unlocked" && resumed && ownedForeground) { "app_locked" }
        // Do not combine an old epoch read with a later unlocked state across
        // concurrent revoke/auth transitions. This is admission, not a grant.
        check(expected == epoch.get()) { "stale_epoch" }
    }

    internal fun <T> scoped(expected: String, body: () -> T): T {
        requireEpoch(expected)
        val previous = callEpoch.get(); callEpoch.set(expected)
        val value: T
        try { value = body() } finally { callEpoch.set(previous) }
        try { requireEpoch(expected) }
        catch (error: Throwable) { if (value is ByteArray) value.fill(0); throw error }
        return value
    }
    // Called only by the exact registered native wallet dialog's real focus
    // observer. This preserves existing authority; it never authenticates.
    internal fun consentForeground(activity: Activity, expected: String) {
        stateLock.withLock {
            if (owner.get() === activity && resumed && expected == epoch.get() && (phase == "unlocked" || phase == "disabled")) ownedForeground = true
        }
    }
    internal fun capturedCallEpoch(): String = callEpoch.get()?.also(::requireEpoch) ?: error("scoped_client_required")
    // This check is the short native admission point. Never hold a state mutex
    // over core networking/provider IO, so revoke/cover cannot wait behind it.
    internal fun publication(expected: String) { requireEpoch(expected) }

    // Publication and epoch revocation have one native ordering. Once this OS
    // call is admitted, revoke waits for this short synchronous publication;
    // future stale calls still refuse, and completed user copies are retained.
    internal fun copyProtectedText(text: String, expected: String) {
        check(Looper.myLooper() == Looper.getMainLooper()) { "app_lock_unavailable" }
        stateLock.withLock { scoped(expected) {
            publication(expected)
            (context().getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                .setPrimaryClip(android.content.ClipData.newPlainText("Morse",text))
        } }
    }

    private fun revokeState(preserveChallenge: Boolean): Challenge? {
        revoking++
        rotateEpochLocked() // Atomic revocation precedes any main/IO wait.
        val cancelled = challenge.get()?.takeUnless { preserveChallenge }
        cancelled?.let { it.cancelled = true; it.done.countDown() }
        phase = if (booting) "booting" else if (phase == "error") "error" else if (challenge.get() != null) "authenticating" else if (record?.policy == "disabled" && !restricted) "disabled" else "locked"
        return cancelled
    }
    private fun finishRevocation(cancelled: Challenge?) {
        try {
            revoked.forEach { runCatching { it() } }
            MeshMessengerProtectedFiles.revoke()
            onMain { cancelled?.prompt?.cancelAuthentication(); owner.get()?.let(::showCover); MeshMessengerWalletStore.clearActivity() }
        } finally {
            stateLock.withLock { revoking-- }
            emit()
        }
    }
    internal fun invalidate(reason: String, preserveChallenge: Boolean = false) {
        val cancelled = stateLock.withLock { revokeState(preserveChallenge) }
        finishRevocation(cancelled)
    }
    internal fun lock() {
        val cancelled = stateLock.withLock { restrictiveEvent = UUID.randomUUID().toString(); restricted = true; revokeState(false) }
        finishRevocation(cancelled)
    }
    internal fun accountChanging() {
        val cancelled = stateLock.withLock {
            account++
            if (booting || restricted || challenge.get() != null) restrictiveEvent = UUID.randomUUID().toString()
            revokeState(false)
        }
        finishRevocation(cancelled)
    }
    internal fun activate(expected: String) {
        check(Looper.myLooper() == Looper.getMainLooper()) { "app_lock_unavailable" }
        stateLock.withLock {
            requireEpoch(expected); check(resumed) { "app_locked" }
            activatedEpoch = expected
            owner.get()?.let(::maybeUncover)
        }
    }
    private fun maybeUncover(activity: Activity) {
        stateLock.withLock {
            if (revoking != 0 || activatedEpoch != epoch.get() || !resumed || !ownedForeground || (phase != "unlocked" && phase != "disabled")) return@withLock
            covers.remove(activity)?.let { it.handingOff = true; it.dismiss() }
        }
    }
    private class NativeCover(val activity: Activity) : Dialog(activity) {
        var handingOff = false
        init { requestWindowFeature(android.view.Window.FEATURE_NO_TITLE); setCancelable(false); setCanceledOnTouchOutside(false) }
        override fun onWindowFocusChanged(hasFocus: Boolean) {
            super.onWindowFocusChanged(hasFocus)
            if (owner.get() !== activity || handingOff) return
            val expected = stateLock.withLock { ownedForeground = hasFocus || activity.hasWindowFocus(); epoch.get() }
            if (hasFocus) {
                finishIfForeground(challenge.get())
                // Dismiss after framework focus dispatch returns, retaining the
                // exact cover and epoch observed by this callback.
                main.post { stateLock.withLock {
                    if (owner.get() === activity && covers[activity] === this && epoch.get() == expected) maybeUncover(activity)
                } }
            }
            else if (challenge.get() == null && phase == "unlocked" && resumed) invalidate("inactive",false)
        }
    }

    internal fun authenticate(expected: String, desired: Boolean? = null): Map<String, Any> {
        check(Looper.myLooper() != Looper.getMainLooper()) { "app_lock_unavailable" }
        val previousRecord = record ?: error("policy_unreadable")
        check(operation.tryLock()) { "authentication_in_progress" }
        var pending: Challenge? = null
        var admitted = false
        var authenticated = false
        var firstOptIn = false
        var recoveringCommittedDisable = false
        var admittedEvent = ""
        var admissionEpoch = ""
        try {
            var unchangedDisabled = false
            val cancelled = stateLock.withLock {
                check(expected == epoch.get() && record === previousRecord && resumed && !booting && revoking == 0 && phase != "booting" && phase != "error") { "stale_epoch" }
                admitted = true
                val wasRestricted = restricted
                firstOptIn = previousRecord.policy == "disabled" && !wasRestricted && desired == true
                recoveringCommittedDisable = previousRecord.policy == "disabled" && wasRestricted
                admittedEvent = restrictiveEvent
                unchangedDisabled = desired == null && previousRecord.policy == "disabled" && !wasRestricted
                if (unchangedDisabled) null else {
                    restricted = true
                    revokeState(false).also { admissionEpoch = epoch.get() }
                }
            }
            if (unchangedDisabled) return state()
            finishRevocation(cancelled)
            if (!secureCredential()) error("authentication_unavailable")
            val activity = currentActivity()
            val request = stateLock.withLock {
                check(admissionEpoch == epoch.get() && admittedEvent == restrictiveEvent && owner.get() === activity && resumed && !booting && revoking == 0) { "authentication_cancelled" }
                check(activity is FragmentActivity && nextCredentialCode < 0x6000) { "authentication_unavailable" }
                Challenge(activity, account, previousRecord.sequence, desired, nextCredentialCode++).also {
                    pending = it
                    check(challenge.compareAndSet(null, it)) { "authentication_in_progress" }
                    phase = "authenticating"; fault = null
                }
            }
            emit()
            onMain { beginPrompt(request) }
            if (!request.done.await(120, TimeUnit.SECONDS)) { cancel(request.id); error("authentication_timeout") }
            checkValidResult(request)
            authenticated = true
            // Cached policy is not authority after an OS result. Plain unlock
            // and no-op policy commands need the same exact durable recheck.
            verifyDurable(previousRecord)
            checkValidResult(request)
            val target = desired ?: (previousRecord.policy == "enabled")
            // A durable disable may have committed just before losing the OS
            // result's foreground. Recovery requires this NEW exact challenge;
            // restricted disabled state never takes the ordinary early return.
            if (desired == null && previousRecord.policy != "enabled" && !recoveringCommittedDisable) error("policy_recovery_required")
            var committed = previousRecord
            if (desired != null) {
                // First opt-in authenticates BEFORE any durable pending policy.
                val finalPolicy = if (target) "enabled" else "disabled"
                val pendingPolicy = if (target) "enable_pending" else "disable_pending"
                if (committed.policy != finalPolicy) {
                    if (committed.policy != pendingPolicy) {
                        committed = store.transition(committed,pendingPolicy)
                        stateLock.withLock { record = committed }
                    }
                    checkValidResult(request)
                    if (target) MeshMessengerLockedNotifications.drainLegacy()
                    checkValidResult(request)
                    committed = store.transition(committed,finalPolicy)
                    stateLock.withLock { record = committed }
                }
            }
            verifyDurable(committed)
            stateLock.withLock {
                checkValidResult(request)
                check(admittedEvent == restrictiveEvent) { "authentication_cancelled" }
                record = committed
                restricted = committed.policy != "disabled"
                clearedRestrictiveEvent = restrictiveEvent
                rotateEpochLocked(); phase = if (restricted) "unlocked" else "disabled"
                fault = null
            }
            return state()
        } catch (error: Throwable) {
            // A request which never entered this lifecycle cannot revoke a
            // later grant just because its queued admission was stale.
            if (!admitted) throw error
            val durable = runCatching { store.load() }.getOrNull()
            stateLock.withLock {
                if (durable != null) record = durable
                // OS approval is observed by the native callback before this
                // worker wakes. Later cancellation cannot erase that fact, nor
                // can this catch overwrite a later manual/account restriction.
                if (firstOptIn && !authenticated && pending?.approved != true &&
                    admittedEvent == restrictiveEvent && durable == previousRecord && durable.policy == "disabled") {
                    restricted = false; phase = "disabled"; fault = null
                    clearedRestrictiveEvent = restrictiveEvent
                } else {
                    restricted = true; phase = if (durable == null) "error" else "locked"
                    fault = if (durable == null) "policy_unreadable" else "authentication_failed"
                }
                rotateEpochLocked()
            }
            throw error
        } finally {
            stateLock.withLock { pending?.let { challenge.compareAndSet(it, null) } }
            pending?.let { onMain { it.prompt?.cancelAuthentication() } }
            operation.unlock(); emit()
        }
    }

    private fun verifyDurable(expected: MeshMessengerAppLockPolicy.Record) {
        check(store.load() == expected) { "policy_changed" }
    }

    private fun checkValidResult(value: Challenge) = stateLock.withLock {
        check(revoking == 0 && challenge.get() === value && !value.cancelled && value.approved &&
            value.account == account && value.owner === owner.get() && resumed && ownedForeground &&
            SystemClock.elapsedRealtime() <= value.deadline && !value.owner.isDestroyed) { "authentication_cancelled" }
    }
    private fun promptActive(value: Challenge): Boolean = challenge.get() === value && !value.cancelled &&
        value.owner === owner.get() && value.account == account && resumed && !value.owner.isDestroyed &&
        SystemClock.elapsedRealtime() <= value.deadline

    private fun beginPrompt(value: Challenge) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!stateLock.withLock { promptActive(value) }) { cancel(value.id); return }
        if (Build.VERSION.SDK_INT >= 30) {
            val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            if (BiometricManager.from(context()).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) { cancel(value.id); return }
            val prompt = BiometricPrompt(value.owner as FragmentActivity, ContextCompat.getMainExecutor(context()), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    stateLock.withLock {
                        if (challenge.get() !== value || value.cancelled || value.account != account) return@withLock
                        value.approved = true
                        finishIfForeground(value)
                    }
                }
                override fun onAuthenticationError(code: Int, message: CharSequence) { cancel(value.id) }
                // A failed biometric match is not final: keep OS credential fallback.
            })
            val info = BiometricPrompt.PromptInfo.Builder().setTitle(context().getString(R.string.morse_al1_unlock_title))
                .setAllowedAuthenticators(authenticators).build()
            try {
                val launched = stateLock.withLock {
                    if (!promptActive(value)) false else {
                        value.prompt = prompt
                        prompt.authenticate(info)
                        true
                    }
                }
                if (!launched) cancel(value.id)
            } catch (_: Throwable) { cancel(value.id) }
        } else {
            val manager = context().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            val intent = manager.createConfirmDeviceCredentialIntent(context().getString(R.string.morse_al1_unlock_title), context().getString(R.string.morse_al1_unlock_description))
            if (intent == null) { cancel(value.id); return }
            try {
                val launched = stateLock.withLock {
                    if (!promptActive(value)) false else {
                        value.owner.startActivityForResult(intent, value.code)
                        true
                    }
                }
                if (!launched) cancel(value.id)
            } catch (_: Throwable) { cancel(value.id) }
        }
    }
    internal fun activityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        val value = stateLock.withLock {
            val current = challenge.get() ?: return false
            if (current.owner !== activity || current.code != requestCode || Build.VERSION.SDK_INT >= 30) return false
            if (resultCode == Activity.RESULT_OK && !current.cancelled && current.account == account) {
                current.approved = true
                finishIfForeground(current)
            }
            current
        }
        if (resultCode != Activity.RESULT_OK) cancel(value.id)
        return true
    }
    private fun finishIfForeground(value: Challenge?) = stateLock.withLock {
        if (value != null && challenge.get() === value && value.approved && !value.cancelled && resumed &&
            owner.get() === value.owner && ownedForeground) value.done.countDown()
    }
    internal fun cancel(id: String?) {
        val value = stateLock.withLock {
            val current = challenge.get() ?: return
            if (id != current.id) return
            current.cancelled = true; current.done.countDown()
            current
        }
        onMain { value.prompt?.cancelAuthentication() }
    }

    private fun showCover(activity: Activity) {
        check(Looper.myLooper() == Looper.getMainLooper())
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (activity.isDestroyed || activity.isFinishing) return
        if (activatedEpoch == epoch.get() && resumed && ownedForeground && (phase == "unlocked" || phase == "disabled")) { maybeUncover(activity); return }
        val dialog = covers[activity] ?: NativeCover(activity).also { covers[activity] = it }
        val cover = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL; gravity = android.view.Gravity.CENTER
            setBackgroundColor(0xff0a0a0c.toInt()); isClickable = true; isFocusable = true
            addView(TextView(activity).apply { text = activity.getString(R.string.morse_al1_locked); setTextColor(0xffffffff.toInt()); textSize = 22f })
            fun control(label: String, desired: Boolean?) {
                addView(Button(activity).apply {
                    text = label
                    setOnClickListener {
                        val expected = epoch.get()
                        worker.execute { runCatching { authenticate(expected, desired) } }
                    }
                })
            }
            val pending = challenge.get()
            if (pending != null) {
                addView(Button(activity).apply { text = activity.getString(R.string.morse_al1_cancel); setOnClickListener { cancel(pending.id) } })
            } else if (record?.policy == "enable_pending" || record?.policy == "disable_pending") {
                control(activity.getString(R.string.morse_al1_finish_enable), true); control(activity.getString(R.string.morse_al1_disable), false)
            } else control(activity.getString(R.string.morse_al1_unlock), null)
        }
        dialog.setContentView(cover)
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (!dialog.isShowing) dialog.show()
        dialog.window?.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(0xff0a0a0c.toInt()))
        dialog.window?.setLayout(WindowManager.LayoutParams.MATCH_PARENT,WindowManager.LayoutParams.MATCH_PARENT)
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
