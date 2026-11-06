package expo.modules.meshmessenger

import android.app.Activity
import android.app.AlertDialog
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.view.MotionEvent
import android.view.WindowManager
import java.io.File
import java.io.RandomAccessFile
import java.lang.ref.WeakReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileLock
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Wallet records are private native callback material; no Mesh or JS selector exposes them. */
internal object MeshMessengerWalletStore {
    private const val FAILURE = 3
    private const val CANCELLED = 4
    private val gate = ReentrantLock()
    private val main = Handler(Looper.getMainLooper())
    private var app: Context? = null
    private var pins: ByteArray? = null
    private var directory: File? = null
    private var alias = ""
    private var handle: RandomAccessFile? = null
    private var fileLock: FileLock? = null
    @Volatile private var activity = WeakReference<Activity>(null)
    private val prompt = AtomicReference<Prompt?>(null)

    private class Prompt(val owner: Activity, val epoch: String) {
        val result = AtomicInteger(CANCELLED)
        val done = CountDownLatch(1)
        var dialog: AlertDialog? = null
        fun cancel() { result.set(CANCELLED); dialog?.dismiss(); done.countDown() }
    }

    @Synchronized
    fun install(context: Context) {
        if (app != null) return
        val application = context.applicationContext
        val metadata = application.packageManager.getApplicationInfo(
            application.packageName, PackageManager.GET_META_DATA,
        ).metaData ?: error("wallet_configuration_missing")
        val purpose = when (metadata.getString("app.morse.mesh.CREDIT_PURPOSE")) {
            "live" -> 0
            "test" -> 1
            else -> error("wallet_purpose_missing")
        }
        val mint = metadata.getString("app.morse.mesh.CREDIT_USDC_MINT_HEX") ?: error("wallet_mint_missing")
        require(mint.matches(Regex("[0-9a-f]{64}"))) { "wallet_mint_invalid" }
        val bytes = ByteArray(32) { mint.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        require(bytes.any { it != 0.toByte() }) { "wallet_mint_invalid" }
        val folder = File(application.noBackupFilesDir, "morse-wallet-v1-$purpose")
        check((folder.exists() || folder.mkdirs()) && folder.isDirectory) { "wallet_storage_unavailable" }
        Os.chmod(folder.path, 448) // 0700; never shared preferences or backed-up storage.
        directory = folder
        alias = "app.morse.mesh.wallet.v1.$purpose"
        pins = bytes + byteArrayOf(purpose.toByte())
        app = application
        (application as Application).registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityResumed(value: Activity) { setActivity(value) }
            override fun onActivityPaused(value: Activity) { if (activity.get() === value) clearActivity() }
            override fun onActivityDestroyed(value: Activity) { if (activity.get() === value) clearActivity() }
            override fun onActivityCreated(value: Activity, state: Bundle?) = Unit
            override fun onActivityStarted(value: Activity) = Unit
            override fun onActivityStopped(value: Activity) = Unit
            override fun onActivitySaveInstanceState(value: Activity, state: Bundle) = Unit
        })
    }

    fun setActivity(value: Activity?) { activity = WeakReference(value) }
    internal fun hasOwnedPrompt(): Boolean = prompt.get()?.dialog?.isShowing == true
    fun clearActivity() {
        activity = WeakReference(null)
        main.post { prompt.get()?.cancel() }
    }

    @JvmStatic external fun invoke(operation: Int, input: ByteArray): ByteArray

    @JvmStatic private fun configuredPins(): ByteArray { MeshMessengerAppLock.capturedCallEpoch(); return requireNotNull(pins).clone() }

    @JvmStatic private fun acquire(): Int {
        try { MeshMessengerAppLock.capturedCallEpoch() } catch (_: Exception) { return CANCELLED }
        gate.lock()
        return try {
            check(handle == null && fileLock == null)
            val opened = RandomAccessFile(File(requireNotNull(directory), "wallet.lock"), "rw")
            handle = opened
            Os.chmod(File(requireNotNull(directory), "wallet.lock").path, 384) // 0600
            fileLock = opened.channel.lock() // OS lock spans independent application processes.
            0
        } catch (_: Exception) {
            runCatching { handle?.close() }
            handle = null
            fileLock = null
            gate.unlock()
            FAILURE
        }
    }

    private fun locked() { MeshMessengerAppLock.capturedCallEpoch(); check(gate.isHeldByCurrentThread && fileLock?.isValid == true) }
    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    // Keystore aliases are privileged platform state, outside the JS-accessible
    // filesystem. Advance this highwater mark BEFORE acknowledging a counter.
    // Restoring an older valid sealed file must never reuse a bounty address.
    private fun generation(): Long? {
        val prefix = "$alias.counter."
        val names = keyStore().aliases()
        var highest: Long? = null
        while (names.hasMoreElements()) {
            val name = names.nextElement()
            if (!name.startsWith(prefix)) continue
            val suffix = name.substring(prefix.length)
            val count = suffix.toLongOrNull() ?: error("wallet_counter_invalid")
            require(count in 0..2147483648L && suffix == count.toString())
            if (highest == null || count > highest) highest = count
        }
        return highest
    }

    private fun recordCounter(record: ByteArray): Long {
        require(record.size == 44 && record.copyOfRange(0, 4).contentEquals(byteArrayOf(77, 87, 76, 49)))
        val counter = ByteBuffer.wrap(record).order(ByteOrder.LITTLE_ENDIAN).getLong(36)
        require(counter in 0..2147483648L)
        return counter
    }

    private fun aad() = "morse-wallet-record-v1".toByteArray(Charsets.US_ASCII) + requireNotNull(pins)

    @JvmStatic private fun load(): ByteArray? {
        locked()
        val target = File(requireNotNull(directory), "wallet.sealed")
        val temporary = File(requireNotNull(directory), "wallet.pending")
        if (!target.exists()) {
            // A deleted record or interrupted first creation is not a new wallet.
            check(!temporary.exists() && existingKey() == null && generation() == null) { "wallet_record_missing" }
            return null
        }
        require(target.length() == 80L) { "wallet_record_invalid" }
        val encrypted = target.readBytes()
        try {
            require(encrypted.copyOfRange(0, 8).contentEquals("MWSEAL01".toByteArray(Charsets.US_ASCII)))
            val key = existingKey() ?: error("wallet_key_missing")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypted, 8, 12))
            cipher.updateAAD(aad())
            val record = cipher.doFinal(encrypted, 20, 60)
            try {
                check(recordCounter(record) == generation()) { "wallet_counter_rollback" }
                return record
            } catch (failure: Exception) { record.fill(0); throw failure }
        } finally { encrypted.fill(0) }
    }

    private fun createKey(name: String = alias): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    private fun syncDirectory() {
        val descriptor = Os.open(requireNotNull(directory).path, OsConstants.O_RDONLY, 0)
        try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
    }

    @JvmStatic private fun replace(record: ByteArray): Int = try {
        locked()
        val next = recordCounter(record)
        val previous = generation()
        check((previous == null && next == 0L) || (previous != null && next == previous + 1))
        val folder = requireNotNull(directory)
        val target = File(folder, "wallet.sealed")
        val temporary = File(folder, "wallet.pending")
        val key = existingKey() ?: run {
            check(!target.exists() && !temporary.exists()) { "wallet_key_missing" }
            createKey()
        }
        // A crash between marker creation and durable rename deliberately
        // fails closed. No counter or public bounty address can escape first.
        createKey("$alias.counter.$next")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        require(cipher.iv.size == 12)
        cipher.updateAAD(aad())
        val sealed = "MWSEAL01".toByteArray(Charsets.US_ASCII) + cipher.iv + cipher.doFinal(record)
        try {
            RandomAccessFile(temporary, "rw").use { output ->
                Os.chmod(temporary.path, 384)
                output.setLength(0)
                output.write(sealed)
                output.fd.sync()
            }
            Os.rename(temporary.path, target.path)
            syncDirectory() // Acknowledged only after the rename itself is durable.
            if (previous != null) keyStore().deleteEntry("$alias.counter.$previous")
        } finally { sealed.fill(0) }
        0
    } catch (_: Exception) { FAILURE }

    @JvmStatic private fun release(): Int {
        if (!gate.isHeldByCurrentThread) return FAILURE
        return try {
            fileLock?.release()
            handle?.close()
            0
        } catch (_: Exception) { FAILURE }
        finally { runCatching { handle?.close() }; fileLock = null; handle = null; gate.unlock() }
    }

    private fun active(owner: Activity) = activity.get() === owner && !owner.isFinishing && !owner.isDestroyed
    private fun foreground(owner: Activity) = active(owner) && owner.hasWindowFocus()

    @JvmStatic private fun authorize(operation: Int, intent: ByteArray): Int {
        if (Looper.myLooper() == Looper.getMainLooper()) return CANCELLED
        val text = try { confirmation(operation, intent, requireNotNull(pins)) } catch (_: Exception) { return CANCELLED }
        val owner = activity.get() ?: return CANCELLED
        val expected = try { MeshMessengerAppLock.capturedCallEpoch() } catch (_: Exception) { return CANCELLED }
        val pending = Prompt(owner,expected)
        if (!prompt.compareAndSet(null, pending)) return CANCELLED
        try {
            main.post {
                if (runCatching { MeshMessengerAppLock.requireEpoch(pending.epoch) }.isFailure || !foreground(owner) || prompt.get() !== pending) { pending.cancel(); return@post }
                val dialog = AlertDialog.Builder(owner)
                    .setTitle(if (operation == 1) "Create local wallet" else if (operation == 5) "Confirm bounty transfer" else "Confirm credit payment")
                    .setMessage(text)
                    .setNegativeButton("Cancel") { _, _ -> pending.cancel() }
                    .setPositiveButton(if (operation == 1) "Create wallet" else if (operation == 5) "Move bounty" else "Confirm payment") { _, _ ->
                        if (active(owner) && pending.dialog?.window?.decorView?.hasWindowFocus() == true
                            && prompt.get() === pending && runCatching { MeshMessengerAppLock.requireEpoch(pending.epoch) }.isSuccess) pending.result.set(0)
                        pending.done.countDown()
                    }
                    .setOnCancelListener { pending.cancel() }
                    .create()
                pending.dialog = dialog
                dialog.setOnDismissListener { pending.done.countDown() }
                dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                dialog.show()
                dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                dialog.window?.decorView?.viewTreeObserver?.addOnWindowFocusChangeListener { focused ->
                    if (prompt.get() === pending) {
                        if (focused) MeshMessengerAppLock.consentForeground(owner,pending.epoch)
                        else if (dialog.isShowing && pending.result.get() != 0) MeshMessengerAppLock.invalidate("inactive",false)
                    }
                }
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply {
                    // Keep this owned dialog focused until the native SDK
                    // authorization callback returns; default auto-dismiss can
                    // otherwise race the final foreground/epoch check.
                    setOnClickListener {
                        if (active(owner) && dialog.window?.decorView?.hasWindowFocus() == true && prompt.get() === pending &&
                            runCatching { MeshMessengerAppLock.requireEpoch(pending.epoch) }.isSuccess) pending.result.set(0)
                        pending.done.countDown()
                    }
                    filterTouchesWhenObscured = true
                    setOnTouchListener { _, event ->
                        (event.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) != 0
                    }
                }
            }
            if (!pending.done.await(120, TimeUnit.SECONDS)) return CANCELLED
            if (pending.result.get() == 0) {
                try { MeshMessengerAppLock.publication(pending.epoch) } catch (_: Exception) { return CANCELLED }
            }
            // Returning native approval is the irreversible consent admission
            // point. A later lock cannot claim to undo already approved signing.
            return pending.result.get()
        } catch (_: InterruptedException) { Thread.currentThread().interrupt(); return CANCELLED }
        finally {
            prompt.compareAndSet(pending, null)
            main.post { pending.dialog?.dismiss() }
        }
    }

    @JvmStatic private external fun authorizationText(operation: Int, intent: ByteArray): ByteArray

    // Native configuration remains authoritative even for direct formatter use.
    // The shared SDK formats the already validated public intent; it cannot
    // authorize, access wallet storage, or sign anything through this helper.
    internal fun confirmation(operation: Int, intent: ByteArray, configuration: ByteArray): String {
        require(configuration.size == 33 && configuration[32].toInt() in 0..1)
        require(configuration.take(32).any { it != 0.toByte() })
        if (operation == 1) {
            require(intent.size == 32)
        } else if (operation == 5) {
            require(intent.size == 198 && intent.copyOfRange(0, 4).contentEquals(byteArrayOf(1, 66, 87, 84)))
            require(intent[164] == configuration[32])
        } else {
            require(operation == 3 && intent.size == 288 && intent.copyOfRange(0, 4).contentEquals(byteArrayOf(1, 67, 81, 84)))
            require(intent[141] == configuration[32])
            val asset = intent[132].toInt()
            require(asset == 0 || asset == 1)
            if (asset == 0) require(intent.copyOfRange(100, 132).contentEquals(configuration.copyOfRange(0, 32)))
        }
        return authorizationText(operation, intent).toString(Charsets.UTF_8)
    }
}
