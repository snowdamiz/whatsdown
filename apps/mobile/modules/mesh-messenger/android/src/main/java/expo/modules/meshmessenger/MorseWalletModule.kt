package expo.modules.meshmessenger

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.functions.Queues
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.nio.ByteBuffer

// The in-app wallet's host (plan §6.13): packages/wallet-core, linked into
// libmessenger_mobile.so, with the seed (BIP39 entropy) sealed by the app's
// Android Keystore key (MeshMessengerSecureStore; its preferences are excluded
// from backups). The seed never reaches JavaScript: the recovery phrase (for
// display), public keys, parsed pay requests and signed transactions do. Every
// request frame that held the seed is wiped when the call returns.
// The API is apps/mobile/modules/mesh-messenger/wallet.ts.
class MorseWalletModule : Module() {
    private val lock = Any()
    private var confirming: Promise? = null

    override fun definition() = ModuleDefinition {
        Name("MorseWallet")

        AsyncFunction("walletExists") { locked { read(ENTROPY)?.also { it.fill(0) } != null } }

        AsyncFunction("walletCreate") { words: Int ->
            locked {
                val answer = core(1, byteArrayOf(words.toByte()))
                val entropy = vector(answer, 0)
                val phrase = vector(answer, 4 + entropy.size)
                try {
                    storeNew(entropy)
                    String(phrase, Charsets.UTF_8)
                } finally {
                    answer.fill(0)
                    entropy.fill(0)
                    phrase.fill(0)
                }
            }
        }

        AsyncFunction("walletRestore") { phrase: String ->
            locked {
                val typed = vec32(phrase.toByteArray(Charsets.UTF_8))
                val entropy = try { core(2, typed) } finally { typed.fill(0) }
                try { storeNew(entropy) } finally { entropy.fill(0) }
            }
        }

        // Behind the device's biometrics or screen lock; a device without a lock has
        // nothing to ask for.
        AsyncFunction("walletPhrase") { promise: Promise -> confirmOwner(promise) }.runOnQueue(Queues.MAIN)

        AsyncFunction("walletWipe") {
            locked {
                for (name in listOf(ENTROPY, BOUNTY_INDEX)) {
                    if (MeshMessengerSecureStore.delete(name.toByteArray()) != 0) throw WalletException("wallet_store_failed")
                }
            }
        }

        // Ops 4 (address), 5 (transfer), 6 (parse a Solana Pay URL); `body` follows the seed.
        AsyncFunction("walletCall") { op: Int, body: ByteArray -> locked { call(op, body) } }

        // u32 index || public key; the next index is persisted before the address is returned.
        AsyncFunction("walletNextBountyAddress") {
            locked {
                val index = issued()
                val key = derive(index)
                write(BOUNTY_INDEX, u32(index + 1))
                u32(index) + key
            }
        }

        AsyncFunction("walletBountyIndex") { atLeast: Int ->
            locked {
                entropy().fill(0)
                if (atLeast < 0) throw WalletException("bad_index")
                val issued = issued()
                if (atLeast > issued) write(BOUNTY_INDEX, u32(atLeast))
                maxOf(issued, atLeast)
            }
        }

        // Screen-lock confirmation on Android 6-9, before BiometricPrompt could offer it.
        OnActivityResult { _, payload ->
            if (payload.requestCode != CONFIRM_REQUEST) return@OnActivityResult
            val promise = confirming ?: return@OnActivityResult
            confirming = null
            if (payload.resultCode == Activity.RESULT_OK) reveal(promise) else promise.reject(WalletException("authentication_failed"))
        }
    }

    private fun <T> locked(body: () -> T): T = synchronized(lock) {
        appContext.reactContext?.let { MeshMessengerSecureStore.install(it) }
        body()
    }

    private fun confirmOwner(promise: Promise) {
        val activity = appContext.currentActivity ?: return promise.reject(WalletException("authentication_failed"))
        val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isDeviceSecure) return reveal(promise)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            @Suppress("DEPRECATION")
            val intent = keyguard.createConfirmDeviceCredentialIntent("Recovery phrase", "Show your wallet's recovery phrase")
                ?: return reveal(promise)
            confirming = promise
            @Suppress("DEPRECATION")
            activity.startActivityForResult(intent, CONFIRM_REQUEST)
            return
        }
        val builder = BiometricPrompt.Builder(activity).setTitle("Show your wallet's recovery phrase")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        }
        builder.build().authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = reveal(promise)
                override fun onAuthenticationError(code: Int, message: CharSequence) =
                    promise.reject(WalletException("authentication_failed"))
            },
        )
    }

    private fun reveal(promise: Promise) {
        try {
            promise.resolve(
                locked {
                    val seeded = seeded(ByteArray(0))
                    val phrase = try { core(3, seeded) } finally { seeded.fill(0) }
                    try { String(phrase, Charsets.UTF_8) } finally { phrase.fill(0) }
                },
            )
        } catch (error: CodedException) {
            promise.reject(error)
        }
    }

    private fun call(op: Int, body: ByteArray): ByteArray {
        if (op == 6) return core(6, body)
        if (op != 4 && op != 5) throw WalletException("bad_op")
        val issued = issued()
        for (start in 0 until (if (op == 4) 5 else 10) step 5) {
            if (body.size < start + 5) throw WalletException("bad_frame")
            if (body[start].toInt() == 2 && ByteBuffer.wrap(body, start + 1, 4).int.toUInt() >= issued.toUInt()) {
                throw WalletException("bounty_not_issued")
            }
        }
        if (op == 5 && body[5].toInt() != 1) throw WalletException("fee_payer_not_account")
        val seeded = seeded(body)
        return try { core(op, seeded) } finally { seeded.fill(0) }
    }

    private fun derive(index: Int): ByteArray {
        val seeded = seeded(byteArrayOf(2) + u32(index))
        return try { core(4, seeded) } finally { seeded.fill(0) }
    }

    private fun read(name: String): ByteArray? = try {
        MeshMessengerSecureStore.get(name.toByteArray())
    } catch (_: Exception) {
        throw WalletException("wallet_store_failed")
    }

    private fun write(name: String, value: ByteArray) {
        val key = name.toByteArray()
        val frame = u32(key.size) + key + value
        try {
            if (MeshMessengerSecureStore.put(frame) != 0) throw WalletException("wallet_store_failed")
        } finally {
            frame.fill(0)
        }
    }

    private fun entropy(): ByteArray = read(ENTROPY) ?: throw WalletException("wallet_missing")

    // vector32(seed) || rest, in one buffer; the caller wipes it.
    private fun seeded(rest: ByteArray): ByteArray {
        val entropy = entropy()
        return try {
            ByteBuffer.allocate(4 + entropy.size + rest.size).putInt(entropy.size).put(entropy).put(rest).array()
        } finally {
            entropy.fill(0)
        }
    }

    private fun issued(): Int = read(BOUNTY_INDEX)?.let {
        if (it.size != 4) throw WalletException("wallet_store_failed")
        ByteBuffer.wrap(it).int
    } ?: 0

    private fun storeNew(entropy: ByteArray) {
        read(ENTROPY)?.let {
            it.fill(0)
            throw WalletException("wallet_exists")
        }
        write(BOUNTY_INDEX, u32(0))
        write(ENTROPY, entropy)
    }

    private companion object {
        const val ENTROPY = "morse/wallet/entropy/v1"
        const val BOUNTY_INDEX = "morse/wallet/bounty-index/v1"
        const val CONFIRM_REQUEST = 0x4d57

        fun u32(value: Int): ByteArray = ByteBuffer.allocate(4).putInt(value).array()

        fun vec32(bytes: ByteArray): ByteArray =
            ByteBuffer.allocate(4 + bytes.size).putInt(bytes.size).put(bytes).array()

        fun vector(bytes: ByteArray, offset: Int): ByteArray {
            if (bytes.size < offset + 4) throw WalletException("bad_frame")
            val length = ByteBuffer.wrap(bytes, offset, 4).int
            if (length < 0 || bytes.size < offset + 4 + length) throw WalletException("bad_frame")
            return bytes.copyOfRange(offset + 4, offset + 4 + length)
        }

        // One wallet-core call on `1 || op || body`; the request is wiped before returning.
        fun core(op: Int, body: ByteArray): ByteArray {
            val request = ByteBuffer.allocate(2 + body.size).put(1).put(op.toByte()).put(body).array()
            return try {
                MorseWalletNative.call(request)
            } catch (error: IllegalStateException) {
                throw WalletException(error.message ?: "wallet_failed")
            } finally {
                request.fill(0)
            }
        }
    }
}

internal class WalletException(code: String) : CodedException(code, code, null)

internal object MorseWalletNative {
    init {
        System.loadLibrary("messenger_mobile")
    }

    // MorseWalletHost.cpp: wallet-core's morse_wallet_call; throws IllegalStateException
    // with wallet-core's error code.
    @JvmStatic external fun call(request: ByteArray): ByteArray
}
