package expo.modules.meshmessenger

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import expo.modules.kotlin.Promise
import expo.modules.kotlin.functions.Queues
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

// App lock (apps/mobile/src/LockGate.tsx): the device's biometrics or screen lock
// before Morse shows anything. FLAG_SECURE already keeps the window out of
// recents and screenshots (MeshMessengerScreenSecurity). The same confirmation
// as the wallet's recovery phrase (MorseWalletModule). The API is
// apps/mobile/modules/mesh-messenger/lock.ts.
class MorseLockModule : Module() {
    private var confirming: Promise? = null

    override fun definition() = ModuleDefinition {
        Name("MorseLock")

        // A device without a screen lock has nothing to ask for, so it can't offer the lock.
        AsyncFunction("lockAvailable") {
            val context = appContext.reactContext ?: return@AsyncFunction false
            (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure
        }

        // Whether the owner unlocked. A device whose screen lock was removed since the
        // lock was turned on opens: there is no owner check left to make.
        AsyncFunction("lockAuthenticate") { reason: String, promise: Promise -> confirm(reason, promise) }
            .runOnQueue(Queues.MAIN)

        // Screen-lock confirmation on Android 6-9, before BiometricPrompt could offer it.
        OnActivityResult { _, payload ->
            if (payload.requestCode != CONFIRM_REQUEST) return@OnActivityResult
            val promise = confirming ?: return@OnActivityResult
            confirming = null
            promise.resolve(payload.resultCode == Activity.RESULT_OK)
        }
    }

    private fun confirm(reason: String, promise: Promise) {
        val activity = appContext.currentActivity ?: return promise.resolve(false)
        val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isDeviceSecure) return promise.resolve(true)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            @Suppress("DEPRECATION")
            val intent = keyguard.createConfirmDeviceCredentialIntent("Unlock Morse", reason)
                ?: return promise.resolve(true)
            confirming = promise
            @Suppress("DEPRECATION")
            activity.startActivityForResult(intent, CONFIRM_REQUEST)
            return
        }
        val builder = BiometricPrompt.Builder(activity).setTitle("Unlock Morse").setSubtitle(reason)
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
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = promise.resolve(true)
                override fun onAuthenticationError(code: Int, message: CharSequence) = promise.resolve(false)
            },
        )
    }

    private companion object {
        const val CONFIRM_REQUEST = 0x4c4b
    }
}
