package expo.modules.meshmessenger

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object MeshMessengerSecureStore {
    private const val ALIAS = "app.whatsdown.mesh.storage.v1"
    private const val PREFERENCES = "mesh_messenger_secure_store"
    private const val OK = 0
    private const val INVALID_INPUT = 1
    private const val PLATFORM_FAILURE = 3
    private const val MAX_KEY_BYTES = 4096

    @Volatile private var context: Context? = null

    fun install(value: Context) {
        context = value.applicationContext
    }

    @JvmStatic
    @Synchronized
    fun put(input: ByteArray): Int {
        if (input.size < 5) return INVALID_INPUT
        val keyLength = ByteBuffer.wrap(input, 0, 4).int
        if (keyLength !in 1..MAX_KEY_BYTES || keyLength >= input.size - 4) return INVALID_INPUT

        return try {
            val key = input.copyOfRange(4, 4 + keyLength)
            val value = input.copyOfRange(4 + keyLength, input.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
            val encrypted = byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + cipher.doFinal(value)
            if (preferences().edit().putString(keyName(key), Base64.encodeToString(encrypted, Base64.NO_WRAP)).commit()) {
                OK
            } else {
                PLATFORM_FAILURE
            }
        } catch (_: Exception) {
            PLATFORM_FAILURE
        }
    }

    @JvmStatic
    @Synchronized
    fun get(key: ByteArray): ByteArray? {
        require(key.isNotEmpty() && key.size <= MAX_KEY_BYTES)
        val encoded = preferences().getString(keyName(key), null) ?: return null
        val encrypted = Base64.decode(encoded, Base64.NO_WRAP)
        require(encrypted.isNotEmpty())
        val ivLength = encrypted[0].toInt() and 0xff
        require(ivLength in 12..32 && encrypted.size > ivLength + 1)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            encryptionKey(),
            GCMParameterSpec(128, encrypted, 1, ivLength),
        )
        return cipher.doFinal(encrypted, ivLength + 1, encrypted.size - ivLength - 1)
    }

    @JvmStatic
    @Synchronized
    fun delete(key: ByteArray): Int {
        if (key.isEmpty() || key.size > MAX_KEY_BYTES) return INVALID_INPUT
        return try {
            if (preferences().edit().remove(keyName(key)).commit()) OK else PLATFORM_FAILURE
        } catch (_: Exception) {
            PLATFORM_FAILURE
        }
    }

    private fun preferences() = requireNotNull(context) { "Secure store is not installed" }
        .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    private fun keyName(key: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest(key)
        .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }
}
