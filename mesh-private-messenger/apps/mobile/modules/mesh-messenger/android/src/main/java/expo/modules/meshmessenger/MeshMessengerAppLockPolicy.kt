package expo.modules.meshmessenger

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

internal interface MeshMessengerAppLockPolicyPort {
    fun load(): MeshMessengerAppLockPolicy.Record
    fun transition(previous: MeshMessengerAppLockPolicy.Record, desired: String): MeshMessengerAppLockPolicy.Record
}

/** Separate installation policy. Never touches Mesh/account/wallet key labels. */
internal class MeshMessengerAppLockPolicy(private val context: Context) : MeshMessengerAppLockPolicyPort {
    data class Record(val install: String, val sequence: Long, val policy: String)
    private val folder = File(context.noBackupFilesDir, "morse-app-lock-v1")
    private val file = AtomicFile(File(folder, "policy.aead"))
    private val marker = AtomicFile(File(folder, "policy-initialized.v1"))
    private val alias = "app.morse.app-lock.policy.v1"
    private val magic = byteArrayOf(1, 77, 65, 76)
    private val aad = "morse-app-lock-policy-v1:${context.packageName}".toByteArray(Charsets.UTF_8)
    private val states = setOf("disabled", "enable_pending", "enabled", "disable_pending")

    @Synchronized override fun load(): Record {
        check(folder.exists() || folder.mkdirs()) { "policy_unreadable" }
        Os.chmod(folder.path, 448)
        val existing = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()
        if (!existing) {
            check(!marker.baseFile.exists() && !File(marker.baseFile.path+".bak").exists() && !File(marker.baseFile.path+".new").exists()) { "policy_unreadable" }
            check(!KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)) { "policy_unreadable" }
            // Marker FIRST: interruption before the first record is fail-closed.
            val first = Record(UUID.randomUUID().toString(), 0, "disabled")
            mark(first.install)
            return save(first, bootstrap = true)
        }
        val bytes = file.readFully()
        check(bytes.size in 33..4096 && bytes.copyOfRange(0, 4).contentEquals(magic)) { "policy_unreadable" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, bytes.copyOfRange(4, 16)))
        cipher.updateAAD(aad)
        val clear = cipher.doFinal(bytes.copyOfRange(16, bytes.size))
        val result = try { decode(clear) } finally { clear.fill(0) }
        if (!marker.baseFile.exists() && !File(marker.baseFile.path+".bak").exists() && !File(marker.baseFile.path+".new").exists()) mark(result.install)
        check(marker.readFully().contentEquals("AL1:${result.install}\n".toByteArray(Charsets.US_ASCII))) { "policy_unreadable" }
        return result
    }

    @Synchronized override fun transition(previous: Record, desired: String): Record {
        check(desired in states && previous.sequence < 9_007_199_254_740_990L &&
            desired in when(previous.policy) {
                "disabled" -> setOf("enable_pending")
                "enabled" -> setOf("disable_pending")
                "enable_pending" -> setOf("enabled","disable_pending")
                "disable_pending" -> setOf("disabled","enable_pending")
                else -> emptySet()
            }) { "policy_unreadable" }
        val actual = load()
        check(actual == previous) { "policy_changed" }
        return save(previous.copy(sequence = previous.sequence + 1, policy = desired), false)
    }

    private fun save(record: Record, bootstrap: Boolean): Record {
        check(record.policy in states && UUID.fromString(record.install).toString() == record.install) { "policy_unreadable" }
        val json = JSONObject().put("version", 1).put("install", record.install)
            .put("sequence", record.sequence).put("policy", record.policy).toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(bootstrap))
        cipher.updateAAD(aad)
        val sealed = try { cipher.doFinal(json) } finally { json.fill(0) }
        check(cipher.iv.size == 12) { "policy_unreadable" }
        val stream = file.startWrite()
        try {
            stream.write(magic); stream.write(cipher.iv); stream.write(sealed)
            file.finishWrite(stream)
            Os.chmod(file.baseFile.path, 384)
        } catch (error: Throwable) { file.failWrite(stream); throw error }
        // A reported success must survive the exact native decode/readback.
        val stored = file.readFully()
        val verify = Cipher.getInstance("AES/GCM/NoPadding")
        verify.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, stored.copyOfRange(4, 16)))
        verify.updateAAD(aad)
        val clear = verify.doFinal(stored.copyOfRange(16, stored.size))
        val actual = try { decode(clear) } finally { clear.fill(0) }
        check(actual == record) { "policy_unreadable" }
        return actual
    }

    private fun mark(install: String) {
        val stream = marker.startWrite()
        try { stream.write("AL1:$install\n".toByteArray(Charsets.US_ASCII)); marker.finishWrite(stream); Os.chmod(marker.baseFile.path, 384) }
        catch (error: Throwable) { marker.failWrite(stream); throw error }
    }

    private fun decode(bytes: ByteArray): Record {
        val value = JSONObject(bytes.toString(Charsets.UTF_8))
        check(value.keys().asSequence().toSet() == setOf("version", "install", "sequence", "policy") && value.opt("version") == 1) { "policy_unreadable" }
        val sequence = value.get("sequence")
        check(sequence is Int || sequence is Long) { "policy_unreadable" }
        val record = Record(value.get("install") as? String ?: error("policy_unreadable"), (sequence as Number).toLong(), value.get("policy") as? String ?: error("policy_unreadable"))
        check(UUID.fromString(record.install).toString() == record.install) { "policy_unreadable" }
        check(record.sequence in 0..9_007_199_254_740_990L && record.policy in states) { "policy_unreadable" }
        return record
    }

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        check(create) { "policy_unreadable" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
}
