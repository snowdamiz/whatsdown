package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator proof for account-bound journal exports and OS custody.
class JournalProofTest : InstrumentationTestCase() {
    private fun vector(value: ByteArray) = ByteBuffer.allocate(4 + value.size).putInt(value.size).put(value).array()
    private fun packet(vararg fields: ByteArray): ByteArray {
        val result = ByteBuffer.allocate(4 + fields.sumOf { 4 + it.size }).putInt(fields.size)
        fields.forEach { result.putInt(it.size).put(it) }
        return result.array()
    }
    private fun hex(value: String): ByteArray {
        require(value.length <= 1200000 && value.length % 2 == 0)
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    fun testCommand() {
        val context = instrumentation.targetContext
        MeshMessengerSecureStore.install(context)
        MeshMessengerPushMaterial.install(context)
        MeshLibrary.ensureInitialized()
        assertEquals(0, MeshMessengerHost.registerHostCallbacks())
        val path = File(context.filesDir, "journal-proof.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val body = hex(fields.optString("body"))
            val id = hex(fields.optString("id"))
            val value = when (fields.getString("operation")) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector(if (body.isEmpty()) "account_a".toByteArray() else body))
                "profile" -> MeshLibrary.load_profile_export(path)
                "discard" -> MeshLibrary.account_discard_export(vector(path) + vector(id))
                "read" -> MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector("read-state/index".toByteArray()))
                "write" -> MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector("read-state/index".toByteArray()) + vector(body))
                "bad-load" -> MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector("read-state/index".toByteArray()) + byteArrayOf(0))
                "bad-write" -> MeshLibrary.journal_save_bound_export(vector(path) + vector(id))
                "bad-key" -> MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector("profile/v1".toByteArray()) + vector(body))
                "preview" -> MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector("preferences/notification-preview".toByteArray()) + vector(body))
                "read-preview" -> MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector("preferences/notification-preview".toByteArray()))
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
