package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator harness: production Mesh performs HTTP and authenticates chunks.
class AttachmentProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "attachment-proof.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val body = hex(fields.optString("body"))
            val id = hex(fields.optString("id"))
            val value = when (fields.getString("operation")) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector("native-attachments".toByteArray()))
                "upload" -> {
                    require(body.size == 4)
                    val size = ByteBuffer.wrap(body).int
                    require(size in 1..16777216)
                    MeshLibrary.attachment_upload_export(packet(path, "fixture.bin".toByteArray(), "application/octet-stream".toByteArray(), ByteArray(size) { 37 }))
                }
                "read_all" -> {
                    require(id.size == 4)
                    val count = ByteBuffer.wrap(id).int
                    require(count in 1..256)
                    val digest = MessageDigest.getInstance("SHA-256")
                    var total = 0L
                    repeat(count) { index ->
                        val chunk = MeshLibrary.attachment_fetch_chunk_export(packet(path, body, ByteBuffer.allocate(4).putInt(index).array()))
                        require(chunk.isNotEmpty() && chunk.size <= 65536)
                        digest.update(chunk)
                        total += chunk.size
                    }
                    ByteBuffer.allocate(40).putLong(total).put(digest.digest()).array()
                }
                "discard" -> MeshLibrary.attachment_discard_export(packet(path, body))
                "erase" -> MeshLibrary.erase_account_export(path)
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
