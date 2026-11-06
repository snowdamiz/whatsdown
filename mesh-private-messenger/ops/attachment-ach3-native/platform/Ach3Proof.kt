package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Isolated terminal-driven ACH3 native proof. Only fixture-owned accounts and content.
class Ach3ProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "ach3.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val second = File(context.filesDir, "legacy.db").path.toByteArray()
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val body = hex(fields.optString("body"))
            val id = hex(fields.optString("id"))
            val value = when (fields.getString("operation")) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector("ach3_fixture".toByteArray()))
                "create-other" -> MeshLibrary.create_account_export(vector(second) + vector("legacy_fixture".toByteArray()))
                "erase-other" -> MeshLibrary.erase_account_export(second)
                "erase" -> MeshLibrary.erase_account_export(path)
                "install" -> MeshLibrary.install_fixture(packet(path,body))
                "install-other" -> MeshLibrary.install_fixture(packet(second,body))
                "ticket" -> MeshLibrary.fixture_ticket(packet(path))
                "ticket-other" -> MeshLibrary.fixture_ticket(packet(second))
                "require" -> MeshLibrary.fixture_require(packet(path,body))
                "require-other" -> MeshLibrary.fixture_require(packet(second,body))
                "free-prepare" -> MeshLibrary.attachment_prepare_export(vector(path) + vector("free-fixture.bin".toByteArray()) + vector("application/octet-stream".toByteArray()) + vector(body) + vector(byteArrayOf(0,0,0,1)))
                "free-seal" -> MeshLibrary.attachment_seal_chunk_export(vector(path) + vector(body) + vector(id) + vector(ByteArray(if (id.contentEquals(byteArrayOf(0,0,0,0))) 65536 else 1) {37}))
                "free-upload" -> MeshLibrary.attachment_upload_export(packet(path,"free-upload.bin".toByteArray(),"application/octet-stream".toByteArray(),ByteArray(65537) {37},body))
                "free-upload-other" -> MeshLibrary.attachment_upload_export(packet(second,"free-upload.bin".toByteArray(),"application/octet-stream".toByteArray(),ByteArray(65537) {37},body))
                "free-upload-one" -> MeshLibrary.attachment_upload_export(packet(path,"free-upload.bin".toByteArray(),"application/octet-stream".toByteArray(),ByteArray(1) {37},body))
                "old-upload" -> MeshLibrary.attachment_upload_export(packet(path,"old.bin".toByteArray(),"application/octet-stream".toByteArray(),byteArrayOf(37)))
                "preview" -> MeshLibrary.credit_attachment_preview_export(packet(path,body))
                "prepare" -> MeshLibrary.credit_attachment_prepare_export(packet(path,id,"paid-fixture.bin".toByteArray(),"application/octet-stream".toByteArray(),byteArrayOf(1,0,0,1),body))
                "prepare-other" -> MeshLibrary.credit_attachment_prepare_export(packet(second,id,"paid-fixture.bin".toByteArray(),"application/octet-stream".toByteArray(),byteArrayOf(1,0,0,1),body))
                "old-prepare" -> MeshLibrary.credit_attachment_prepare_export(packet(path,id,"old.bin".toByteArray(),"application/octet-stream".toByteArray(),byteArrayOf(1,0,0,1)))
                "inventory" -> MeshLibrary.credit_attachments_export(packet(path))
                "inventory-other" -> MeshLibrary.credit_attachments_export(packet(second))
                "reference" -> MeshLibrary.paid_reference(packet(path,id))
                "paid-seal" -> MeshLibrary.credit_attachment_part_export(packet(path,id,body,ByteArray(if (body.contentEquals(byteArrayOf(0,0,0,0))) 65536 else 1) {37}))
                "paid-recover" -> MeshLibrary.credit_attachment_part_recover_export(packet(path,id,body))
                "fetch" -> MeshLibrary.attachment_fetch_chunk_export(packet(path,body,id))
                "alternate" -> MeshLibrary.alternate_reference(packet(path,body))
                "legacy" -> MeshLibrary.legacy_fixture(packet(path,body))
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
