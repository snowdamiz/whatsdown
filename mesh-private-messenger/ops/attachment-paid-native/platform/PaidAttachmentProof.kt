package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator proof. All credit policy, cryptography, persistence and HTTP
// execute through the compiled production Mesh exports and JNI/OS callbacks.
class PaidAttachmentProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "paid-attachment-proof.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val id = hex(fields.optString("id"))
            val body = hex(fields.optString("body"))
            val value = when (fields.getString("operation")) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector(if (body.isEmpty()) "native-postage".toByteArray() else body))
                "register" -> MeshLibrary.directory_register_export(path)
                "profile" -> MeshLibrary.load_profile_export(path)
                "resolve" -> MeshLibrary.directory_resolve_export(vector(path) + vector(body))
                "fanout" -> MeshLibrary.fanout_send_export(vector(path) + vector(id) + body)
                "outbox" -> MeshLibrary.outbox_list_export(path)
                "drain" -> MeshLibrary.outbox_drain_export(vector(path) + vector(body))
                "postage-candidate" -> MeshLibrary.credit_postage_candidate_export(packet(path, id))
                "postage-preview" -> MeshLibrary.credit_postage_preview_export(ByteBuffer.allocate(4).putInt(3).array() + vector(path) + body)
                "postage-prepare" -> MeshLibrary.credit_postage_prepare_export(ByteBuffer.allocate(4).putInt(4).array() + vector(path) + body)
                "postage-recover" -> MeshLibrary.credit_postage_recover_export(packet(path, id))
                "postage-continue" -> MeshLibrary.credit_postage_continue_export(packet(path, id))
                "postage-inventory" -> MeshLibrary.credit_postage_inventory_export(packet(path))
                "retention" -> MeshLibrary.credit_retention_export(packet(path, body))
                "retention-recover" -> MeshLibrary.credit_retention_recover_export(packet(path, id))
                "action" -> MeshLibrary.credit_action_continue_export(packet(path, id, body))
                "discover" -> MeshLibrary.credit_discover_online_export(packet(path))
                "continue" -> MeshLibrary.credit_purchase_continue_export(packet(path, id))
                "admit" -> MeshLibrary.credit_admit_export(packet(path, body))
                "prepare" -> MeshLibrary.credit_prepare_export(packet(path, byteArrayOf(0, 0, 0, 100), byteArrayOf(2)))
                "quote" -> MeshLibrary.credit_quote_export(packet(path, id, body))
                "handoff" -> MeshLibrary.credit_payment_handoff_export(packet(path, id))
                "recover" -> MeshLibrary.credit_recover_export(packet(path, id))
                "finalize" -> MeshLibrary.credit_finalize_export(packet(path, id, body))
                "balance" -> MeshLibrary.credit_balance_export(packet(path))
                "authorize" -> MeshLibrary.fanout_send_export(vector(path) + vector(id) + vector(body) + vector(byteArrayOf(4)) + vector(byteArrayOf()) + vector(byteArrayOf()) + vector(byteArrayOf()))
                "attachment-preview" -> MeshLibrary.credit_attachment_preview_export(packet(path,byteArrayOf(1,0,0,1)))
                "attachment-prepare" -> MeshLibrary.credit_attachment_prepare_export(packet(path,id,"owned-paid.bin".toByteArray(),"application/octet-stream".toByteArray(),byteArrayOf(1,0,0,1),body))
                "attachment-recover" -> MeshLibrary.credit_attachment_recover_export(packet(path,id))
                "attachment-inventory" -> MeshLibrary.credit_attachments_export(packet(path))
                "attachment-stage" -> {
                    val wireProfile=if(body.isEmpty()) 3 else body[0].toInt() and 255
                    require((body.isEmpty() || body.size==1) && wireProfile in 3..4)
                    var first=byteArrayOf(); var last=byteArrayOf()
                    for (index in 0 until 257) {
                        val wire=MeshLibrary.credit_attachment_part_export(packet(path,id,ByteBuffer.allocate(4).putInt(index).array(),ByteArray(if(index==256) 1 else 65536) {37}))
                        require(wire.copyOfRange(0,4).contentEquals(byteArrayOf(wireProfile.toByte(),65,67,72)))
                        require(wire.size==if(index==256 && wireProfile==3) 41 else 65576)
                        if(index==0) first=wire
                        if(index==256) last=wire
                    }
                    packet(first,last)
                }
                "attachment-grant" -> MeshLibrary.credit_attachment_grant_export(packet(path,id,body))
                "attachment-upload" -> MeshLibrary.credit_attachment_upload_export(packet(path,id,body))
                "attachment-upload-all" -> {
                    for(index in 0 until 258) MeshLibrary.credit_attachment_upload_export(packet(path,id,ByteBuffer.allocate(4).putInt(index).array()))
                    byteArrayOf(0,0,1,2)
                }
                "attachment-complete" -> MeshLibrary.credit_attachment_complete_export(packet(path,id))
                "attachment-delete" -> MeshLibrary.credit_attachment_delete_export(packet(path,id))
                "fetch" -> MeshLibrary.attachment_fetch_chunk_export(packet(path,body,id))
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            val detail = error.message ?: error.toString()
            // The generated JNI binding formats application status 9, whereas
            // Swift exposes its payload as Data. Normalize only that known ABI
            // status; host/argument/panic errors must retain their distinct text.
            result.put("result", "rejected").put("raw_error", detail)
                .put("error", detail.removePrefix("Mesh library call failed (status=9): "))
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
