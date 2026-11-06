package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator proof for profile-bound fanout and owned signed peers.
class FanoutProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "fanout-a.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val second = File(context.filesDir, "fanout-b.db").path.toByteArray()
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val body = hex(fields.optString("body"))
            val id = hex(fields.optString("id"))
            val value = when (fields.getString("operation")) {
                "create-a" -> MeshLibrary.create_account_export(vector(path) + vector("alice".toByteArray()))
                "create-b" -> MeshLibrary.create_account_export(vector(second) + vector("bob".toByteArray()))
                "replacement-a" -> MeshLibrary.create_account_export(vector(path) + vector("carol".toByteArray()))
                "profile-a" -> MeshLibrary.load_profile_export(path)
                "profile-b" -> MeshLibrary.load_profile_export(second)
                "entry-a" -> MeshLibrary.directory_entry_export(path)
                "entry-b" -> MeshLibrary.directory_entry_export(second)
                "fanout-a" -> MeshLibrary.fanout_send_export(vector(path) + vector(id) + body)
                "fanout-b" -> MeshLibrary.fanout_send_export(vector(second) + vector(id) + body)
                "outbox-a" -> MeshLibrary.outbox_list_export(path)
                "outbox-b" -> MeshLibrary.outbox_list_export(second)
                "initial-b" -> MeshLibrary.receive_initial_export(vector(second) + vector(body))
                "message-a" -> MeshLibrary.receive_message_export(vector(path) + vector(body))
                "message-b" -> MeshLibrary.receive_message_export(vector(second) + vector(body))
                "ack-a" -> MeshLibrary.outbox_ack_export(vector(path) + vector(body))
                "ack-b" -> MeshLibrary.outbox_ack_export(vector(second) + vector(body))
                "group-a" -> MeshLibrary.group_create_export(path)
                "invitations-a" -> MeshLibrary.group_invitations_export(path)
                "invitations-b" -> MeshLibrary.group_invitations_export(second)
                "discard-a" -> MeshLibrary.account_discard_export(vector(path) + vector(id))
                "history-b" -> MeshLibrary.load_history_export(vector(second) + vector(body))
                "bad-fanout" -> MeshLibrary.fanout_send_export(vector(path))
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
