package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator proof. All credit policy, cryptography, persistence and HTTP
// execute through the compiled production Mesh exports and JNI/OS callbacks.
class CreditProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "credit-proof.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val id = hex(fields.optString("id"))
            val body = hex(fields.optString("body"))
            val value = when (fields.getString("operation")) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector("native-lightning".toByteArray()))
                "discover" -> MeshLibrary.credit_discover_online_export(packet(path))
                "continue" -> MeshLibrary.credit_purchase_continue_export(packet(path, id))
                "admit" -> MeshLibrary.credit_admit_export(packet(path, body))
                "prepare" -> MeshLibrary.credit_prepare_export(packet(path, byteArrayOf(0, 0, 0, 100), byteArrayOf(2)))
                "quote" -> MeshLibrary.credit_quote_export(packet(path, id, body))
                "handoff" -> MeshLibrary.credit_payment_handoff_export(packet(path, id))
                "recover" -> MeshLibrary.credit_recover_export(packet(path, id))
                "finalize" -> MeshLibrary.credit_finalize_export(packet(path, id, body))
                "balance" -> MeshLibrary.credit_balance_export(packet(path))
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
