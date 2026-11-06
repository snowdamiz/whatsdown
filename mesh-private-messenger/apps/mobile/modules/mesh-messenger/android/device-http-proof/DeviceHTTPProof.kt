package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary
import org.json.JSONObject

// Owned emulator proof for production account HTTP exports and OS custody. No screen capture.
class DeviceHTTPProofTest : InstrumentationTestCase() {
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
        val path = File(context.filesDir, "device-http-proof.db").path.toByteArray()
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
                "resolve" -> MeshLibrary.directory_resolve_export(vector(path) + vector(body))
                "authorize" -> {
                    val parts = JSONObject(String(body, Charsets.UTF_8))
                    MeshLibrary.authorize_device_link_for_set_export(vector(path) + vector(hex(parts.getString("devices"))) + vector(hex(parts.getString("pending"))))
                }
                "renew" -> MeshLibrary.devices_renew_export(vector(path) + vector(body))
                "revoke" -> MeshLibrary.device_revoke_export(vector(path) + vector(body) + vector(id))
                "register" -> MeshLibrary.directory_register_export(path)
                "prekeys" -> MeshLibrary.prekeys_synchronize_export(path)
                "profile" -> MeshLibrary.load_profile_export(path)
                "capabilities" -> MeshLibrary.account_capabilities_export(vector(path) + vector(id))
                "delete" -> MeshLibrary.account_delete_export(vector(path) + vector(id))
                "discard" -> MeshLibrary.account_discard_export(vector(path) + vector(id))
                "bad-capabilities" -> MeshLibrary.account_capabilities_export(vector(path) + vector(id) + byteArrayOf(0))
                "bad-delete" -> MeshLibrary.account_delete_export(vector(path))
                "bad-renew" -> MeshLibrary.devices_renew_export(vector(path))
                "bad-revoke" -> MeshLibrary.device_revoke_export(vector(path) + vector(byteArrayOf(1)) + vector(ByteArray(15) { 2 }))
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", value.joinToString("") { "%02x".format(it.toInt() and 255) })
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
