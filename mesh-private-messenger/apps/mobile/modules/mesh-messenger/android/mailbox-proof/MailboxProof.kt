package expo.modules.meshmessenger

import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import mesh.MeshLibrary

class MailboxProofTest : InstrumentationTestCase() {
    private fun packet(vararg fields: ByteArray): ByteArray {
        val output = ByteBuffer.allocate(4 + fields.sumOf { 4 + it.size }).putInt(fields.size)
        fields.forEach { output.putInt(it.size).put(it) }
        return output.array()
    }
    private fun expectFailure(block: () -> Unit) {
        try { block(); fail("native boundary accepted an invalid session") }
        catch (expected: IllegalStateException) { assertTrue(expected.message.orEmpty().contains("mailbox")) }
    }
    fun testSignedNativeMailboxSession() {
        val context = instrumentation.targetContext
        MeshMessengerSecureStore.install(context)
        MeshMessengerPushMaterial.install(context)
        MeshLibrary.ensureInitialized()
        assertEquals(0, MeshMessengerHost.registerHostCallbacks())
        val path = File(context.filesDir, "mailbox-proof.db").path.toByteArray()
        MeshLibrary.initialize(path)
        val request = ByteBuffer.allocate(8 + path.size + 5).putInt(path.size).put(path).putInt(5).put("alice".toByteArray()).array()
        MeshLibrary.create_account_export(request)
        val entry = MeshLibrary.directory_entry_export(path)
        File(context.filesDir, "profile-entry.hex").writeText(entry.joinToString("") { "%02x".format(it.toInt() and 255) })
        val ready = File(context.filesDir, "server-ready")
        val deadline = System.currentTimeMillis() + 120000
        while (!ready.exists() && System.currentTimeMillis() < deadline) Thread.sleep(50)
        assertTrue("owned peer did not start", ready.exists())
        // A real Java exception in secure-store get must become a recoverable
        // native error. Restore only the original OS-sealed test records.
        val preferences = context.getSharedPreferences("mesh_messenger_secure_store", 0)
        val sealed = preferences.all.mapValues { it.value as String }
        assertTrue(sealed.isNotEmpty())
        try {
            val corrupt = preferences.edit()
            sealed.keys.forEach { corrupt.putString(it, "!") }
            assertTrue(corrupt.commit())
            try { MeshLibrary.mailbox_stream_open_export(path); fail("corrupt secure store accepted") }
            catch (expected: IllegalStateException) { assertTrue(expected.message.orEmpty().contains("secure_storage_unavailable")) }
        } finally {
            val restore = preferences.edit()
            sealed.forEach { (key, value) -> restore.putString(key, value) }
            assertTrue(restore.commit())
        }
        MeshMessengerHost.unregisterHostCallbacks()
        try { MeshLibrary.mailbox_stream_open_export(path); fail("unregistered callbacks accepted") }
        catch (expected: IllegalStateException) { assertTrue(expected.message.orEmpty().contains("network_configuration_required")) }
        assertEquals(0, MeshMessengerHost.registerHostCallbacks())
        val first = MeshLibrary.mailbox_stream_open_export(path)
        assertEquals(32, first.size)
        assertEquals("ready", MeshLibrary.mailbox_stream_poll_export(packet(path, first)).toString(Charsets.UTF_8))
        assertEquals("encrypted-wakeup", MeshLibrary.mailbox_stream_poll_export(packet(path, first)).toString(Charsets.UTF_8))
        val second = MeshLibrary.mailbox_stream_open_export(path)
        assertFalse(first.contentEquals(second))
        expectFailure { MeshLibrary.mailbox_stream_poll_export(packet(path, first)) }
        expectFailure { MeshLibrary.mailbox_stream_poll_export(packet("other.db".toByteArray(), second)) }
        expectFailure { MeshLibrary.mailbox_stream_poll_export(packet(path, second) + byteArrayOf(1)) }
        assertEquals("ready", MeshLibrary.mailbox_stream_poll_export(packet(path, second)).toString(Charsets.UTF_8))
        MeshLibrary.mailbox_stream_close_export(packet(path, second))
        expectFailure { MeshLibrary.mailbox_stream_poll_export(packet(path, second)) }
        val erased = MeshLibrary.mailbox_stream_open_export(path)
        MeshLibrary.erase_account_export(path)
        expectFailure { MeshLibrary.mailbox_stream_poll_export(packet(path, erased)) }
        File(context.filesDir, "result.json").writeText("{\"result\":\"passed\",\"exports\":3,\"signed_sessions\":3,\"java_exception_recovered\":true,\"callback_reregistration\":true}")
    }
}
