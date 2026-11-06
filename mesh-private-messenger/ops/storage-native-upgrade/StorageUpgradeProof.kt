package expo.modules.meshmessenger

import android.database.sqlite.SQLiteDatabase
import android.test.InstrumentationTestCase
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import mesh.MeshLibrary
import org.json.JSONArray
import org.json.JSONObject

// Owned native upgrade fixture. Account/journal operations use the unchanged
// production ABI and Android Keystore. SQLite inspection is read-only.
class StorageUpgradeProofTest : InstrumentationTestCase() {
    private fun vector(value: ByteArray) = ByteBuffer.allocate(4 + value.size).putInt(value.size).put(value).array()
    private fun hex(value: String): ByteArray {
        require(value.length <= 100000 && value.length % 2 == 0)
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun encoded(value: ByteArray) = value.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun digest(value: ByteArray) = encoded(MessageDigest.getInstance("SHA-256").digest(value))
    private fun inspect(path: File): ByteArray {
        val result = JSONObject()
        SQLiteDatabase.openDatabase(path.path, null, SQLiteDatabase.OPEN_READONLY).use { database ->
            database.rawQuery("SELECT sql FROM sqlite_master WHERE name = 'encrypted_blobs'", null).use { cursor ->
                require(cursor.moveToFirst())
                result.put("schema", cursor.getString(0))
            }
            val columns = JSONArray()
            database.rawQuery("PRAGMA table_info(encrypted_blobs)", null).use { cursor ->
                while (cursor.moveToNext()) columns.put(cursor.getString(1))
            }
            result.put("columns", columns)
            val records = JSONArray()
            database.rawQuery("SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash", null).use { cursor ->
                while (cursor.moveToNext()) records.put(JSONObject()
                    .put("index", cursor.getString(0)).put("ciphertext_sha256", digest(cursor.getBlob(1))))
            }
            result.put("records", records)
            val indexExists = database.rawQuery("SELECT name FROM sqlite_master WHERE name = 'encrypted_blob_index'", null).use { it.moveToFirst() }
            val versions = JSONArray()
            if (indexExists) database.rawQuery("SELECT version FROM encrypted_blob_index", null).use { cursor ->
                while (cursor.moveToNext()) versions.put(cursor.getLong(0))
            }
            result.put("index_versions", versions)
            var rowidAvailable = true
            try { database.rawQuery("SELECT rowid FROM encrypted_blobs LIMIT 1", null).use { it.moveToFirst() } }
            catch (_: android.database.sqlite.SQLiteException) { rowidAvailable = false }
            result.put("rowid_available", rowidAvailable)
        }
        return result.toString().toByteArray()
    }
    fun testCommand() {
        val context = instrumentation.targetContext
        MeshMessengerSecureStore.install(context)
        MeshMessengerPushMaterial.install(context)
        MeshLibrary.ensureInitialized()
        assertEquals(0, MeshMessengerHost.registerHostCallbacks())
        val database = File(context.filesDir, "storage-upgrade-proof.db")
        val path = database.path.toByteArray()
        val command = File(context.filesDir, "command.json")
        val fields = JSONObject(command.readText())
        command.delete()
        val result = JSONObject()
        try {
            val operation = fields.getString("operation")
            val body = hex(fields.optString("body"))
            val id = hex(fields.optString("id"))
            // Inspection cannot itself invoke the migration being tested.
            if (operation != "inspect") MeshLibrary.initialize(path)
            val value = when (operation) {
                "create" -> MeshLibrary.create_account_export(vector(path) + vector("owned-storage-upgrade".toByteArray()))
                "profile" -> MeshLibrary.load_profile_export(path)
                "foreign-profile" -> {
                    val other = File(context.filesDir, "other-owned-account.db").path.toByteArray()
                    MeshLibrary.initialize(other)
                    MeshLibrary.create_account_export(vector(other) + vector("other-owned-account".toByteArray()))
                    MeshLibrary.load_profile_export(other)
                }
                "write" -> MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + body)
                "read" -> MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector(body))
                "inspect" -> inspect(database)
                else -> error("invalid_proof_operation")
            }
            result.put("result", "passed").put("body", encoded(value))
        } catch (error: Exception) {
            result.put("result", "rejected").put("error", error.toString())
        }
        File(context.filesDir, "response.json").writeText(result.toString())
    }
}
