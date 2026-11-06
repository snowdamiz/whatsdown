package expo.modules.meshmessenger

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.SystemClock
import android.provider.OpenableColumns
import android.system.Os
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Only owned opaque handles cross JS. No caller path/URI or persistent picker grant. */
internal object MeshMessengerProtectedFiles {
    private const val CHUNK = 65_536
    private const val LARGE = 536_870_912L
    private const val SMALL = 16_777_216
    private const val BACKUP = 16_796_864L
    private const val BACKUP_NAME = "morse-backup.morsebackup"
    private const val BACKUP_MIME = "application/octet-stream"
    private val random = SecureRandom()
    private val handles = ConcurrentHashMap<String, Resource>()
    private val choices = ConcurrentHashMap<String, Choice>()
    private val picker = AtomicReference<Picker?>(null)
    private val cleanup = Executors.newSingleThreadExecutor()
    private val selectionWorker = Executors.newSingleThreadExecutor()
    private val admission = Any()
    private lateinit var app: Application
    private lateinit var root: File
    private class ProfileBinding(val profile: (String) -> ByteArray, val documents: File)
    private val profileBinding = AtomicReference<ProfileBinding?>(null)
    private var nextPickerCode = 0x6000 // Never reused in this process.
    private data class Identity(val generation: Long, val account: String, val device: String)
    private data class Context(val purpose: String, val source: String = "", val name: String = "", val mime: String = "", val size: Long = 0)
    private data class Selection(val id: String, val uri: Uri, val name: String, val mime: String, val size: Long)
    private class Choice(val identity: Identity, val context: Context, val destination: Uri?, val files: List<Selection>, val requestId: String? = null) {
        val id = UUID.randomUUID().toString()
        val expires = SystemClock.elapsedRealtime() + 120_000
        val claimed = mutableSetOf<String>()
    }
    private class Picker(val activity: Activity, val identity: Identity, val context: Context, val code: Int, val requestId: String? = null) {
        val callbackClaimed = AtomicBoolean(false)
        val done = CountDownLatch(1)
        var result: Choice? = null
        @Volatile var failure: Throwable? = null
        @Volatile var cancelled = false
    }
    private data class BackupRequest(val identity: Identity, val context: Context, val expected: String, val expires: Long = SystemClock.elapsedRealtime() + 120_000)
    private val backupRequests = ConcurrentHashMap<String,BackupRequest>()
    private open class Resource(val epoch: String, val identity: Identity) {
        val id = UUID.randomUUID().toString()
        val closed = AtomicBoolean(false)
        val busy = ReentrantLock()
        val expires = SystemClock.elapsedRealtime() + 15 * 60_000
        open fun revoke() { closed.set(true) }
        open fun cleanup() = Unit
    }
    private class Source(epoch: String, identity: Identity, val selected: Selection, val descriptor: android.os.ParcelFileDescriptor, val context: Context? = null) : Resource(epoch, identity) {
        val input = FileInputStream(descriptor.fileDescriptor)
        override fun cleanup() { runCatching { input.close() }; runCatching { descriptor.close() } }
    }
    private class Preview(epoch: String, identity: Identity, val file: File) : Resource(epoch, identity) {
        override fun cleanup() { if (file.exists()) check(file.delete()) { "preview_cleanup_failed" } }
    }
    private class Export(epoch: String, identity: Identity, val context: Context, val destination: Uri, val file: File) : Resource(epoch, identity) {
        val key = AtomicReference<ByteArray?>(ByteArray(32).also(random::nextBytes))
        val prefix = ByteArray(4).also(random::nextBytes)
        val output = DataOutputStream(FileOutputStream(file))
        var written = 0L
        var count = 0
        var sealed = false
        // Length-delimited native-owned context. Caller digest alone is never authority.
        val contextHash = MessageDigest.getInstance("SHA-256").digest(packet(listOf("AL1-stage-v1", id,
            identity.generation.toString(), identity.account, identity.device, epoch, context.source,
            context.name, context.mime, context.size.toString())))
        override fun revoke() { super.revoke(); key.getAndSet(null)?.fill(0) }
        override fun cleanup() { runCatching { output.close() }; if (file.exists()) check(file.delete()) { "stage_cleanup_failed" } }
    }

    @Synchronized fun install(application: Application) {
        if (::app.isInitialized) return
        app = application
        root = File(app.noBackupFilesDir, "morse-app-lock-v1/protected")
        check(root.exists() || root.mkdirs()) { "protected_storage_unavailable" }; Os.chmod(root.path, 448)
    }
    fun bind(profile: (String) -> ByteArray, directory: File): () -> Unit {
        val binding = ProfileBinding(profile, directory)
        profileBinding.set(binding)
        return { profileBinding.compareAndSet(binding, null); Unit }
    }
    private fun boundProfile(expected: String): Pair<ProfileBinding, ByteArray> {
        val binding = checkNotNull(profileBinding.get()) { "protected_files_unavailable" }
        MeshMessengerAppLock.requireEpoch(expected)
        val bytes = binding.profile(expected)
        try {
            check(profileBinding.get() === binding) { "protected_files_unavailable" }
            MeshMessengerAppLock.requireEpoch(expected)
        } catch (error: Throwable) { bytes.fill(0); throw error }
        return binding to bytes
    }
    fun cleanOrphans() {
        check(handles.isEmpty()) { "protected_handles_active" }
        root.listFiles()?.forEach { check(it.isFile && it.delete()) { "protected_cleanup_failed" } }
    }
    fun revoke() {
        // Mark/erase authority first; descriptors and owned paths are disposed
        // off the UI thread. Cleanup never waits for a blocked provider to cover.
        handles.values.forEach { resource -> resource.revoke(); handles.remove(resource.id, resource); cleanup.execute { runCatching { resource.cleanup() } } }
        synchronized(admission) {
            val generation = MeshMessengerAppLock.accountGeneration()
            choices.entries.removeAll { it.value.identity.generation != generation || it.value.expires < SystemClock.elapsedRealtime() }
            backupRequests.entries.removeAll { it.value.identity.generation != generation || it.value.expires < SystemClock.elapsedRealtime() }
        }
    }
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun profileFields(bytes: ByteArray): List<ByteArray> {
        require(bytes.size in 16..36_134) { "invalid_profile" }
        val input = ByteBuffer.wrap(bytes)
        val fields = (0..3).map { index ->
            require(input.remaining() >= 4) { "invalid_profile" }; val length = input.int
            require(length >= 0 && length <= input.remaining() && length <= listOf(64,32,16,36_006)[index]) { "invalid_profile" }
            ByteArray(length).also { input.get(it) }
        }
        require(!input.hasRemaining() && fields[1].size == 32 && fields[2].size == 16) { "invalid_profile" }
        return fields
    }
    private fun identity(expected: String): Identity {
        MeshMessengerAppLock.requireEpoch(expected)
        val profile = boundProfile(expected).second
        val fields = try { profileFields(profile) } finally { profile.fill(0) }
        val result = Identity(MeshMessengerAppLock.accountGeneration(), hex(fields[1]), hex(fields[2]))
        fields.forEach { it.fill(0) }; MeshMessengerAppLock.requireEpoch(expected); return result
    }
    private fun requireResource(resource: Resource, expected: String) {
        MeshMessengerAppLock.requireEpoch(expected)
        check(resource.epoch == expected && !resource.closed.get() && resource.identity.generation == MeshMessengerAppLock.accountGeneration() &&
            resource.expires >= SystemClock.elapsedRealtime()) { "stale_file_handle" }
    }
    private inline fun <reified T : Resource, R> use(id: String, expected: String, body: (T) -> R): R {
        val resource = handles[id] as? T ?: error("invalid_file_handle")
        requireResource(resource, expected); check(resource.busy.tryLock()) { "file_operation_in_progress" }
        try { requireResource(resource, expected); return body(resource) } finally { resource.busy.unlock() }
    }
    private fun remember(resource: Resource) = synchronized(admission) {
        try {
            requireResource(resource, resource.epoch)
            check(handles.size < 4) { "protected_handle_limit" }
            handles[resource.id] = resource
            requireResource(resource, resource.epoch)
        } catch (error: Throwable) { handles.remove(resource.id); resource.revoke(); cleanup.execute { resource.cleanup() }; throw error }
    }
    private fun discard(id: String, expected: String) {
        val resource = handles[id] ?: return
        check(resource.epoch == expected) { "foreign_file_handle" }
        if (handles.remove(id, resource)) { resource.revoke(); cleanup.execute { runCatching { resource.cleanup() } } }
    }
    private fun checkedFrame(frame: String, keys: Set<String>): JSONObject {
        require(frame.toByteArray(Charsets.UTF_8).size <= 16_384) { "invalid_file_frame" }
        val value = JSONObject(frame)
        require(value.opt("version") == 1 && value.keys().asSequence().all { it == "version" || it in keys }) { "invalid_file_frame" }
        return value
    }
    private fun string(frame: JSONObject, key: String, max: Int = 4096): String = (frame.get(key) as? String)?.also {
        require(it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).size <= max && it.none { c -> c.code < 32 || c.code == 127 }) { "invalid_file_frame" }
    } ?: error("invalid_file_frame")
    private fun integer(frame: JSONObject, key: String): Long {
        val value = frame.get(key); require(value is Int || value is Long) { "invalid_file_frame" }; return (value as Number).toLong()
    }
    private fun id(frame: JSONObject, key: String = "handle") = string(frame, key, 36).also { require(UUID.fromString(it).toString() == it) { "invalid_file_handle" } }
    private fun json(vararg pairs: Pair<String, Any>) = JSONObject(mapOf("version" to 1, *pairs)).toString()
    private fun context(frame: JSONObject): Context {
        val purpose = string(frame, "purpose", 16)
        if (purpose == "avatar" || purpose == "attachment") return Context(purpose)
        if (purpose == "backup-source" || purpose == "backup-export") {
            require(listOf("sourceContext","filename","mimeType","size").none(frame::has)) { "invalid_file_frame" }
            return Context(purpose)
        }
        require(purpose == "export") { "invalid_file_purpose" }
        val name = string(frame, "filename", 255); require(name != "." && name != ".." && '/' !in name && '\\' !in name) { "invalid_attachment_name" }
        val mime = string(frame, "mimeType", 255); require(Regex("[-a-zA-Z0-9.+]+/[-a-zA-Z0-9.+]+").matches(mime)) { "invalid_attachment_mime" }
        val size = integer(frame,"size"); require(size in 1..LARGE) { "invalid_attachment_size" }
        return Context(purpose, string(frame,"sourceContext"), name, mime, size)
    }
    private fun backup(context: Context) = context.purpose == "backup-source" || context.purpose == "backup-export"
    private fun destination(context: Context) = context.purpose == "export" || context.purpose == "backup-export"
    private fun backupOwner(context: Context, expected: String) {
        if (backup(context)) { MeshMessengerAppLock.requireEpoch(expected);MeshMessengerAppLock.currentActivity() }
    }
    private fun backupSourceContext(frame: JSONObject, prefix: String, expected: String): String {
        val value=string(frame,"sourceContext");val parts=value.split('/')
        require(parts.size == 3 && parts[0] == prefix && parts[1] == expected && parts[2].matches(Regex("[1-9][0-9]{0,15}")) && (parts[2].toLongOrNull() ?: Long.MAX_VALUE) <= 9_007_199_254_740_991L) { "invalid_file_context" }
        return value
    }
    private fun backupExportContext(frame: JSONObject,expected: String): Context {
        val size=integer(frame,"size")
        require(string(frame,"purpose",16)=="backup-export" && string(frame,"filename",255)==BACKUP_NAME && string(frame,"mimeType",255)==BACKUP_MIME && size in 1..BACKUP) { "invalid_backup_export" }
        return Context("backup-export",backupSourceContext(frame,"backup-export",expected),BACKUP_NAME,BACKUP_MIME,size)
    }
    private fun backupRequest(frame: JSONObject,context: Context,expected: String): String? {
        if(!backup(context)) { require(!frame.has("requestId"));return null }
        val name=id(frame,"requestId");val owner=identity(expected)
        synchronized(admission) {
            val request=backupRequests[name] ?: error("invalid_file_request")
            check(request.identity==owner && request.context==context && request.expected==expected && request.expires>=SystemClock.elapsedRealtime()) { "stale_file_request" }
        }
        return name
    }
    private fun rememberChoice(choice: Choice) = synchronized(admission) {
        check(choice.identity.generation==MeshMessengerAppLock.accountGeneration()) { "stale_file_choice" }
        choice.requestId?.let { name ->
            val request=backupRequests[name] ?: error("cancelled_file_request")
            check(request.identity==choice.identity && request.context==choice.context && request.expires>=SystemClock.elapsedRealtime()) { "stale_file_request" }
        }
        check(choices.size < 4 && choices.values.none { it.identity==choice.identity && it.context==choice.context }) { "ambiguous_file_choice" }
        choices[choice.id]=choice;choice.requestId?.let(backupRequests::remove)
    }
    private fun choiceJSON(choice: Choice): String = synchronized(admission) {
        val fields=mutableListOf<Pair<String,Any>>("choiceId" to choice.id)
        choice.requestId?.let { fields.add("requestId" to it) }
        if(!destination(choice.context) && choice.context.purpose!="avatar") fields.add("files" to JSONArray(choice.files.filter { it.id !in choice.claimed }.map {
            JSONObject(mapOf("selectionId" to it.id,"filename" to it.name,"mimeType" to it.mime,"size" to it.size))
        }))
        json(*fields.toTypedArray())
    }
    private fun exactChoice(id: String, expected: String, context: Context? = null): Choice {
        val value = choices[id] ?: error("invalid_file_choice")
        check(value.expires >= SystemClock.elapsedRealtime() && value.identity == identity(expected) && (context == null || value.context == context)) { "stale_file_choice" }
        return value
    }
    fun dispatch(operation: String, frame: String, bytes: ByteArray, expected: String): Any {
        // Cleanup is deliberately non-authorizing and targets ONLY this epoch.
        if (operation in setOf("abortExport","releasePreview","closeSource","discardPreviews")) {
            require(bytes.isEmpty()) { "invalid_cleanup" }
            val value = checkedFrame(frame, if (operation == "discardPreviews") emptySet() else setOf("handle"))
            if (operation == "discardPreviews") handles.values.filter { it is Preview && it.epoch == expected }.forEach { discard(it.id, expected) }
            else {
                val handle = handles[id(value)]
                check(handle == null || when (operation) { "abortExport" -> handle is Export; "releasePreview" -> handle is Preview; else -> handle is Source }) { "invalid_cleanup" }
                discard(id(value), expected)
            }
            return json()
        }
        return MeshMessengerAppLock.scoped(expected) {
            when (operation) {
                "digest" -> { checkedFrame(frame, emptySet()); require(bytes.size in 1..SMALL); json("digest" to hex(MessageDigest.getInstance("SHA-256").digest(bytes))) }
                "pendingChoice", "chooseDestination", "chooseSource" -> {
                    require(bytes.isEmpty()); val value = checkedFrame(frame,setOf("purpose","sourceContext","filename","mimeType","size","requestId")); val context = context(value);backupOwner(context,expected)
                    if (operation == "pendingChoice") {
                        val owner = identity(expected)
                        choices.entries.removeAll { it.value.expires < SystemClock.elapsedRealtime() || it.value.identity.generation != owner.generation }
                        val matches = choices.values.filter { it.identity == owner && it.context == context }
                        check(matches.size <= 1) { "ambiguous_file_choice" }; matches.firstOrNull()?.let(::choiceJSON) ?: json()
                    } else {
                        check((operation == "chooseDestination") == destination(context)) { "invalid_file_purpose" }
                        choose(context, expected,backupRequest(value,context,expected))?.let(::choiceJSON) ?: json("cancelled" to true)
                    }
                }
                "beginBackupChoice" -> {
                    require(bytes.isEmpty());val value=checkedFrame(frame,setOf("purpose"));val context=context(value)
                    require(backup(context));backupOwner(context,expected);val owner=identity(expected);val name=UUID.randomUUID().toString()
                    synchronized(admission) {
                        val active=picker.get()?.requestId
                        backupRequests.entries.removeAll { it.value.identity.generation!=owner.generation || it.value.expires<SystemClock.elapsedRealtime() || (it.value.expected!=expected && it.key!=active) }
                        check(backupRequests.size<4) { "file_request_limit" };backupRequests[name]=BackupRequest(owner,context,expected)
                    }
                    json("requestId" to name)
                }
                "discardBackupChoice" -> {
                    require(bytes.isEmpty());val value=checkedFrame(frame,setOf("purpose","choiceId","requestId"));val context=context(value)
                    require(backup(context) && value.has("choiceId") != value.has("requestId"));backupOwner(context,expected);val owner=identity(expected)
                    if(value.has("requestId")) {
                        val name=id(value,"requestId")
                        val cancel=synchronized(admission) {
                            backupRequests[name]?.let { check(it.identity==owner && it.context==context) { "stale_file_request" } }
                            val selected=choices.values.filter { it.requestId==name };check(selected.all { it.identity==owner && it.context==context })
                            backupRequests.remove(name);selected.forEach { choices.remove(it.id,it) }
                            picker.get()?.takeIf { it.requestId==name && it.identity==owner && it.context==context }?.takeIf { picker.compareAndSet(it,null) }
                        }
                        cancel?.let { it.cancelled=true;it.failure=IllegalStateException("cancelled_file_request");it.done.countDown() }
                    } else {
                        val name=id(value,"choiceId")
                        synchronized(admission) { choices[name]?.let { check(it.identity==owner && it.context==context);choices.remove(name,it) } }
                    }
                    json()
                }
                "claimSource" -> {
                    require(bytes.isEmpty());val value=checkedFrame(frame,setOf("choiceId","selectionId","size","purpose","sourceContext"));val choice=exactChoice(id(value,"choiceId"),expected)
                    val binding=if(choice.context.purpose=="backup-source") {
                        backupOwner(choice.context,expected);require(string(value,"purpose",16)=="backup-source")
                        Context("backup-source",backupSourceContext(value,"backup-import",expected))
                    } else { require(!value.has("purpose") && !value.has("sourceContext"));null }
                    val selectionId=id(value,"selectionId")
                    val selected=synchronized(admission) {
                        check(choices[choice.id]===choice && (choice.context.purpose=="attachment" || choice.context.purpose=="backup-source"))
                        val selected=choice.files.singleOrNull { it.id==selectionId && it.id !in choice.claimed } ?: error("invalid_file_choice")
                        check(selected.size==integer(value,"size"));choice.claimed.add(selected.id);if(choice.claimed.size==choice.files.size)choices.remove(choice.id,choice);selected
                    }
                    val descriptor=app.contentResolver.openFileDescriptor(selected.uri,"r") ?: error("source_unavailable")
                    var source: Source?=null
                    try {
                        val opened=Source(expected,choice.identity,selected,descriptor,binding);source=opened
                        check(descriptor.statSize==selected.size) { "attachment_source_changed" };remember(opened)
                        json("handle" to opened.id,"size" to selected.size)
                    } catch(error:Throwable) { if(source!=null)source.cleanup() else descriptor.close();throw error }
                }
                "readSource" -> {
                    require(bytes.isEmpty()); val value = checkedFrame(frame,setOf("handle","offset","length"))
                    use<Source,ByteArray>(id(value),expected) { source ->
                        val offset = integer(value,"offset"); val length = integer(value,"length")
                        require(offset >= 0 && length in 1..CHUNK.toLong() && offset + length <= source.selected.size); check(source.descriptor.statSize == source.selected.size) { "attachment_source_changed" }
                        source.input.channel.position(offset); val result = ByteArray(length.toInt())
                        try { DataInputStream(source.input).readFully(result); requireResource(source,expected); check(source.descriptor.statSize == source.selected.size); result }
                        catch (error: Throwable) { result.fill(0); throw error }
                    }
                }
                "beginExport" -> {
                    require(bytes.isEmpty());val value=checkedFrame(frame,setOf("purpose","sourceContext","filename","mimeType","size","choiceId"))
                    val isBackup=value.optString("purpose")=="backup-export";val context=if(isBackup)backupExportContext(value,expected) else context(value)
                    backupOwner(context,expected)
                    val choice=exactChoice(id(value,"choiceId"),expected,if(isBackup)Context("backup-export") else context);check(destination(context) && choices.remove(choice.id,choice)) { "invalid_file_choice" }
                    val file = File(root,UUID.randomUUID().toString()); check(file.createNewFile()); Os.chmod(file.path,384)
                    val export = Export(expected,choice.identity,context,requireNotNull(choice.destination),file); remember(export); json("handle" to export.id)
                }
                "writeExport" -> {
                    val value = checkedFrame(frame,setOf("handle","offset"))
                    use<Export,String>(id(value),expected) { export ->
                        check(!export.sealed && export.count < 8192 && integer(value,"offset") == export.written && bytes.size in 1..CHUNK && export.written + bytes.size <= export.context.size) { "invalid_attachment_range" }
                        try {
                            val encrypted = crypt(export,Cipher.ENCRYPT_MODE,export.count,bytes.size,bytes)
                            try { requireResource(export,expected); export.output.writeInt(export.count); export.output.writeInt(bytes.size); export.output.writeInt(encrypted.size); export.output.write(encrypted) }
                            finally { encrypted.fill(0) }
                            requireResource(export,expected); export.written += bytes.size; export.count++; json()
                        } catch (error: Throwable) { discard(export.id,expected); throw error }
                    }
                }
                "commitExport" -> {
                    require(bytes.isEmpty()); val value = checkedFrame(frame,setOf("handle"))
                    use<Export,String>(id(value),expected) { export ->
                        check(!export.sealed && export.written == export.context.size) { "attachment_incomplete" }; export.sealed = true
                        try {
                            export.output.flush(); export.output.close()
                            scan(export,expected) { chunk -> chunk.fill(0) } // Complete prepass BEFORE opening destination.
                            MeshMessengerAppLock.publication(expected)
                            app.contentResolver.openOutputStream(export.destination,"w")?.use { output ->
                                scan(export,expected) { chunk ->
                                    try { requireResource(export,expected); MeshMessengerAppLock.publication(expected); output.write(chunk) }
                                    finally { chunk.fill(0) }
                                }
                                requireResource(export,expected); output.flush()
                            } ?: error("destination_unavailable")
                            requireResource(export,expected); json()
                        } finally { discard(export.id,expected) }
                    }
                }
                "writePreview" -> {
                    val value = checkedFrame(frame,setOf("key","mimeType")); string(value,"key",256); val mime = string(value,"mimeType",255)
                    require(mime in setOf("image/jpeg","image/png","image/webp","image/gif","image/avif","image/heic","image/heif") && bytes.size in 1..SMALL) { "invalid_preview" }
                    val file = File(root,UUID.randomUUID().toString()); val preview = Preview(expected,identity(expected),file); remember(preview)
                    try { check(file.createNewFile()); Os.chmod(file.path,384); FileOutputStream(file).use { it.write(bytes) }; requireResource(preview,expected); json("handle" to preview.id,"uri" to Uri.fromFile(file).toString()) }
                    catch (error: Throwable) { discard(preview.id,expected); throw error }
                }
                "importAvatar" -> {
                    require(bytes.isEmpty()); val value = checkedFrame(frame,setOf("purpose","choiceId")); check(string(value,"purpose",16) == "avatar")
                    val choice = exactChoice(id(value,"choiceId"),expected,Context("avatar")); check(choices.remove(choice.id,choice)); importAvatar(choice,expected)
                }
                else -> error("invalid_file_operation")
            }
        }
    }
    private fun packet(values: List<String>) = ByteArrayOutputStream().also { bytes -> DataOutputStream(bytes).use { out -> values.forEach { val value = it.toByteArray(Charsets.UTF_8); out.writeInt(value.size); out.write(value) } } }.toByteArray()
    private fun crypt(export: Export, mode: Int, index: Int, length: Int, bytes: ByteArray): ByteArray {
        val key = export.key.get()?.clone() ?: error("stale_file_handle")
        try {
            val nonce = ByteBuffer.allocate(12).put(export.prefix).putLong(index.toLong()).array()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(mode,SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
            cipher.updateAAD(export.contextHash + ByteBuffer.allocate(8).putInt(index).putInt(length).array()); return cipher.doFinal(bytes)
        } finally { key.fill(0) }
    }
    private fun scan(export: Export, expected: String, consume: (ByteArray) -> Unit) {
        DataInputStream(FileInputStream(export.file)).use { input ->
            var total = 0L
            repeat(export.count) { index ->
                requireResource(export,expected); check(input.readInt() == index) { "invalid_stage" }; val length = input.readInt(); val encryptedLength = input.readInt()
                check(length in 1..CHUNK && encryptedLength == length + 16 && total + length <= export.context.size) { "invalid_stage" }
                val encrypted = ByteArray(encryptedLength); input.readFully(encrypted)
                val chunk = try { crypt(export,Cipher.DECRYPT_MODE,index,length,encrypted) } finally { encrypted.fill(0) }
                try { check(chunk.size == length); requireResource(export,expected); consume(chunk) } finally { chunk.fill(0) }
                total += length
            }
            check(total == export.context.size && input.read() == -1) { "invalid_stage" }
        }
    }
    private fun choose(context: Context, expected: String,requestId: String? = null): Choice? {
        val activity = MeshMessengerAppLock.currentActivity(); val identity = identity(expected)
        val request = synchronized(admission) { check(nextPickerCode < 0x8000) { "picker_unavailable" }; Picker(activity,identity,context,nextPickerCode++,requestId) }
        check(picker.compareAndSet(null,request)) { "picker_in_progress" }
        try {
            activity.runOnUiThread {
                try {
                    MeshMessengerAppLock.requireEpoch(expected)
                    check(picker.get()===request && !request.cancelled) { "cancelled_file_request" }
                    val intent = if (destination(context)) Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(if(context.purpose=="backup-export")BACKUP_MIME else context.mime).putExtra(Intent.EXTRA_TITLE,if(context.purpose=="backup-export")BACKUP_NAME else context.name)
                    else Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(if (context.purpose == "avatar") "image/*" else "*/*").putExtra(Intent.EXTRA_ALLOW_MULTIPLE,context.purpose == "attachment")
                    activity.startActivityForResult(intent,request.code)
                } catch (error: Throwable) { request.failure = error; request.done.countDown() }
            }
            check(request.done.await(120,TimeUnit.SECONDS)) { "picker_timeout" }; request.failure?.let { throw it }
            return request.result
        } finally { picker.compareAndSet(request,null);requestId?.let(backupRequests::remove) }
    }
    fun activityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        val request=picker.get() ?: return false
        if(request.activity!==activity || request.code!=requestCode)return false
        if(!request.callbackClaimed.compareAndSet(false,true))return true
        val received=runCatching {
            val clip=data?.clipData
            if(backup(request.context) && clip!=null)check(clip.itemCount<=1) { "invalid_file_choice" }
            if(data==null)null else if(clip!=null)(0 until clip.itemCount).map { clip.getItemAt(it).uri } else listOfNotNull(data.data)
        }
        val complete={
            try {
                val uriList=received.getOrThrow()
                if(resultCode!=Activity.RESULT_OK || uriList==null)request.cancelled=true
                else {
                    check(request.identity.generation==MeshMessengerAppLock.accountGeneration()) { "stale_file_choice" }
                    check(uriList.isNotEmpty() && uriList.size<=(if(request.context.purpose=="attachment")10 else 1) && uriList.distinct().size==uriList.size && uriList.all { it.scheme=="content" }) { "invalid_file_choice" }
                    val files=if(destination(request.context))emptyList() else uriList.map { uri ->
                        var name:String?=null;var size=-1L
                        app.contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE),null,null,null)?.use { cursor -> if(cursor.moveToFirst()) { name=cursor.getString(0);if(!cursor.isNull(1))size=cursor.getLong(1) } }
                        val mime=app.contentResolver.getType(uri) ?: "application/octet-stream"
                        val bound=if(request.context.purpose=="avatar")20_971_520L else if(request.context.purpose=="backup-source")BACKUP else LARGE
                        check(size in 1..bound && name!=null && name!!.toByteArray(Charsets.UTF_8).size<=255 && mime.length<=255) { "invalid_attachment_size" }
                        Selection(UUID.randomUUID().toString(),uri,name!!,mime,size)
                    }
                    val choice=Choice(request.identity,request.context,if(destination(request.context))uriList.single() else null,files,request.requestId)
                    rememberChoice(choice);request.result=choice
                }
            } catch(error:Throwable) { request.failure=error }
            finally { request.done.countDown() }
        }
        if(backup(request.context))selectionWorker.execute(complete) else complete()
        return true
    }
    private fun importAvatar(choice: Choice, expected: String): String {
        val selected = choice.files.single(); check(selected.size <= 20_971_520)
        val bytes = app.contentResolver.openInputStream(selected.uri)?.use { input ->
            val output = ByteArrayOutputStream(); val chunk = ByteArray(CHUNK)
            try {
                while (true) { MeshMessengerAppLock.requireEpoch(expected); val count=input.read(chunk); if(count<0)break; check(count>0 && output.size()+count<=20_971_520) { "invalid_avatar" }; output.write(chunk,0,count) }
                val result=output.toByteArray(); check(result.size.toLong()==selected.size) { "attachment_source_changed" }; result
            } finally { chunk.fill(0) }
        } ?: error("source_unavailable")
        try {
            MeshMessengerAppLock.requireEpoch(expected)
            val bounds=BitmapFactory.Options().apply { inJustDecodeBounds=true }; BitmapFactory.decodeByteArray(bytes,0,bytes.size,bounds)
            check(bounds.outWidth in 1..40_000 && bounds.outHeight in 1..40_000) { "invalid_avatar" }
            var sample=1; while(bounds.outWidth/sample>4096 || bounds.outHeight/sample>4096)sample*=2
            var image=BitmapFactory.decodeByteArray(bytes,0,bytes.size,BitmapFactory.Options().apply { inSampleSize=sample }) ?: error("invalid_avatar")
            try {
                val orientation=ExifInterface(ByteArrayInputStream(bytes)).getAttributeInt(ExifInterface.TAG_ORIENTATION,ExifInterface.ORIENTATION_NORMAL)
                val matrix=Matrix().apply { when(orientation) { 2->setScale(-1f,1f); 3->setRotate(180f); 4->setScale(1f,-1f); 5->{setRotate(90f);postScale(-1f,1f)};6->setRotate(90f);7->{setRotate(-90f);postScale(-1f,1f)};8->setRotate(-90f) } }
                val rotated=Bitmap.createBitmap(image,0,0,image.width,image.height,matrix,true); if(rotated!==image){image.recycle();image=rotated}
                val side=minOf(image.width,image.height); val cropped=Bitmap.createBitmap(image,(image.width-side)/2,(image.height-side)/2,side,side)
                val scaled=Bitmap.createScaledBitmap(cropped,160,160,true)
                try {
                    for(quality in listOf(70,45,20)) { MeshMessengerAppLock.requireEpoch(expected); val output=ByteArrayOutputStream(); check(scaled.compress(Bitmap.CompressFormat.JPEG,quality,output));val encoded=output.toByteArray()
                        try { val avatar="data:image/jpeg;base64,"+android.util.Base64.encodeToString(encoded,android.util.Base64.NO_WRAP); if(avatar.length<=12_288){MeshMessengerAppLock.requireEpoch(expected);return json("avatar" to avatar)} } finally { encoded.fill(0) }
                    };error("avatar_too_large")
                } finally { if(scaled!==cropped)scaled.recycle();if(cropped!==image)cropped.recycle() }
            } finally { image.recycle() }
        } finally { bytes.fill(0) }
    }
    private fun legacy(expected: String, profile: ByteArray, kind: String): File {
        require(kind in setOf("read-state","notification-state","receipt-marks","read-receipts","notification-preview")) { "invalid_preference" }
        val (binding, actual)=boundProfile(expected)
        try { check(profile.contentEquals(actual)) { "stale_profile" } } finally { actual.fill(0) }
        val fields=profileFields(profile);val account=hex(fields[1]);fields.forEach { it.fill(0) }
        val suffix=if(kind in setOf("read-state","notification-state","receipt-marks"))".json" else ""
        check(profileBinding.get() === binding) { "protected_files_unavailable" }
        return File(binding.documents,"$kind-$account$suffix")
    }
    fun readLegacy(profile: ByteArray, kind: String, expected: String): String? = MeshMessengerAppLock.scoped(expected) {
        val file=legacy(expected,profile,kind); if(!file.exists())null else { check(file.length()<=1_048_576);MeshMessengerAppLock.publication(expected);file.readText(Charsets.UTF_8) }
    }
    fun removeLegacy(profile: ByteArray, kind: String, expected: String) = MeshMessengerAppLock.scoped(expected) {
        val file=legacy(expected,profile,kind);MeshMessengerAppLock.publication(expected);if(file.exists())check(file.delete()) { "preference_cleanup_failed" }
    }
    fun forgetLegacy(account: String, expected: String) = MeshMessengerAppLock.scoped(expected) {
        val profile=boundProfile(expected).second
        try { check(identity(expected).account==account) { "stale_profile" };removeLegacy(profile,"read-receipts",expected);removeLegacy(profile,"notification-preview",expected) } finally { profile.fill(0) }
    }
}
