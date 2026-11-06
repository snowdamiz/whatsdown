package expo.modules.meshmessenger

import android.content.Context
import android.content.res.AssetManager
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

// The real C++ registration requires these unrelated methods; none may be called.
internal object MeshMessengerSecureStore {
    @JvmStatic fun put(bytes: ByteArray): Int = error("unexpected secure-store put: ${bytes.size}")
    @JvmStatic fun get(bytes: ByteArray): ByteArray = error("unexpected secure-store get: ${bytes.size}")
    @JvmStatic fun delete(bytes: ByteArray): Int = error("unexpected secure-store delete: ${bytes.size}")
}

private object RpcTLSHostProof {
    @JvmStatic external fun checkRead(capacity: Int, status: Int, expected: ByteArray)
}

private const val MAX_BYTES = 82002
private val absent = byteArrayOf(1, 0)
private fun payload(size: Int) = ByteArray(size) { (it * 31 + 17).toByte() }

private fun readerProof() {
    val names = arrayOf(MeshMessengerRpcTLS.ASSET)
    check(MeshMessengerRpcTLS.read(emptyArray()) { error("absent asset opened") }.contentEquals(absent))
    for (size in listOf(2, 3, MAX_BYTES)) {
        val bytes = payload(size)
        check(MeshMessengerRpcTLS.read(names) { ByteArrayInputStream(bytes) }.contentEquals(bytes))
    }
    for (size in listOf(0, 1, MAX_BYTES + 1)) {
        check(runCatching { MeshMessengerRpcTLS.read(names) { ByteArrayInputStream(payload(size)) } }.isFailure)
    }
    check(runCatching { MeshMessengerRpcTLS.read(names) { throw IOException("open failure") } }.isFailure)
    var closed = false
    check(runCatching {
        MeshMessengerRpcTLS.read(names) {
            object : InputStream() {
                override fun read(): Int = throw IOException("read failure")
                override fun close() { closed = true }
            }
        }
    }.isFailure && closed)
    check(runCatching {
        MeshMessengerRpcTLS.read(names) {
            object : ByteArrayInputStream(absent) {
                override fun close() { throw IOException("close failure") }
            }
        }
    }.isFailure)
    check(runCatching {
        MeshMessengerRpcTLS.read(names) {
            object : InputStream() {
                override fun read(): Int = 0
                override fun read(buffer: ByteArray, offset: Int, length: Int): Int = 0
            }
        }
    }.isFailure)
    val maximum = payload(MAX_BYTES)
    check(MeshMessengerRpcTLS.read(names) {
        object : ByteArrayInputStream(maximum) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
                super.read(buffer, offset, minOf(length, 113))
        }
    }.contentEquals(maximum))
    val oversized = ByteArrayInputStream(payload(MAX_BYTES + 100))
    check(runCatching { MeshMessengerRpcTLS.read(names) { oversized } }.isFailure)
    check(oversized.available() == 99) // Bound the read itself, including the one-byte overflow probe.
    println("RPC Kotlin reader: absence, opaque bytes, bounds, partial/zero reads, open/read/close errors passed")
}

fun main(args: Array<String>) {
    System.load(args[0])
    val mode = args[1]
    if (mode == "reader") { readerProof(); return }
    val value = when (mode) {
        "maximum", "bridge-bounds" -> payload(MAX_BYTES)
        "empty" -> byteArrayOf()
        "truncated" -> byteArrayOf(1)
        "oversized" -> payload(MAX_BYTES + 1)
        else -> payload(3)
    }
    var opened = 0
    val assets = AssetManager(
        listing = {
            when (mode) {
                "list-error" -> throw IOException("list failure")
                "list-null" -> null
                "absent" -> emptyArray()
                else -> arrayOf(MeshMessengerRpcTLS.ASSET)
            }
        },
        opening = {
            opened++
            when (mode) {
                "open-error", "directory" -> throw IOException("present resource cannot open")
                "read-error" -> object : InputStream() {
                    override fun read(): Int = throw IOException("present resource cannot read")
                }
                "close-error" -> object : ByteArrayInputStream(value) {
                    override fun close() { throw IOException("present resource cannot close") }
                }
                else -> ByteArrayInputStream(value)
            }
        },
    )
    MeshMessengerPushMaterial.install(Context(assets))
    check(MeshMessengerHost.registerHostCallbacks() == 0)
    if (mode in listOf("list-error", "list-null", "open-error", "directory", "read-error", "close-error", "empty", "truncated", "oversized")) {
        check(MeshMessengerPushMaterial.rpcTLSRoots() == null)
        RpcTLSHostProof.checkRead(MAX_BYTES, 3, byteArrayOf())
        // An installed read failure cannot be turned into physical absence by retrying.
        MeshMessengerPushMaterial.install(Context(AssetManager({ emptyArray() }, { error("retry opened") })))
        RpcTLSHostProof.checkRead(MAX_BYTES, 3, byteArrayOf())
    } else {
        val expected = if (mode == "absent") absent else value
        if (mode == "absent") check(opened == 0)
        RpcTLSHostProof.checkRead(MAX_BYTES, 0, expected)
        RpcTLSHostProof.checkRead(expected.size, 0, expected)
        RpcTLSHostProof.checkRead(expected.size - 1, 4, byteArrayOf())
        RpcTLSHostProof.checkRead(0, 4, byteArrayOf())
        val copy = requireNotNull(MeshMessengerPushMaterial.rpcTLSRoots())
        copy.fill(0)
        check(requireNotNull(MeshMessengerPushMaterial.rpcTLSRoots()).contentEquals(expected))
        RpcTLSHostProof.checkRead(MAX_BYTES, 0, expected)
        MeshMessengerPushMaterial.clear()
        MeshMessengerPushMaterial.install(Context(AssetManager({ error("immutable install relisted") }, { error("immutable install reopened") })))
        RpcTLSHostProof.checkRead(MAX_BYTES, 0, expected)
        MeshMessengerHost.unregisterHostCallbacks()
        RpcTLSHostProof.checkRead(MAX_BYTES, 3, byteArrayOf())
        check(MeshMessengerHost.registerHostCallbacks() == 0)
        RpcTLSHostProof.checkRead(MAX_BYTES, 0, expected)
        if (mode == "bridge-bounds") {
            val field = MeshMessengerPushMaterial.javaClass.getDeclaredField("rpcTLSRootsFrame")
            field.isAccessible = true
            for (size in listOf(0, 1, MAX_BYTES + 1)) {
                field.set(null, payload(size))
                RpcTLSHostProof.checkRead(MAX_BYTES, 1, byteArrayOf())
            }
        }
    }
    println("RPC Kotlin install + production JNI callback: $mode passed")
}
