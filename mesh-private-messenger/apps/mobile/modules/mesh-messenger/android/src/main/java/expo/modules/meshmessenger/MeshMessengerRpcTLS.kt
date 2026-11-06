package expo.modules.meshmessenger

import java.io.InputStream

/** Packaged bytes only. Companion framing, origin authority and TLS stay in Mesh. */
internal object MeshMessengerRpcTLS {
    const val ASSET = "morse-rpc-tls-roots-v1.bin"

    fun read(names: Array<String>, open: () -> InputStream): ByteArray {
        if (!names.contains(ASSET)) return byteArrayOf(1, 0)
        return open().use { input ->
            val bytes = ByteArray(82003)
            var length = 0
            while (length < bytes.size) {
                val count = input.read(bytes, length, bytes.size - length)
                if (count < 0) break
                check(count > 0) { "rpc_tls_config_invalid" }
                length += count
            }
            check(length in 2..82002) { "rpc_tls_config_invalid" }
            bytes.copyOf(length)
        }
    }
}
