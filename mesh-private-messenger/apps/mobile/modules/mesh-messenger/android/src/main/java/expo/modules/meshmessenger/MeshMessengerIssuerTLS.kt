package expo.modules.meshmessenger

import java.io.InputStream

/** Immutable packaged issuer resource. Parsing and origin authority stay in Mesh. */
internal object MeshMessengerIssuerTLS {
    const val ASSET = "morse-issuer-tls-root-v1.bin"
    fun read(names: Array<String>, open: () -> InputStream): ByteArray {
        if (!names.contains(ASSET)) return byteArrayOf(1, 0, 0, 0, 0, 0, 0)
        return open().use { input ->
            val bytes = ByteArray(67592)
            var length = 0
            while (length < bytes.size) {
                val count = input.read(bytes, length, bytes.size - length)
                if (count < 0) break
                check(count > 0) { "issuer_tls_config_invalid" }
                length += count
            }
            check(length in 7..67591) { "issuer_tls_config_invalid" }
            bytes.copyOf(length)
        }
    }
}
