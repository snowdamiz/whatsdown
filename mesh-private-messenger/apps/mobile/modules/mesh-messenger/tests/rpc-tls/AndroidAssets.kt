package android.content.res

import java.io.InputStream

class AssetManager(
    private val listing: () -> Array<String>?,
    private val opening: () -> InputStream,
) {
    fun list(path: String): Array<String>? { check(path.isEmpty()); return listing() }
    fun open(name: String): InputStream {
        check(name == "morse-rpc-tls-roots-v1.bin" || name == "morse-issuer-tls-root-v1.bin")
        return opening()
    }
}
