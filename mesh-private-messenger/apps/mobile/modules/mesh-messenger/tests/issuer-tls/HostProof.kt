package expo.modules.meshmessenger

import java.io.ByteArrayInputStream
import java.io.IOException

fun main() {
    check(MeshMessengerIssuerTLS.read(emptyArray()) { error("absent asset opened") }.contentEquals(byteArrayOf(1,0,0,0,0,0,0)))
    val names = arrayOf(MeshMessengerIssuerTLS.ASSET)
    val maximum = ByteArray(67591) { 7 }
    check(MeshMessengerIssuerTLS.read(names) { ByteArrayInputStream(maximum) }.contentEquals(maximum))
    for (size in listOf(0, 6, 67592)) {
        check(runCatching { MeshMessengerIssuerTLS.read(names) { ByteArrayInputStream(ByteArray(size)) } }.isFailure)
    }
    check(runCatching { MeshMessengerIssuerTLS.read(names) { throw IOException("owned failure") } }.isFailure)
    println("issuer TLS Android reader: absent, exact bound, truncation, oversize and read failures passed")
}
