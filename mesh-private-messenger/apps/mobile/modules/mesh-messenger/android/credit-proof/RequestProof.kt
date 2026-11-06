package expo.modules.meshmessenger

import java.io.File

private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
fun main(args: Array<String>) {
    val lines = File(args[0]).readLines()
    lines.forEachIndexed { index, line ->
        val parts = line.split('\t')
        val accepted = runCatching { MeshMessengerCreditRequest.validate(parts[0], hex(parts[2]), hex(parts[1])) }.isSuccess
        check(accepted == (parts[3] == "1")) { "Unexpected credit request decision at vector $index: ${parts[0]}" }
    }
    println("Kotlin credit host framing: ${lines.size} vectors passed")
}
