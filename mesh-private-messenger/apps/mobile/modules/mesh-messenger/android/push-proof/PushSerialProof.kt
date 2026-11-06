package expo.modules.meshmessenger

fun main() {
    val queue = MeshMessengerPushSerialQueue()
    val events = mutableListOf<String>()
    var clearDone: (() -> Unit)? = null
    var primeDone: (() -> Unit)? = null
    queue.enqueue { done -> events.add("clear-start"); clearDone = done }
    queue.enqueue { done -> events.add("prime-start"); primeDone = done }
    check(events == listOf("clear-start")) { "a new token may not be acquired before old deletion finishes" }
    clearDone!!()
    check(events == listOf("clear-start", "prime-start"))
    queue.enqueue { done -> events.add("third"); done() }
    clearDone!!()
    check(events == listOf("clear-start", "prime-start")) { "duplicate old callback may not release a newer operation" }
    primeDone!!()
    check(events == listOf("clear-start", "prime-start", "third"))
    var release: (() -> Unit)? = null
    var sameAccount = true
    queue.enqueue { done -> release = done }
    queue.enqueue { done ->
        events.add(if (sameAccount) "stale-effect" else "stale-rejected")
        done()
    }
    sameAccount = false
    release!!()
    check(events.last() == "stale-rejected") { "account check must happen when OS work actually starts" }
    queue.enqueue { done ->
        events.add("reentrant-first")
        queue.enqueue { next -> events.add("reentrant-second"); next() }
        done()
    }
    check(events.takeLast(2) == listOf("reentrant-first", "reentrant-second"))
    println("Kotlin push queue: serialization, duplicate callbacks, delayed account checks and reentrancy pass")
}
