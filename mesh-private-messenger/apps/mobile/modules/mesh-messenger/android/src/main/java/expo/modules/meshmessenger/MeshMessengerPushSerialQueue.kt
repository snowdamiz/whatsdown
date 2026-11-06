package expo.modules.meshmessenger

// Serializes OS operations only; Mesh owns all account and action checks.
internal class MeshMessengerPushSerialQueue {
    private class Job(val body: (() -> Unit) -> Unit)
    private val jobs = java.util.ArrayDeque<Job>()

    fun enqueue(body: (() -> Unit) -> Unit) {
        val job = Job(body)
        val first = synchronized(this) {
            jobs.addLast(job)
            jobs.size == 1
        }
        if (first) start(job)
    }

    private fun start(job: Job) {
        job.body { finish(job) }
    }

    private fun finish(job: Job) {
        val next = synchronized(this) {
            if (jobs.peekFirst() !== job) return
            jobs.removeFirst()
            jobs.peekFirst()
        }
        if (next != null) start(next)
    }
}
