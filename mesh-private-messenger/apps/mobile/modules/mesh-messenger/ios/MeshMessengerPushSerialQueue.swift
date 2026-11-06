import Foundation

// Only serializes asynchronous OS work. Mesh validates each saved action when
// it starts and before its result is cached; the queue makes no account policy.
final class MeshMessengerPushSerialQueue {
  private final class Job {
    let body: (@escaping () -> Void) -> Void
    init(_ body: @escaping (@escaping () -> Void) -> Void) { self.body = body }
  }
  private let lock = NSLock()
  private var jobs: [Job] = []

  func enqueue(_ body: @escaping (@escaping () -> Void) -> Void) {
    let job = Job(body)
    lock.lock()
    jobs.append(job)
    let first = jobs.count == 1
    lock.unlock()
    if first { start(job) }
  }

  private func start(_ job: Job) {
    job.body { self.finish(job) }
  }

  private func finish(_ job: Job) {
    lock.lock()
    guard jobs.first === job else { lock.unlock(); return }
    jobs.removeFirst()
    let next = jobs.first
    lock.unlock()
    if let next { start(next) }
  }
}
