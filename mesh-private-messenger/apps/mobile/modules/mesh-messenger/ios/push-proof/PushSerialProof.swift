import Foundation

@main struct PushSerialProof {
  static func main() {
    let queue = MeshMessengerPushSerialQueue()
    var events: [String] = []
    var clearDone: (() -> Void)?
    var primeDone: (() -> Void)?
    queue.enqueue { done in events.append("clear-start"); clearDone = done }
    queue.enqueue { done in events.append("prime-start"); primeDone = done }
    precondition(events == ["clear-start"], "a new token may not be acquired before old deletion finishes")
    clearDone!()
    precondition(events == ["clear-start", "prime-start"])
    queue.enqueue { done in events.append("third"); done() }
    clearDone!()
    precondition(events == ["clear-start", "prime-start"], "duplicate old callback may not release a newer operation")
    primeDone!()
    precondition(events == ["clear-start", "prime-start", "third"])
    var release: (() -> Void)?
    var sameAccount = true
    queue.enqueue { done in release = done }
    queue.enqueue { done in
      if sameAccount { events.append("stale-effect") }
      else { events.append("stale-rejected") }
      done()
    }
    sameAccount = false
    release!()
    precondition(events.last == "stale-rejected", "account check must happen when OS work actually starts")
    queue.enqueue { done in
      events.append("reentrant-first")
      queue.enqueue { next in events.append("reentrant-second"); next() }
      done()
    }
    precondition(Array(events.suffix(2)) == ["reentrant-first", "reentrant-second"])
    print("Swift push queue: serialization, duplicate callbacks, delayed account checks and reentrancy pass")
  }
}
