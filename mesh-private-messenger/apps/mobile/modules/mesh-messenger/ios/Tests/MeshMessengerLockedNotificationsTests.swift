import Foundation

private enum TestFailure: Error { case assertion(String), injected }
private func expect(_ condition: @autoclosure () throws -> Bool, _ why: String) throws { if try !condition() { throw TestFailure.assertion(why) } }
private func refuses(_ body: () throws -> Void) throws {
  do { try body() } catch TestFailure.assertion(let why) { throw TestFailure.assertion(why) } catch { return }
  throw TestFailure.assertion("expected refusal")
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  let record: MeshMessengerAppLockPolicy.Record
  init(_ mode: String) { record = .init(install: UUID().uuidString.lowercased(), sequence: 0, policy: mode) }
  func load() throws -> MeshMessengerAppLockPolicy.Record { record }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record { throw TestFailure.injected }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval { 0 }
  var canAuthenticate: Bool { true }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) { completion(false) }
  func cancel(requestID: String) {}
  func render(state: [String: Any], uncover: Bool) {}
  func copyText(_ text: String) {}
}
private final class Port: MeshMessengerNoticePort {
  var ownsDelegate = true
  let mutex = NSRecursiveLock()
  var notices: [MeshMessengerNotice] = []
  var pendingIDs: [String] = []
  var deliveredIDs: [String] = []
  var adds: [(Error?) -> Void] = []
  var hold = false
  var queryNeverReturns = false
  var beforeDelivered: (() -> Void)?
  var removeWorks = true
  var locationDelivered = false
  func removeAllPending() { mutex.lock(); defer { mutex.unlock() }; if removeWorks { pendingIDs = [] } }
  func removeAllDelivered() { mutex.lock(); defer { mutex.unlock() }; if removeWorks { deliveredIDs = []; locationDelivered = false } }
  func add(_ notice: MeshMessengerNotice, completion: @escaping (Error?) -> Void) {
    mutex.lock(); notices.append(notice); pendingIDs.append(notice.identifier); let held = hold
    if held { adds.append(completion) }; mutex.unlock()
    if !held { completion(nil) }
  }
  func pending(_ completion: @escaping ([String]) -> Void) { mutex.lock(); let ids = pendingIDs, stuck = queryNeverReturns; mutex.unlock(); if !stuck { completion(ids) } }
  func delivered(_ completion: @escaping ([String]) -> Void) { beforeDelivered?(); mutex.lock(); let ids = deliveredIDs; mutex.unlock(); completion(ids) }
  func removePending(_ ids: [String]) { mutex.lock(); defer { mutex.unlock() }; if removeWorks { pendingIDs.removeAll { ids.contains($0) } } }
  func removeDelivered(_ ids: [String]) { mutex.lock(); defer { mutex.unlock() }; if removeWorks { deliveredIDs.removeAll { ids.contains($0) } } }
  func finish(_ index: Int = 0, twice: Bool = false) { mutex.lock(); let done = adds[index]; mutex.unlock(); done(nil); if twice { done(nil) } }
}
private final class Outcome {
  let done = DispatchSemaphore(value: 0), mutex = NSLock()
  var result: Result<Void, Error>?
  var count = 0
  func complete(_ result: Result<Void, Error>) { mutex.lock(); self.result = result; count += 1; mutex.unlock(); done.signal() }
  func value() throws { guard done.wait(timeout: .now() + 2) == .success else { throw TestFailure.assertion("operation did not complete") }; mutex.lock(); let result = result!; mutex.unlock(); try result.get() }
}
private struct Fixture {
  let gate: MeshMessengerAppLock, port: Port, notices: MeshMessengerLockedNotifications
  init(_ mode: String = "disabled", timeout: TimeInterval = 0.2) throws {
    let policy = Policy(mode), nativePort = Port(); port = nativePort
    gate = MeshMessengerAppLock(platform: Platform(), makeStore: { policy }, cleanStaging: {}, drainNotices: {}, validateEnvironment: { if !nativePort.ownsDelegate { throw TestFailure.injected } })
    try gate.bootstrap(); gate.foreground(ownerSceneID: "scene", active: true)
    notices = MeshMessengerLockedNotifications(gate: gate, port: port, deadlineSeconds: timeout)
  }
  let frame = "{\"version\":1,\"id\":\"private-thread/message\",\"title\":\"Alice\",\"body\":\"private words\",\"scope\":\"chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"mention\":true}"
  func publish() -> Outcome { let result = Outcome(); notices.publish(frame, expected: gate.currentEpoch, completion: result.complete); return result }
}
@main private enum NotificationTests {
  static func main() {
    let done = DispatchSemaphore(value: 0)
    DispatchQueue.global().async { run(); done.signal() }
    while done.wait(timeout: .now()) != .success { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
  }
  static func run() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) { do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") } }
    test("disabled publication retains content with opaque OS identity and exactly once completion") {
      let f = try Fixture(); f.port.hold = true; let outcome = f.publish()
      try expect(f.port.notices.count == 1, "real add admitted")
      let value = f.port.notices[0]
      try expect(!value.generic && value.title == "Alice" && value.body == "private words" && value.scope == "chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" && value.mention, "disabled content retained")
      try expect(UUID(uuidString: value.identifier) != nil && !value.identifier.contains("private"), "opaque native ID")
      f.port.finish(twice: true); try outcome.value(); try expect(outcome.count == 1, "duplicate OS callback consumed once")
    }
    test("restrictive generic wake contains no private metadata") {
      let f = try Fixture("enabled"), result = Outcome(); f.notices.genericWakeup(completion: result.complete); try result.value()
      let value = f.port.notices.first
      try expect(value?.generic == true && value?.title == "" && value?.body == "" && value?.scope == nil && value?.mention == false, "native fixed generic only")
      try refuses { try f.publish().value() }; try expect(f.port.notices.count == 1, "locked private entry refused")
    }
    test("late add callback after revoke removes its exact request and refuses stale success") {
      let f = try Fixture(); f.port.hold = true; let outcome = f.publish()
      try expect(f.port.notices.count == 1, "tracked add")
      f.gate.lock(); f.port.finish(); try refuses { try outcome.value() }
      try expect(f.port.pendingIDs.isEmpty && f.port.deliveredIDs.isEmpty, "late publication removed")
    }
    test("drain waits for old add callback and removes every app-owned legacy ID") {
      let f = try Fixture(timeout: 1); f.port.hold = true; let outcome = f.publish()
      try expect(f.port.notices.count == 1, "tracked add")
      f.port.pendingIDs.append("chat/legacy/message"); f.port.deliveredIDs = ["encrypted-wakeup", "foreign:raw"]
      f.gate.lock(); let drained = Outcome()
      DispatchQueue.global().async { drained.complete(Result { try f.notices.drainLegacy() }) }
      Thread.sleep(forTimeInterval: 0.03); try expect(drained.done.wait(timeout: .now()) == .timedOut, "drain waits for admitted callback")
      f.port.finish(); try refuses { try outcome.value() }; try drained.value()
      try expect(f.port.pendingIDs.isEmpty && f.port.deliveredIDs.isEmpty, "actual pending/delivered identifiers all removed")
    }
    test("drain verifies asynchronous removal and refuses nonempty or missing query completion") {
      let f = try Fixture(); f.port.pendingIDs = ["legacy"]; f.port.removeWorks = false
      try refuses { try f.notices.drainLegacy() }
      let g = try Fixture(); g.port.queryNeverReturns = true
      try refuses { try g.notices.drainLegacy() }
      let h = try Fixture(); h.port.deliveredIDs = Array(repeating: "id", count: 10_001)
      try refuses { try h.notices.drainLegacy() }
    }
    test("unknown fields stale epochs and delegate replacement cannot publish") {
      let f = try Fixture(); let malformed = Outcome()
      f.notices.publish(f.frame.dropLast() + ",\"unknown\":true}", expected: f.gate.currentEpoch, completion: malformed.complete)
      try refuses { try malformed.value() }; try expect(f.port.notices.isEmpty, "unknown frame rejected")
      let old = f.gate.currentEpoch; f.gate.accountChanging(); let stale = Outcome()
      f.notices.publish(f.frame, expected: old, completion: stale.complete); try refuses { try stale.value() }
      f.port.ownsDelegate = false; let generic = Outcome(); f.notices.genericWakeup(completion: generic.complete)
      try refuses { try generic.value() }; try refuses { try f.notices.drainLegacy() }
      try expect(f.port.notices.isEmpty, "no unowned publisher")
    }
    test("drain removes OS location deliveries absent from delivered enumeration") {
      let f = try Fixture(); f.port.locationDelivered = true
      try f.notices.drainLegacy()
      try expect(!f.port.locationDelivered, "remove-all covers unenumerable OS location deliveries")
    }
    test("drain rechecks delegate ownership after its final asynchronous query") {
      let f = try Fixture(); var reads = 0
      f.port.beforeDelivered = { reads += 1; if reads == 2 { f.port.ownsDelegate = false } }
      try refuses { try f.notices.drainLegacy() }
      try expect(reads == 2, "actual final delivered query replaced delegate")
    }
    test("missing add callback times out caller but stays tracked until actual completion") {
      let f = try Fixture(timeout: 0.05); f.port.hold = true; let outcome = f.publish()
      try refuses { try outcome.value() }
      // A caller timeout must not pretend the OS add has finished.
      try refuses { try f.notices.drainLegacy() }
      f.port.finish(twice: true)
      try expect(outcome.count == 1 && f.port.pendingIDs.isEmpty && f.port.deliveredIDs.isEmpty, "late OS add cleaned without duplicate success")
      try f.notices.drainLegacy()
    }
    let scopeA = "chat/" + String(repeating: "a", count: 32)
    let scopeB = "group/" + String(repeating: "b", count: 64)
    func issued(_ f: Fixture, scope: String) throws -> String {
      let outcome = Outcome()
      f.notices.publish(f.frame.replacingOccurrences(of: scopeA, with: scope), expected: f.gate.currentEpoch, completion: outcome.complete)
      try outcome.value(); return f.port.notices.last!.identifier
    }
    func consume(_ f: Fixture, owner: String = "scene") throws -> String {
      try f.gate.consumeNotice(f.gate.currentEpoch, ownerSceneID: owner)
    }
    test("issued disabled tap routes exact scope once and duplicate UUID cannot replace a newer tap") {
      let f = try Fixture(), a = try issued(f, scope: scopeA), b = try issued(f, scope: scopeB)
      f.gate.recordNotice(a, scope: scopeA)
      try expect(try consume(f) == "{\"version\":1,\"kind\":\"scope\",\"scope\":\"\(scopeA)\"}", "actual issued scope consumed")
      f.gate.recordNotice(b, scope: scopeB); f.gate.recordNotice(a, scope: scopeA)
      try expect(try consume(f).contains(scopeB), "used UUID does not overwrite a later distinct tap")
      try expect(try consume(f) == "{\"version\":1,\"kind\":\"none\"}", "consumed once")
    }
    test("old-account OS deliveries cannot be relabeled into a current private intent") {
      let f = try Fixture(), id = try issued(f, scope: scopeA)
      f.gate.accountChanging(); f.gate.recordNotice(id, scope: scopeA)
      try expect(try consume(f) == "{\"version\":1,\"kind\":\"inbox\"}", "old issued account becomes inbox")
      let current = try issued(f, scope: scopeA); f.gate.recordNotice(current, scope: scopeA)
      f.gate.accountChanging()
      try expect(try consume(f) == "{\"version\":1,\"kind\":\"inbox\"}", "pending private intent downgraded on account change")
    }
    test("inactive disabled tap survives same-owner activation only with current issuance") {
      let f = try Fixture(); f.gate.foreground(ownerSceneID: "scene", active: false)
      let id = try issued(f, scope: scopeA); f.gate.recordNotice(id, scope: scopeA)
      try refuses { _ = try consume(f) }
      f.gate.foreground(ownerSceneID: "scene", active: true)
      try expect(try consume(f).contains(scopeA), "same-owner current issuance survives activation")
      let next = try issued(f, scope: scopeA); f.gate.recordNotice(next, scope: scopeA)
      f.gate.foreground(ownerSceneID: "different", active: true)
      try expect(try consume(f, owner: "different") == "{\"version\":1,\"kind\":\"inbox\"}", "owner transition clears private slot")
    }
    test("native notice consume requires actual owner and cannot be stolen through generic bool") {
      let f = try Fixture(), id = try issued(f, scope: scopeA); f.gate.recordNotice(id, scope: scopeA)
      try refuses { _ = try consume(f, owner: "other") }
      try expect(!(try f.gate.consumeInbox(f.gate.currentEpoch)), "generic compatibility consumer leaves private slot alone")
      try expect(try consume(f).contains(scopeA), "correct owner retains its unconsumed target")
    }
    test("issuance is bounded and failed add cleanup releases only its own slot") {
      let f = try Fixture()
      for _ in 0..<128 { _ = try issued(f, scope: scopeA) }
      try refuses { _ = try issued(f, scope: scopeA) }
      try expect(f.port.notices.count == 128, "capacity refuses before OS add")
      let old = f.port.notices[0].identifier; f.gate.forgetNotice(old)
      let fresh = try issued(f, scope: scopeB); f.gate.forgetNotice(old)
      f.gate.recordNotice(fresh, scope: scopeB)
      try expect(try consume(f).contains(scopeB), "late old cleanup cannot clear newer issuance")
    }
    test("legacy malformed and scope-mismatched responses produce only generic inbox") {
      let f = try Fixture(), id = try issued(f, scope: scopeA)
      for (identifier, scope) in [(UUID().uuidString, scopeA), (id, scopeB), (UUID().uuidString, "chat/private")] {
        f.gate.recordNotice(identifier, scope: scope)
        try expect(try consume(f) == "{\"version\":1,\"kind\":\"inbox\"}", "unproven target discarded")
      }
    }
    test("presentation admits only matching native issuance and uses current gate ordering") {
      let f = try Fixture(), id = try issued(f, scope: scopeA)
      var options: [Bool] = []
      f.notices.presentMessage(id, scope: scopeA) { options.append($0) }
      f.notices.presentMessage(UUID().uuidString, scope: scopeA) { options.append($0) }
      f.notices.presentMessage(id, scope: scopeB) { options.append($0) }
      f.gate.accountChanging()
      f.notices.presentMessage(id, scope: scopeA) { options.append($0) }
      try expect(options == [true, false, false, false], "no legacy or mismatched private presentation")
    }
    test("response adapter consumes real publication and refuses lost delegate ownership") {
      let f = try Fixture(), id = try issued(f, scope: scopeA)
      f.notices.receiveMessage(id, scope: scopeA)
      try expect(try consume(f).contains(scopeA), "actual adapter routes current issued scope")
      f.port.ownsDelegate = false; f.notices.receiveMessage(UUID().uuidString, scope: nil)
      try refuses { _ = try consume(f) }; f.port.ownsDelegate = true
      try refuses { _ = try consume(f) } // Restoring ownership cannot revive this process.
    }
    test("notification observation quarantines before delegate restoration and next gate access") {
      for entry in 0..<3 {
        let f = try Fixture(), id = try issued(f, scope: scopeA)
        f.notices.receiveMessage(id, scope: scopeA)
        let old = f.gate.currentEpoch
        f.port.ownsDelegate = false
        if entry == 0 {
          f.notices.receiveMessage(UUID().uuidString, scope: nil)
        } else if entry == 1 {
          var calls: [Bool] = []
          f.notices.presentMessage(id, scope: scopeA) { calls.append($0) }
          try expect(calls == [false], "unowned presentation completes once without private options")
        } else {
          let result = Outcome(); f.notices.genericWakeup(completion: result.complete)
          try refuses { try result.value() }
        }
        // Restore before any gate call: notification observation must itself revoke.
        f.port.ownsDelegate = true
        try expect(f.gate.currentEpoch != old && f.gate.restrictionActive, "observed loss revoked private authority immediately")
        try expect(f.gate.state()["phase"] as? String == "error", "sticky quarantine survives delegate restoration")
        try refuses { _ = try consume(f) }
        try expect(!f.gate.presentation().uncover, "quarantined process stays covered")
      }
    }
    test("observed environment loss permanently drops old private routing before ownership recovers") {
      let f = try Fixture(), id = try issued(f, scope: scopeA); f.notices.receiveMessage(id, scope: scopeA)
      f.port.ownsDelegate = false; try refuses { _ = try consume(f) }
      f.port.ownsDelegate = true
      try refuses { _ = try consume(f) }
      f.notices.receiveMessage(id, scope: scopeA)
      try refuses { _ = try consume(f) }
      let restarted = try Fixture(); restarted.notices.receiveMessage(id, scope: scopeA)
      try expect(try consume(restarted) == "{\"version\":1,\"kind\":\"inbox\"}", "new process has no old private issuance")
    }
    test("private OS presentation completion cannot follow a completed revoke") {
      let f = try Fixture(), id = try issued(f, scope: scopeA)
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
      let presented = DispatchSemaphore(value: 0), revoked = DispatchSemaphore(value: 0), started = DispatchSemaphore(value: 0)
      let result = Outcome()
      DispatchQueue.global().async {
        f.notices.presentMessage(id, scope: scopeA) { allowed in
          if allowed { entered.signal(); _ = release.wait(timeout: .now() + 2) }
          result.complete(allowed ? .success(()) : .failure(TestFailure.injected))
        }
        presented.signal()
      }
      guard entered.wait(timeout: .now() + 2) == .success else { throw TestFailure.assertion("actual presentation callback reached") }
      DispatchQueue.global().async { started.signal(); f.gate.accountChanging(); revoked.signal() }
      _ = started.wait(timeout: .now() + 2)
      let tooEarly = revoked.wait(timeout: .now() + 0.05) == .success
      release.signal()
      guard presented.wait(timeout: .now() + 2) == .success else { throw TestFailure.assertion("presentation reaped") }
      if !tooEarly { guard revoked.wait(timeout: .now() + 2) == .success else { throw TestFailure.assertion("revoke reaped") } }
      try result.value(); try expect(!tooEarly, "revoke cannot complete inside earlier private publication")
      var late = true; f.notices.presentMessage(id, scope: scopeA) { late = $0 }
      try expect(!late, "revoked issuance cannot present afterward")
    }
    test("cold OS response retains only generic intent until verified disabled bootstrap and owner") {
      let policy = Policy("disabled"), port = Port()
      let gate = MeshMessengerAppLock(platform: Platform(), makeStore: { policy }, cleanStaging: {}, drainNotices: {})
      let notices = MeshMessengerLockedNotifications(gate: gate, port: port)
      notices.receiveMessage(UUID().uuidString, scope: scopeA)
      try refuses { _ = try gate.consumeNotice(gate.currentEpoch, ownerSceneID: "scene") }
      try gate.bootstrap(); gate.foreground(ownerSceneID: "scene", active: true)
      try expect(try gate.consumeNotice(gate.currentEpoch, ownerSceneID: "scene") == "{\"version\":1,\"kind\":\"inbox\"}", "cold private target never retained")
      try expect(try gate.consumeNotice(gate.currentEpoch, ownerSceneID: "scene") == "{\"version\":1,\"kind\":\"none\"}", "cold tap consumed once")
    }
    print("IOS_NOTICE_HOST_RESULT failures=\(failures) groups=21")
    if failures != 0 { exit(1) }
  }
}
