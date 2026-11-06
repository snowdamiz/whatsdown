import Foundation

private enum TestFailure: Error { case assertion(String), injected }
private func expect(_ value: @autoclosure () -> Bool, _ why: String) throws {
  if !value() { throw TestFailure.assertion(why) }
}
private func refuses(_ expected: MeshMessengerAppLock.Failure? = nil, _ body: () throws -> Void) throws {
  do { try body() }
  catch TestFailure.assertion(let why) { throw TestFailure.assertion(why) }
  catch {
    if let expected { try expect((error as? MeshMessengerAppLock.Failure) == expected, "expected \(expected), got \(error)") }
    return
  }
  throw TestFailure.assertion("expected refusal")
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  var record: MeshMessengerAppLockPolicy.Record
  var writes: [String] = []
  var afterWrite: ((String) throws -> Void)?
  var beforeWrite: ((String) throws -> Void)?
  var unreadable = false
  init(_ policy: String) { record = .init(install: UUID().uuidString.lowercased(), sequence: 0, policy: policy) }
  func load() throws -> MeshMessengerAppLockPolicy.Record { if unreadable { throw TestFailure.injected }; return record }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record {
    try expect(previous == record, "exact persisted record guard")
    try beforeWrite?(desired)
    record = .init(install: record.install, sequence: record.sequence + 1, policy: desired)
    writes.append(desired); try afterWrite?(desired); return record
  }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval = 10
  var canAuthenticate = true
  private let mutex = NSLock()
  private var callbacks: [String: (Bool) -> Void] = [:]
  private var latest: String?
  private(set) var uncovered = false
  var copy: ((String) -> Void)?
  func copyText(_ text: String) { copy?(text) }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) {
    mutex.lock(); callbacks[requestID] = completion; latest = requestID; mutex.unlock()
  }
  func cancel(requestID: String) {} // Preserve late callback to test stale admission.
  func render(state: [String: Any], uncover: Bool) { mutex.lock(); uncovered = uncover; mutex.unlock() }
  func request() -> String? { mutex.lock(); defer { mutex.unlock() }; return latest }
  func complete(_ id: String, _ success: Bool) { mutex.lock(); let callback = callbacks[id]; mutex.unlock(); callback?(success) }
}
private final class Job {
  let done = DispatchSemaphore(value: 0)
  private let mutex = NSLock()
  private var result: Result<[String: Any], Error>?
  init(_ body: @escaping () throws -> [String: Any]) {
    DispatchQueue.global().async { let value = Result { try body() }; self.mutex.lock(); self.result = value; self.mutex.unlock(); self.done.signal() }
  }
  func finished() -> Bool { mutex.lock(); defer { mutex.unlock() }; return result != nil }
  func value() throws -> [String: Any] {
    guard done.wait(timeout: .now() + 3) == .success else { throw TestFailure.assertion("native operation timeout") }
    mutex.lock(); let value = result!; mutex.unlock(); return try value.get()
  }
}
private struct Fixture {
  let policy: Policy
  let platform = Platform()
  let gate: MeshMessengerAppLock
  init(_ mode: String = "enabled", drain: @escaping () throws -> Void = {}, environment: @escaping () throws -> Void = {}) throws {
    let policy = Policy(mode); self.policy = policy
    gate = MeshMessengerAppLock(platform: platform, makeStore: { policy }, cleanStaging: {}, drainNotices: drain, validateEnvironment: environment)
    try gate.bootstrap(); gate.foreground(ownerSceneID: "scene-one", active: true)
  }
  func start(_ desired: Bool? = nil) throws -> (Job, String) {
    let old = platform.request(), expected = gate.currentEpoch
    let job = Job { try gate.authenticate(expected, ownerSceneID: gate.presentation().owner ?? "missing", desired: desired) }
    for _ in 0..<1000 {
      if let id = platform.request(), id != old { return (job, id) }
      if job.finished() { _ = try job.value(); throw TestFailure.assertion("no owned OS request") }
      Thread.sleep(forTimeInterval: 0.001)
    }
    throw TestFailure.assertion("OS request not started")
  }
  func unlock() throws -> [String: Any] { let (job, id) = try start(); platform.complete(id, true); return try job.value() }
}

@main private enum AppLockTests {
  static func main() {
    let done = DispatchSemaphore(value: 0)
    DispatchQueue.global().async { run(); done.signal() }
    while done.wait(timeout: .now()) != .success { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
  }
  static func run() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("enabled bootstrap stays restricted until exact OS success") {
      let f = try Fixture(); try expect(f.gate.state()["phase"] as? String == "locked", "cold enabled locked")
      try refuses { try f.gate.requireEpoch(f.gate.currentEpoch) }
      let old = f.gate.currentEpoch; let state = try f.unlock()
      try expect(state["phase"] as? String == "unlocked" && f.gate.currentEpoch != old, "fresh unlock")
      try expect(state["requestId"] == nil, "successful result must consume request identity")
      try f.gate.requireEpoch(f.gate.currentEpoch); try expect(!f.platform.uncovered, "readiness still required")
    }
    test("first opt-in cancellation restores fresh disabled without durable writes") {
      let f = try Fixture("disabled"), old = f.gate.currentEpoch; let (job, id) = try f.start(true)
      f.gate.cancel(id, ownerSceneID: "scene-one"); try refuses(.cancelled) { _ = try job.value() }
      try expect(f.gate.state()["phase"] as? String == "disabled" && f.gate.currentEpoch != old, "fresh disabled scope")
      try expect(f.policy.writes.isEmpty, "cancel before pending")
    }
    test("stale queued authentication cannot relock a newer unlock") {
      let f = try Fixture(), old = f.gate.currentEpoch; _ = try f.unlock(); let current = f.gate.currentEpoch
      try refuses(.staleEpoch) { _ = try f.gate.authenticate(old, ownerSceneID: "scene-one") }
      try expect(f.gate.currentEpoch == current && f.gate.state()["phase"] as? String == "unlocked", "stale admission is side effect free")
    }
    test("exact approved result waits through prompt inactivity for original scene") {
      let f = try Fixture(); let (job, id) = try f.start()
      f.gate.foreground(ownerSceneID: "scene-one", active: false); f.platform.complete(id, true)
      try expect(!job.finished(), "inactive result cannot unlock")
      f.gate.foreground(ownerSceneID: "scene-one", active: true); _ = try job.value()
      try expect(f.gate.state()["phase"] as? String == "unlocked", "same scene admits held result")
    }
    test("true background consumes request and ignores late success") {
      let f = try Fixture(); let (job, id) = try f.start()
      f.gate.foreground(ownerSceneID: "scene-one", active: false, cancelPending: true); try refuses { _ = try job.value() }
      let old = f.gate.currentEpoch; f.platform.complete(id, true); f.gate.foreground(ownerSceneID: "scene-one", active: true)
      try expect(f.gate.currentEpoch == old && f.gate.state()["phase"] as? String == "locked", "late callback cannot grant")
    }
    test("authenticated enable write failure remains covered") {
      let f = try Fixture("disabled"); f.policy.afterWrite = { _ in throw TestFailure.injected }
      let (job, id) = try f.start(true); f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.policy.record.policy == "enable_pending" && f.gate.restrictionActive, "durable pending preserved")
      try expect(f.gate.state()["phase"] as? String == "locked", "failure stays covered")
    }
    test("committed disable interrupted by background needs a new OS request") {
      let f = try Fixture(); f.policy.afterWrite = { mode in if mode == "disabled" { f.gate.foreground(ownerSceneID: "scene-one", active: false, cancelPending: true) } }
      let (job, id) = try f.start(false); f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.policy.record.policy == "disabled" && f.gate.restrictionActive, "committed disable remains covered")
      f.gate.foreground(ownerSceneID: "scene-one", active: true); let (recovery, freshID) = try f.start()
      try expect(freshID != id && !recovery.finished(), "fresh OS challenge required")
      f.platform.complete(freshID, true); let result = try recovery.value(); try expect(result["phase"] as? String == "disabled", "recovered disabled")
    }
    test("account change cancels request and stale scoped completion refuses") {
      let f = try Fixture(); let (job, id) = try f.start(); f.gate.accountChanging(); f.platform.complete(id, true)
      try refuses { _ = try job.value() }; _ = try f.unlock(); let expected = f.gate.currentEpoch
      try refuses { _ = try f.gate.scoped(expected) { f.gate.accountChanging(); return Data([1,2,3]) } }
    }
    test("expired OS success is refused without authority") {
      let f = try Fixture(); let (job, id) = try f.start(); f.platform.monotonicTime += 121; f.platform.complete(id, true)
      try refuses(.timeout) { _ = try job.value() }; try expect(f.gate.state()["phase"] as? String == "locked", "expired remains locked")
    }
    test("nested native scope preserves original call capture") {
      let f = try Fixture(); _ = try f.unlock(); let expected = f.gate.currentEpoch
      let captured = try f.gate.scoped(expected) { try f.gate.scoped(expected) { try f.gate.capturedCallEpoch() } }
      try expect(captured == expected, "nested native capture"); try refuses { _ = try f.gate.capturedCallEpoch() }
      let bytes = try f.gate.scopedData(expected) { Data([7,8]) }
      try expect(bytes == Data([7,8]), "current scoped bytes preserved")
      try refuses(.staleEpoch) { _ = try f.gate.scopedData(expected) { f.gate.lock(); return Data([9,10]) } }
    }
    test("first pending write failure cannot restore disabled in the running session") {
      let f = try Fixture("disabled"); f.policy.beforeWrite = { _ in throw TestFailure.injected }
      let (job, id) = try f.start(true); f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.policy.record.policy == "disabled" && f.gate.restrictionActive, "unpersisted authenticated failure stays restricted")
      try refuses { try f.gate.requireEpoch(f.gate.currentEpoch) }
    }
    test("enable notification drain failure leaves pending policy and cover") {
      let f = try Fixture("disabled", drain: { throw TestFailure.injected })
      let (job, id) = try f.start(true); f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.policy.record.policy == "enable_pending" && f.policy.writes == ["enable_pending"], "no enabled commit before drain")
      try expect(f.gate.restrictionActive, "drain refusal stays restricted")
    }
    test("cold pending recovery can choose disable after fresh authentication") {
      let f = try Fixture("enable_pending"); let (job, id) = try f.start(false); f.platform.complete(id, true)
      let result = try job.value(); try expect(result["phase"] as? String == "disabled", "explicit disabled recovery")
      try expect(f.policy.writes == ["disable_pending", "disabled"], "pending then final disable")
    }
    test("unreadable policy cannot bootstrap or authenticate") {
      let p = Policy("enabled"), platform = Platform(); p.unreadable = true
      let gate = MeshMessengerAppLock(platform: platform, makeStore: { p }, cleanStaging: {}, drainNotices: {})
      try refuses { try gate.bootstrap() }; gate.foreground(ownerSceneID: "scene-one", active: true)
      try expect(gate.state()["phase"] as? String == "error" && gate.restrictionActive, "unreadable stays error")
      try refuses { _ = try gate.authenticate(gate.currentEpoch, ownerSceneID: "scene-one") }; try expect(platform.request() == nil, "no prompt bypass")
    }
    test("unavailable first opt-in returns fresh disabled without writing") {
      let f = try Fixture("disabled"); f.platform.canAuthenticate = false; let old = f.gate.currentEpoch
      try refuses { _ = try f.gate.authenticate(old, ownerSceneID: "scene-one", desired: true) }
      try expect(f.gate.state()["phase"] as? String == "disabled" && f.gate.currentEpoch != old && f.policy.writes.isEmpty, "unavailable opt-in did not persist")
    }
    test("readiness only uncovers current authenticated foreground epoch") {
      let f = try Fixture(); let old = f.gate.currentEpoch
      try DispatchQueue.main.sync { try refuses { try f.gate.activate(old, ownerSceneID: "scene-one") } }
      _ = try f.unlock(); let current = f.gate.currentEpoch
      try DispatchQueue.main.sync { try f.gate.activate(current, ownerSceneID: "scene-one") }; try expect(f.platform.uncovered, "current tree can uncover")
      f.gate.lock(); try DispatchQueue.main.sync { try refuses { try f.gate.activate(current, ownerSceneID: "scene-one") } }
      try expect(!f.platform.uncovered, "stale readiness cannot uncover")
    }
    test("foreign scene cannot inherit request or unlocked scope") {
      let f = try Fixture(); let (job, id) = try f.start()
      f.gate.foreground(ownerSceneID: "scene-two", active: true); f.platform.complete(id, true); try refuses { _ = try job.value() }
      _ = try f.unlock(); let old = f.gate.currentEpoch; f.gate.foreground(ownerSceneID: "scene-one", active: true)
      try refuses { try f.gate.requireEpoch(old) }; try expect(f.gate.state()["phase"] as? String == "locked", "scene switch revokes")
    }
    test("lock revokes immediately while policy IO is blocked") {
      let f = try Fixture("disabled"), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
      f.policy.beforeWrite = { _ in entered.signal(); _ = release.wait(timeout: .now() + 3) }
      let (job, id) = try f.start(true); f.platform.complete(id, true)
      try expect(entered.wait(timeout: .now() + 2) == .success, "entered real transition boundary")
      let old = f.gate.currentEpoch; f.gate.lock()
      try expect(f.gate.currentEpoch != old && !f.platform.uncovered, "revoke did not wait for write")
      release.signal(); try refuses { _ = try job.value() }
      try expect(f.policy.record.policy == "enable_pending", "interrupted write cannot finish enable")
    }
    test("lock and account events cannot bypass a failed bootstrap drain") {
      let policy = Policy("enabled"), platform = Platform()
      let gate = MeshMessengerAppLock(platform: platform, makeStore: { policy }, cleanStaging: {}, drainNotices: { throw TestFailure.injected })
      try refuses { try gate.bootstrap() }; gate.foreground(ownerSceneID: "scene-one", active: true)
      gate.lock(); gate.accountChanging()
      let expected = gate.currentEpoch, job = Job { try gate.authenticate(expected, ownerSceneID: "scene-one") }
      for _ in 0..<1000 {
        if let id = platform.request() { platform.complete(id, true); break }
        if job.finished() { break }
        Thread.sleep(forTimeInterval: 0.001)
      }
      try refuses { _ = try job.value() }
      try expect(platform.request() == nil, "failed boot cannot start authentication")
      try refuses { try gate.requireEpoch(gate.currentEpoch) }
    }
    test("held OS success cannot restore disabled after background cancellation") {
      let f = try Fixture("disabled"); let (job, id) = try f.start(true)
      f.gate.foreground(ownerSceneID: "scene-one", active: false); f.platform.complete(id, true)
      f.gate.foreground(ownerSceneID: "scene-one", active: false, cancelPending: true)
      try refuses { _ = try job.value() }
      try expect(f.gate.restrictionActive && f.gate.state()["phase"] as? String == "locked", "observed success cannot restore disabled")
    }
    test("manual lock during first opt-in cannot be undone by its cancellation") {
      let f = try Fixture("disabled"); let (job, _) = try f.start(true); f.gate.lock()
      try refuses { _ = try job.value() }
      try expect(f.gate.restrictionActive && f.gate.state()["phase"] as? String == "locked", "newer manual lock wins")
    }
    test("lifecycle cannot publish disabled while initial cleanup is blocked") {
      let policy = Policy("disabled"), platform = Platform(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
      let gate = MeshMessengerAppLock(platform: platform, makeStore: { policy }, cleanStaging: { entered.signal(); _ = release.wait(timeout: .now() + 3) }, drainNotices: {})
      let boot = Job { try gate.bootstrap(); return gate.state() }
      try expect(entered.wait(timeout: .now() + 2) == .success, "cleanup entered")
      gate.foreground(ownerSceneID: "scene-one", active: true)
      let phase = gate.state()["phase"] as? String
      release.signal(); _ = try boot.value()
      try expect(phase == "booting", "no disabled phase before cleanup completes")
    }
    test("plain unlock checks exact persisted policy after OS success") {
      let f = try Fixture(); let (job, id) = try f.start()
      let old = f.policy.record; f.policy.record = .init(install: old.install, sequence: old.sequence + 1, policy: "disable_pending")
      f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.gate.restrictionActive && f.gate.state()["policy"] as? String == "disable_pending", "changed policy requires explicit recovery")
    }
    test("missing persisted policy cannot unlock through cached enabled state") {
      let f = try Fixture(); let (job, id) = try f.start(); f.policy.unreadable = true
      f.platform.complete(id, true); try refuses { _ = try job.value() }
      try expect(f.gate.restrictionActive && f.gate.state()["phase"] as? String == "error", "missing policy fails closed")
    }
    test("foreign native source cannot authenticate cancel or publish readiness") {
      let f = try Fixture(); let old = f.gate.currentEpoch
      let foreign = Job { try f.gate.authenticate(old, ownerSceneID: "scene-two") }
      for _ in 0..<1000 {
        if let id = f.platform.request() { f.platform.complete(id, true); break }
        if foreign.finished() { break }; Thread.sleep(forTimeInterval: 0.001)
      }
      try refuses { _ = try foreign.value() }
      try expect(f.platform.request() == nil && f.gate.currentEpoch == old, "foreign admission has no side effects")
      let (job, id) = try f.start(); f.gate.cancel(id, ownerSceneID: "scene-two")
      f.platform.complete(id, true); _ = try job.value()
      try DispatchQueue.main.sync { try refuses { try f.gate.activate(f.gate.currentEpoch, ownerSceneID: "scene-two") } }
      try expect(!f.platform.uncovered, "foreign readiness leaves owner covered")
      try DispatchQueue.main.sync { try f.gate.activate(f.gate.currentEpoch, ownerSceneID: "scene-one") }
      try expect(f.platform.uncovered, "exact native owner can publish readiness")
    }
    test("clipboard publication cannot finish after a completed revoke") {
      let f = try Fixture(); _ = try f.unlock(); let expected = f.gate.currentEpoch
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), attempting = DispatchSemaphore(value: 0)
      let traceLock = NSLock(); var trace: [String] = []
      f.platform.copy = { _ in
        entered.signal(); _ = release.wait(timeout: .now() + 3)
        traceLock.lock(); trace.append("publication"); traceLock.unlock()
      }
      let copy = Job { try DispatchQueue.main.sync { try f.gate.copyProtectedText("private", expected: expected) }; return [:] }
      try expect(entered.wait(timeout: .now() + 2) == .success, "bounded publication entered")
      let revoke = Job { attempting.signal(); f.gate.lock(); traceLock.lock(); trace.append("revoked"); traceLock.unlock(); return [:] }
      try expect(attempting.wait(timeout: .now() + 2) == .success, "revoke scheduled")
      // Let the competing lock complete if the publisher released its guard.
      for _ in 0..<100 { if revoke.finished() { break }; Thread.sleep(forTimeInterval: 0.001) }
      release.signal(); _ = try copy.value(); _ = try revoke.value()
      try expect(trace == ["publication", "revoked"], "no clipboard write after completed revocation: \(trace)")
      try DispatchQueue.main.sync { try refuses { try f.gate.copyProtectedText("stale", expected: expected) } }
      try expect(trace.count == 2, "stale publication never reaches clipboard")
    }
    test("manual lock during initial policy load survives disabled bootstrap") {
      let policy = Policy("disabled"), platform = Platform(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
      let gate = MeshMessengerAppLock(platform: platform, makeStore: { entered.signal(); _ = release.wait(timeout: .now() + 3); return policy }, cleanStaging: {}, drainNotices: {})
      let boot = Job { try gate.bootstrap(); return gate.state() }
      try expect(entered.wait(timeout: .now() + 2) == .success, "initial policy load held")
      gate.lock(); gate.foreground(ownerSceneID: "scene-one", active: true)
      release.signal(); _ = try boot.value()
      try expect(gate.restrictionActive && gate.state()["phase"] as? String == "locked", "newer manual lock survives disabled load")
      try refuses { try gate.requireEpoch(gate.currentEpoch) }
    }
    test("native cover hide cannot finish after a completed revoke") {
      let f = try Fixture(); _ = try f.unlock(); let expected = f.gate.currentEpoch
      try DispatchQueue.main.sync { try f.gate.activate(expected, ownerSceneID: "scene-one") }
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), attempting = DispatchSemaphore(value: 0)
      let traceLock = NSLock(); var trace: [String] = []
      let hide = Job {
        try DispatchQueue.main.sync {
          try expect(f.gate.commitUncover(expected, ownerSceneID: "scene-one", action: {
            entered.signal(); _ = release.wait(timeout: .now() + 3)
            traceLock.lock(); trace.append("hide"); traceLock.unlock()
          }), "current hide admitted")
        }; return [:]
      }
      try expect(entered.wait(timeout: .now() + 2) == .success, "immediate hide entered")
      let revoke = Job { attempting.signal(); f.gate.lock(); traceLock.lock(); trace.append("revoked"); traceLock.unlock(); return [:] }
      try expect(attempting.wait(timeout: .now() + 2) == .success, "revoke scheduled")
      for _ in 0..<100 { if revoke.finished() { break }; Thread.sleep(forTimeInterval: 0.001) }
      release.signal(); _ = try hide.value(); _ = try revoke.value()
      try expect(trace == ["hide", "revoked"], "no hide after completed revocation: \(trace)")
      try DispatchQueue.main.sync {
        try expect(!f.gate.commitUncover(expected, ownerSceneID: "scene-one", action: { trace.append("stale hide") }), "stale hide refused")
      }
      try expect(trace.count == 2, "stale hide never commits")
    }
    test("native environment ownership is required before startup and scoped access") {
      let policy = Policy("disabled"), platform = Platform()
      let broken = MeshMessengerAppLock(platform: platform, makeStore: { policy }, cleanStaging: {}, drainNotices: {}, validateEnvironment: { throw TestFailure.injected })
      try refuses { try broken.bootstrap() }
      var safe = true
      let f = try Fixture("disabled", environment: { if !safe { throw TestFailure.injected } })
      let expected = f.gate.currentEpoch; try f.gate.requireEpoch(expected); safe = false
      try refuses { try f.gate.requireEpoch(expected) }
      f.gate.foreground(ownerSceneID: "scene-one", active: true)
      try expect(f.gate.state()["phase"] as? String == "error" && f.gate.restrictionActive, "foreground ownership loss stays covered")
    }
    test("native environment loss prevents OS success and actual cover hide") {
      var safe = true
      let f = try Fixture(environment: { if !safe { throw TestFailure.injected } })
      let (job, id) = try f.start(); safe = false; f.platform.complete(id, true)
      try refuses { _ = try job.value() }
      // A separate healthy session isolates hide admission from the failed one.
      safe = true; let g = try Fixture(environment: { if !safe { throw TestFailure.injected } })
      _ = try g.unlock(); let expected = g.gate.currentEpoch
      try DispatchQueue.main.sync { try g.gate.activate(expected, ownerSceneID: "scene-one") }
      safe = false; var hidden = false
      let accepted = DispatchQueue.main.sync { g.gate.commitUncover(expected, ownerSceneID: "scene-one", action: { hidden = true }) }
      try expect(!accepted && !hidden, "ownership loss blocks actual hide")
    }
    test("observed environment loss revokes the visible session before returning to UI") {
      var safe = true
      let f = try Fixture("disabled", environment: { if !safe { throw TestFailure.injected } })
      let expected = f.gate.currentEpoch
      try DispatchQueue.main.sync { try f.gate.activate(expected, ownerSceneID: "scene-one") }
      try expect(f.platform.uncovered, "actual visible session prepared")
      safe = false; try refuses { try f.gate.requireEpoch(expected) }
      DispatchQueue.main.sync {}
      try expect(!f.platform.uncovered && f.gate.currentEpoch != expected && f.gate.state()["phase"] as? String == "error", "ownership failure must cover and revoke without a later lifecycle event")
      safe = true
      try refuses { try f.gate.requireEpoch(expected) }
      try refuses { try f.gate.requireEpoch(f.gate.currentEpoch) }
    }
    print("IOS_CONTROLLER_HOST_RESULT failures=\(failures) groups=31")
    if failures != 0 { exit(1) }
  }
}
