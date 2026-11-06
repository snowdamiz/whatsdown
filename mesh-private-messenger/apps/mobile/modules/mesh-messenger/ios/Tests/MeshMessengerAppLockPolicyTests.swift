import Foundation

private let installation = "c0799707-eae0-4c7b-a3e3-166aa9a86750"
private let otherInstallation = "026045f0-17b8-4ffa-bb81-84000cec349c"
private func encoded(_ policy: String, _ sequence: Int64 = 0, _ install: String = installation) -> Data {
  Data("{\"version\":1,\"install\":\"\(install)\",\"sequence\":\(sequence),\"policy\":\"\(policy)\"}".utf8)
}
private func marker(_ install: String = installation) -> Data { Data("AL1:\(install)\n".utf8) }
private enum TestFailure: Error { case expectation(String), injected }
private func expect(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
  if try !value() { throw TestFailure.expectation(message) }
}
private func refused(_ work: () throws -> Void) throws {
  do { try work() } catch { return }
  throw TestFailure.expectation("operation unexpectedly succeeded")
}
private final class Store: MeshMessengerAppLockPolicyStorage {
  var markerData: Data?
  var recordData: Data?
  var calls: [String] = []
  var fail: String?
  var commitThenFail: String?
  var corruptAfterUpdate = false
  func before(_ name: String) throws { calls.append(name); if fail == name { throw TestFailure.injected } }
  func after(_ name: String) throws { if commitThenFail == name { throw TestFailure.injected } }
  func readMarker() throws -> Data? { try before("readMarker"); return markerData }
  func createMarker(_ data: Data) throws { try before("createMarker"); guard markerData == nil else { throw TestFailure.injected }; markerData = data; try after("createMarker") }
  func readRecord() throws -> Data? { try before("readRecord"); return recordData }
  func createRecord(_ data: Data) throws { try before("createRecord"); guard recordData == nil else { throw TestFailure.injected }; recordData = data; try after("createRecord") }
  func updateRecord(_ data: Data) throws { try before("updateRecord"); guard recordData != nil else { throw TestFailure.injected }; recordData = corruptAfterUpdate ? Data([0]) : data; try after("updateRecord") }
  var writes: [String] { calls.filter { $0.hasPrefix("create") || $0 == "updateRecord" } }
}
private func policy(_ store: Store) -> MeshMessengerAppLockPolicy {
  MeshMessengerAppLockPolicy(storage: store, makeInstall: { installation })
}
private func existing(_ state: String = "enabled", _ sequence: Int64 = 4) -> Store {
  let store = Store(); store.markerData = marker(); store.recordData = encoded(state, sequence); return store
}

@main struct PolicyTests {
  static func main() {
    let tests: [(String, () throws -> Void)] = [
      ("fresh bootstrap persists marker before disabled record and reads both back", {
        let store = Store(); let value = try policy(store).load()
        try expect(value == .init(install: installation, sequence: 0, policy: "disabled"), "initial record")
        try expect(store.writes == ["createMarker", "createRecord"], "marker must precede record")
        try expect(store.markerData == marker() && store.recordData == encoded("disabled"), "exact durable bytes")
        try expect(store.calls.suffix(2).contains("readRecord") && store.calls.suffix(2).contains("readMarker"), "checked readback")
      }),
      ("fresh policy readers preserve existing enabled and both pending states", {
        for state in ["disabled", "enabled", "enable_pending", "disable_pending"] {
          let store = existing(state); let value = try policy(store).load()
          try expect(value.policy == state && value.sequence == 4, "stored authority")
          try expect(store.writes.isEmpty, "reload cannot rewrite policy")
        }
      }),
      ("surviving valid policy repairs absent marker without policy rewrite", {
        let store = existing(); store.markerData = nil
        try expect(try policy(store).load().policy == "enabled", "policy preserved")
        try expect(store.markerData == marker() && store.writes == ["createMarker"], "repair only marker")
      }),
      ("marker without policy and mismatched or malformed marker fail without writes", {
        for data in [marker(), marker(otherInstallation), Data(), Data("AL1\n".utf8)] {
          let store = existing(); store.markerData = data
          if data == marker() { store.recordData = nil }
          try refused { _ = try policy(store).load() }; try expect(store.writes.isEmpty, "no permissive repair")
        }
      }),
      ("interrupted marker-first bootstrap cannot be retried as a fresh install", {
        let store = Store(); store.commitThenFail = "createMarker"
        try refused { _ = try policy(store).load() }
        try expect(store.recordData == nil && store.markerData == marker(), "interruption state")
        store.commitThenFail = nil
        try refused { _ = try policy(store).load() }; try expect(store.writes == ["createMarker"], "no second bootstrap")
      }),
      ("failed initial record add retains restrictive initialization evidence", {
        let store = Store(); store.fail = "createRecord"
        try refused { _ = try policy(store).load() }; store.fail = nil
        try refused { _ = try policy(store).load() }
        try expect(store.markerData == marker() && store.recordData == nil, "marker not erased")
      }),
      ("unreadable policy or marker is never classified as absence", {
        for point in ["readMarker", "readRecord"] {
          let store = Store(); store.fail = point
          try refused { _ = try policy(store).load() }; try expect(store.writes.isEmpty, "no bootstrap after read failure")
        }
      }),
      ("enable and disable each persist pending before final state", {
        let store = existing("disabled", 0); let p = policy(store)
        let a = try p.load(); let b = try p.transition(previous: a, desired: "enable_pending")
        let c = try p.transition(previous: b, desired: "enabled")
        let d = try p.transition(previous: c, desired: "disable_pending")
        let e = try p.transition(previous: d, desired: "disabled")
        try expect([a.sequence,b.sequence,c.sequence,d.sequence,e.sequence] == [0,1,2,3,4], "monotonic checked writes")
        try expect(try policy(store).load() == e, "durable final")
      }),
      ("pending recovery permits freshly authenticated choice in either direction", {
        for start in ["enable_pending", "disable_pending"] {
          for desired in ["enable_pending", "disable_pending"] {
            let store = existing(start); let p = policy(store)
            let next = try p.transition(previous: p.load(), desired: desired)
            try expect(next.policy == desired && next.sequence == 5, "pending recovery")
          }
        }
      }),
      ("stale record and installation cannot overwrite current policy", {
        let store = existing(); let p = policy(store)
        for previous in [MeshMessengerAppLockPolicy.Record(install: installation, sequence: 3, policy: "enabled"), .init(install: otherInstallation, sequence: 4, policy: "enabled")] {
          try refused { _ = try p.transition(previous: previous, desired: "disable_pending") }
        }
        try expect(store.writes.isEmpty, "stale transition wrote")
      }),
      ("direct final-state changes and wrong pending completion fail", {
        for pair in [("enabled","disabled"),("disabled","enabled"),("enable_pending","disabled"),("disable_pending","enabled"),("enabled","unknown"),("disabled","disable_pending"),("enabled","enable_pending")] {
          let store = existing(pair.0); let p = policy(store); let previous = try p.load()
          try refused { _ = try p.transition(previous: previous, desired: pair.1) }
          try expect(store.writes.isEmpty, "invalid transition wrote")
        }
      }),
      ("commit-then-error preserves durable pending and does not restore disabled", {
        let store = existing("disabled"); let p = policy(store); let previous = try p.load()
        store.commitThenFail = "updateRecord"
        try refused { _ = try p.transition(previous: previous, desired: "enable_pending") }
        store.commitThenFail = nil
        try expect(try policy(store).load().policy == "enable_pending", "pending lost after reported failure")
        try expect(store.writes == ["updateRecord"], "failure attempted rollback")
      }),
      ("mismatched post-write readback never reports success", {
        let store = existing("disabled"); let p = policy(store); let previous = try p.load()
        store.corruptAfterUpdate = true
        try refused { _ = try p.transition(previous: previous, desired: "enable_pending") }
        try refused { _ = try policy(store).load() }
        try expect(store.writes == ["updateRecord"], "no repair after corruption")
      }),
      ("sequence bound is checked before mutation", {
        let store = existing("enabled", 9_007_199_254_740_990); let p = policy(store)
        try refused { _ = try p.transition(previous: p.load(), desired: "disable_pending") }
        try expect(store.writes.isEmpty, "overflow write")
      }),
      ("two policy instances serialize concurrent writers and preserve exactly one winner", {
        let store = existing("disabled"); let a = policy(store); let b = policy(store)
        let previous = try a.load(); let group = DispatchGroup(); let lock = NSLock()
        var winners = 0; var stale = 0
        for writer in [a, b] {
          group.enter(); DispatchQueue.global().async {
            defer { group.leave() }
            do { _ = try writer.transition(previous: previous, desired: "enable_pending"); lock.lock(); winners += 1; lock.unlock() }
            catch MeshMessengerAppLockPolicy.Failure.policyChanged { lock.lock(); stale += 1; lock.unlock() }
            catch { }
          }
        }
        group.wait()
        try expect(winners == 1 && stale == 1 && store.writes == ["updateRecord"], "concurrent write arbitration")
        try expect(try a.load() == .init(install: installation, sequence: 5, policy: "enable_pending"), "winner preserved")
      }),
      ("malformed unknown duplicate and noncanonical record encodings are refused", {
        let valid = String(data: encoded("enabled"), encoding: .utf8)!
        let invalid = ["", "{}", valid + " ", valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":true"), valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"), valid.replacingOccurrences(of: "\"sequence\":0", with: "\"sequence\":0.0"), valid.replacingOccurrences(of: "\"policy\":\"enabled\"", with: "\"policy\":\"invalid\""), valid.replacingOccurrences(of: "\"version\":1", with: "\"extra\":1,\"version\":1"), valid.replacingOccurrences(of: installation, with: installation.uppercased()), String(repeating: "x", count: 4097)]
        for text in invalid {
          let store = existing(); store.recordData = Data(text.utf8)
          try refused { _ = try policy(store).load() }; try expect(store.writes.isEmpty, "malformed repair")
        }
      }),
      ("real marker storage persists exact bytes and refuses overwrite or symlinks", {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("morse-policy-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("policy", isDirectory: true)
        let file = directory.appendingPathComponent("policy-initialized.v1")
        let store = try MeshMessengerAppLockPolicyMarker(directory: directory)
        try expect(try store.read() == nil, "fresh marker absence")
        try store.create(marker()); try expect(try store.read() == marker(), "actual file readback")
        try refused { try store.create(marker(otherInstallation)) }
        try expect(try store.read() == marker(), "overwrite changed marker")
        try expect(try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true, "backup exclusion")
        try FileManager.default.removeItem(at: file)
        let target = root.appendingPathComponent("other"); try marker().write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        try refused { _ = try store.read() }
        try refused { try store.create(marker()) }
      }),
      ("real marker storage refuses empty partial and broadly readable markers", {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("morse-policy-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("policy", isDirectory: true)
        let store = try MeshMessengerAppLockPolicyMarker(directory: directory)
        let file = directory.appendingPathComponent("policy-initialized.v1")
        try store.create(marker())
        try Data().write(to: file)
        try refused { _ = try store.read() }
        try marker().write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        try refused { _ = try store.read() }
      })
    ]
    let semaphore = DispatchSemaphore(value: 0)
    var failures = 0
    do { _ = try policy(Store()).load(); failures += 1; print("FAIL main-thread policy IO admitted") }
    catch MeshMessengerAppLockPolicy.Failure.backgroundRequired { print("PASS main-thread policy IO refused") }
    catch { failures += 1; print("FAIL main-thread refusal returned wrong failure") }
    DispatchQueue.global().async {
      for (name, body) in tests {
        do { try body(); print("PASS \(name)") }
        catch { failures += 1; print("FAIL \(name): \(error)") }
      }
      semaphore.signal()
    }
    semaphore.wait()
    print("RESULT \(tests.count + 1 - failures) passed; \(failures) failed")
    exit(failures == 0 ? 0 : 1)
  }
}
