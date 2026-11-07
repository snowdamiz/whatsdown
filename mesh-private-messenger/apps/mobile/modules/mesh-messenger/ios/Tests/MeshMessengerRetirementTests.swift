import Foundation
import CoreFoundation

private enum Failure: Error { case assertion(String), unavailable }
private func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw Failure.assertion(message) }
}
private func refuses(_ action: () throws -> Void) throws {
  do { try action() } catch { return }
  throw Failure.assertion("retired native binding remained current")
}
private final class Object {}
private final class Mount: MeshMessengerNativeMountObservation {
  func isCurrent() -> Bool { true }
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  let record = MeshMessengerAppLockPolicy.Record(install: UUID().uuidString.lowercased(), sequence: 0, policy: "disabled")
  func load() throws -> MeshMessengerAppLockPolicy.Record { record }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record { throw Failure.unavailable }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval { ProcessInfo.processInfo.systemUptime }
  var canAuthenticate: Bool { false }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) { completion(false) }
  func cancel(requestID: String) {}
  func copyText(_ text: String) {}
  func render(state: [String: Any], uncover: Bool) {}
}
private final class Fixture {
  let gate: MeshMessengerAppLock
  var root = Object()
  let owner = Object(), context = Object(), module = Object(), window = Object(), scene = Object()
  let moduleID = UUID()
  lazy var bindings = MeshMessengerRootBindings(gate: gate) { [unowned self] root, owner in
    guard root === self.root, owner === self.root || owner === self.owner else { return nil }
    return .init(window: window, scene: scene, sceneID: "scene", active: true, mount: Mount())
  }
  init() throws {
    let policy = Policy()
    gate = MeshMessengerAppLock(platform: Platform(), makeStore: { policy }, cleanStaging: {}, drainNotices: {})
    let ready = DispatchSemaphore(value: 0), gate = gate
    DispatchQueue.global().async { try? gate.bootstrap(); ready.signal() }
    try check(ready.wait(timeout: .now() + 2) == .success, "gate bootstrap barrier")
    try gate.requireEpoch(gate.currentEpoch)
    gate.foreground(ownerSceneID: "scene", active: true)
    try bindings.registerModule(module, context: context, registeredModule: module, moduleID: moduleID)
  }
  func attach() throws -> (UUID, MeshMessengerRootBindings.Lease) {
    let id = try bindings.registerRoot(root)
    bindings.rootWindowDidChange(id)
    return (id, try bindings.capture(owner: owner, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: gate.currentEpoch))
  }
}

// The Main thread does not drain its queue until explicitly released below.
// These exercise the production retirement dispatcher, RootBindings and gate.
// Identity ports do not qualify UIKit deallocation or React mutation timing.
@main private enum RetirementTests {
  static func main() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") }
      catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("Main owner retirement changes native authority before returning with Main queue held") {
      let f = try Fixture(), (_, lease) = try f.attach(), epoch = f.gate.currentEpoch
      MeshMessengerNativeRetirement.onMain { f.bindings.retireOwner(lease) }
      try check(f.gate.currentEpoch != epoch, "owner retirement was deferred past return")
      try refuses { _ = try f.bindings.validate(lease) }
    }
    test("Main root retirement changes native authority before returning with Main queue held") {
      let f = try Fixture(), (rootID, lease) = try f.attach(), epoch = f.gate.currentEpoch
      MeshMessengerNativeRetirement.onMain { f.bindings.detachRoot(rootID) }
      try check(f.gate.currentEpoch != epoch, "root retirement was deferred past return")
      try refuses { _ = try f.bindings.validate(lease) }
    }
    test("off-Main retirement returns while Main is held and delayed old loss preserves successor") {
      let f = try Fixture(), (oldID, oldLease) = try f.attach(), oldEpoch = f.gate.currentEpoch
      let submitted = DispatchSemaphore(value: 0)
      DispatchQueue.global().async {
        MeshMessengerNativeRetirement.onMain { f.bindings.detachRoot(oldID); f.bindings.retireOwner(oldLease) }
        submitted.signal()
      }
      try check(submitted.wait(timeout: .now() + 2) == .success, "off-Main retirement must not wait for Main")
      try check(f.gate.currentEpoch == oldEpoch, "off-Main retirement remains deferred; no closure claim")
      f.root = Object()
      let (_, fresh) = try f.attach(), freshEpoch = f.gate.currentEpoch
      var drained = false
      let loop = CFRunLoopGetMain()
      DispatchQueue.main.async { drained = true; CFRunLoopStop(loop) }
      DispatchQueue.global().asyncAfter(deadline: .now() + 2) { CFRunLoopStop(loop) }
      CFRunLoopRun()
      try check(drained, "queued retirement completion barrier")
      try check(f.gate.currentEpoch == freshEpoch, "delayed old retirement revoked successor")
      _ = try f.bindings.validate(fresh)
      try refuses { _ = try f.bindings.validate(oldLease) }
    }
    print("RESULT \(3 - failures)/3 native retirement groups passed")
    if failures != 0 { exit(1) }
  }
}
