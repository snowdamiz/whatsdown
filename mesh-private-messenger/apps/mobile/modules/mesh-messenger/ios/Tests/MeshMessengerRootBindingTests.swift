import Foundation

private enum CheckFailure: Error { case assertion(String), injected }
private func check(_ value: @autoclosure () throws -> Bool, _ why: String) throws {
  if try !value() { throw CheckFailure.assertion(why) }
}
private func refuses(_ body: () throws -> Void) throws {
  do { try body() } catch CheckFailure.assertion(let why) { throw CheckFailure.assertion(why) } catch { return }
  throw CheckFailure.assertion("expected refusal")
}
private final class ValueBox<T> {
  private let lock = NSLock(); private var value: T
  init(_ value: T) { self.value = value }
  func get() -> T { lock.lock(); defer { lock.unlock() }; return value }
  func set(_ next: T) { lock.lock(); value = next; lock.unlock() }
}
private final class NativeObject {}
// Foundation observation port only: these are native identity/refusal tests,
// not a UIKit, Fabric, Expo registry or production reload reproduction.
private final class MountObservation: MeshMessengerNativeMountObservation {
  weak var fixture: Fixture?, host: AnyObject?, presenter: AnyObject?, surface: AnyObject?, owner: AnyObject?
  init(_ fixture: Fixture, owner: AnyObject) {
    self.fixture = fixture; host = fixture.host; presenter = fixture.presenter
    surface = fixture.nativeSurface; self.owner = owner
  }
  func isCurrent() -> Bool {
    guard let fixture, let owner, let host, let presenter, let surface else { return false }
    return fixture.host === host && fixture.presenter === presenter && fixture.nativeSurface === surface &&
      fixture.rootTagMatchesSurface && !fixture.absentOwners.contains(ObjectIdentifier(owner)) &&
      fixture.registryReplacements[ObjectIdentifier(owner)] == nil
  }
}
private final class WeakObject {
  weak var value: AnyObject?
  init(_ value: AnyObject?) { self.value = value }
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  let record = MeshMessengerAppLockPolicy.Record(install: UUID().uuidString.lowercased(), sequence: 0, policy: "disabled")
  func load() throws -> MeshMessengerAppLockPolicy.Record { record }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record { throw CheckFailure.injected }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval { ProcessInfo.processInfo.systemUptime }
  var canAuthenticate = false
  var presentations = 0
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) { presentations += 1; completion(false) }
  func cancel(requestID: String) {}
  func render(state: [String: Any], uncover: Bool) {}
  func copyText(_ text: String) {}
}
private final class Fixture {
  let gate: MeshMessengerAppLock, platform: Platform
  var root: NativeObject? = NativeObject(), owner: NativeObject? = NativeObject()
  var context: NativeObject? = NativeObject(), module: NativeObject? = NativeObject()
  var window: NativeObject? = NativeObject(), scene: NativeObject? = NativeObject()
  var active = true
  var host = NativeObject(), presenter = NativeObject(), nativeSurface = NativeObject()
  var rootTagMatchesSurface = true
  var absentOwners = Set<ObjectIdentifier>()
  var registryReplacements: [ObjectIdentifier: NativeObject] = [:]
  var moduleID = UUID()
  var descendants = Set<ObjectIdentifier>()
  lazy var bindings = MeshMessengerRootBindings(gate: gate) { [weak self] root, owner in
    guard let self, let current = self.root, root === current,
          owner === root || self.descendants.contains(ObjectIdentifier(owner)),
          let window = self.window, let scene = self.scene else { return nil }
    return MeshMessengerRootBindings.Surface(window: window, scene: scene, sceneID: "owned-scene", active: self.active, mount: MountObservation(self, owner: owner))
  }
  init() throws {
    platform = Platform(); let policy = Policy()
    gate = MeshMessengerAppLock(platform: platform, makeStore: { policy }, cleanStaging: {}, drainNotices: {})
    let result = ValueBox<Result<Void, Error>?>(nil), done = DispatchSemaphore(value: 0), ownedGate = gate
    DispatchQueue.global().async {
      do { try ownedGate.bootstrap(); result.set(.success(())) } catch { result.set(.failure(error)) }; done.signal()
    }
    try check(done.wait(timeout: .now() + 2) == .success, "actual native gate bootstrap completed")
    guard let result = result.get() else { throw CheckFailure.assertion("bootstrap outcome") }; try result.get()
    gate.foreground(ownerSceneID: "owned-scene", active: true)
    descendants.insert(ObjectIdentifier(owner!))
  }
  func start() throws -> UUID {
    let token = try bindings.registerRoot(root!); bindings.rootWindowDidChange(token); return token
  }
  func admitModule(registered: AnyObject? = nil) throws {
    try bindings.registerModule(module!, context: context!, registeredModule: registered ?? module!, moduleID: moduleID)
  }
  func capture(expected: String? = nil) throws -> MeshMessengerRootBindings.Lease {
    try admitModule()
    return try bindings.capture(owner: owner!, viewContext: context!, module: module!, moduleContext: context!, moduleID: moduleID, expected: expected ?? gate.currentEpoch)
  }
  func freshOwnerAndModule() {
    owner = NativeObject(); module = NativeObject(); moduleID = UUID(); descendants.insert(ObjectIdentifier(owner!))
  }
  func rotateActualNativeEpoch() {
    gate.foreground(ownerSceneID: "owned-scene", active: false)
    gate.foreground(ownerSceneID: "owned-scene", active: true)
  }
}

private final class StartupPolicyStorage: MeshMessengerAppLockPolicyStorage {
  var marker: Data?, record: Data?
  func readMarker() throws -> Data? { marker }
  func readRecord() throws -> Data? { record }
  func createMarker(_ data: Data) throws { guard marker == nil else { throw CheckFailure.injected }; marker = data }
  func createRecord(_ data: Data) throws { guard record == nil else { throw CheckFailure.injected }; record = data }
  func updateRecord(_ data: Data) throws { guard record != nil else { throw CheckFailure.injected }; record = data }
}
private final class StartupNoticePort: MeshMessengerNoticePort {
  var ownsDelegate = true
  var pendingIDs = ["old-pending"], deliveredIDs = ["old-delivered"]
  func add(_ notice: MeshMessengerNotice, completion: @escaping (Error?) -> Void) { completion(CheckFailure.injected) }
  func pending(_ completion: @escaping ([String]) -> Void) { completion(pendingIDs) }
  func delivered(_ completion: @escaping ([String]) -> Void) { completion(deliveredIDs) }
  func removePending(_ identifiers: [String]) { pendingIDs.removeAll { identifiers.contains($0) } }
  func removeDelivered(_ identifiers: [String]) { deliveredIDs.removeAll { identifiers.contains($0) } }
  func removeAllPending() { pendingIDs = [] }
  func removeAllDelivered() { deliveredIDs = [] }
}
private final class StartupFixture {
  let startup = MeshMessengerNativeStartup(), policy = MeshMessengerAppLockPolicy(storage: StartupPolicyStorage())
  let platform = Platform(), noticePort = StartupNoticePort()
  let directory: URL, root: URL, documents: URL, orphan: URL, original: URL
  var protectionCount = 0, storagePrepared = false
  lazy var gate = MeshMessengerAppLock(platform: platform, makeStore: { [unowned self] in self.policy },
    cleanStaging: { [unowned self] in try self.startup.clean() },
    drainNotices: { [unowned self] in try self.startup.drain() },
    validateEnvironment: { [unowned self] in try self.startup.validate() })
  init() throws {
    directory = FileManager.default.temporaryDirectory.appendingPathComponent("morse-startup-owned-" + UUID().uuidString, isDirectory: true)
    root = directory.appendingPathComponent("stage", isDirectory: true); documents = directory.appendingPathComponent("documents", isDirectory: true)
    orphan = root.appendingPathComponent("old-stage"); original = documents.appendingPathComponent("original-account")
    for path in [root, documents] { try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true) }
    try Data("sealed-owned-stage".utf8).write(to: orphan); try Data("preserve-original".utf8).write(to: original)
  }
  deinit { try? FileManager.default.removeItem(at: directory) }
  func worker<T>(_ body: @escaping () throws -> T) throws -> T {
    let result = ValueBox<Result<T, Error>?>(nil), done = DispatchSemaphore(value: 0)
    DispatchQueue.global().async { result.set(Result { try body() }); done.signal() }
    try check(done.wait(timeout: .now() + 3) == .success, "actual native startup worker completed")
    guard let result = result.get() else { throw CheckFailure.assertion("startup worker result") }; return try result.get()
  }
  func seedEnabledPolicy() throws {
    try worker { [self] in
      let disabled = try policy.load(), pending = try policy.transition(previous: disabled, desired: "enable_pending")
      _ = try policy.transition(previous: pending, desired: "enabled")
    }
  }
  func services() throws -> MeshMessengerNativeStartup.Services {
    let files = MeshMessengerProtectedFiles(gate: gate, root: root, documents: documents,
      profile: { [unowned self] expected in
        try self.gate.requireEpoch(expected)
        func field(_ data: Data) -> Data {
          let count = data.count
          return Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16), UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]) + data
        }
        return Data([0, 0, 0, 4]) + field(Data("Startup fixture".utf8)) + field(Data(repeating: 1, count: 32)) + field(Data(repeating: 2, count: 16)) + field(Data())
      }, choose: { _, _ in nil })
    let notices = MeshMessengerLockedNotifications(gate: gate, port: noticePort, deadlineSeconds: 1)
    return MeshMessengerNativeStartup.Services(files: files, notices: notices, prepareStorage: { [unowned self] in
      var path = self.documents, flags = URLResourceValues(); flags.isExcludedFromBackup = true
      try path.setResourceValues(flags)
      guard try path.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else { throw CheckFailure.injected }
      self.storagePrepared = true
    })
  }
  func protect() {
    protectionCount += 1
    _ = gate.onRevoke { [weak startup] in startup?.revoke() }
  }
}

private final class NativeSubmissionPort: MeshMessengerNoticePort {
  var beforeOwnershipRead: (() -> Void)?
  var adds = 0
  var ownsDelegate: Bool { let hook = beforeOwnershipRead; beforeOwnershipRead = nil; hook?(); return true }
  func add(_ notice: MeshMessengerNotice, completion: @escaping (Error?) -> Void) { adds += 1; completion(nil) }
  func pending(_ completion: @escaping ([String]) -> Void) { completion([]) }
  func delivered(_ completion: @escaping ([String]) -> Void) { completion([]) }
  func removePending(_ identifiers: [String]) {}
  func removeDelivered(_ identifiers: [String]) {}
  func removeAllPending() {}
  func removeAllDelivered() {}
}

@main private enum RootBindingTests {
  static func main() {
    if CommandLine.arguments.contains("--startup") { runStartup(); return }
    if CommandLine.arguments.contains("--owner-scope") { runOwnerScope(); return }
    if CommandLine.arguments.contains("--publication") { runPublication(); return }
    if CommandLine.arguments.contains("--headless-admission") { runHeadlessAdmission(); return }
    if CommandLine.arguments.contains("--owner-construction") { runOwnerConstruction(); return }
    if CommandLine.arguments.contains("--account-transition") { runAccountTransitions(); return }
    if CommandLine.arguments.contains("--headless-lifetime") { runHeadlessLifetime(); return }
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("exact native root context window and scene registration does not grant authentication") {
      let f = try Fixture(), token = try f.start(), expected = f.gate.currentEpoch
      let lease = try f.capture(expected: expected)
      try check(lease.rootID == token && lease.epoch == expected && lease.account == f.gate.accountGeneration, "immutable actual native lease identities")
      try check(try f.bindings.validate(lease) == "owned-scene", "exact native owner accepted")
      try check(f.gate.currentEpoch == expected && f.gate.state()["phase"] as? String == "disabled" && f.platform.presentations == 0, "registration is not OS authentication or epoch refresh")
    }
    test("missing wrong-context or unrelated native owner cannot replace a valid registration") {
      let f = try Fixture(); _ = try f.start(); let good = try f.capture(), expected = f.gate.currentEpoch
      try refuses { _ = try f.bindings.capture(owner: f.owner!, viewContext: NativeObject(), module: f.module!, moduleContext: f.context!, moduleID: f.moduleID, expected: expected) }
      try refuses { _ = try f.bindings.capture(owner: NativeObject(), viewContext: f.context!, module: f.module!, moduleContext: f.context!, moduleID: f.moduleID, expected: expected) }
      try check(try f.bindings.validate(good) == "owned-scene" && f.gate.currentEpoch == expected, "pre-admission refusal preserves current binding")
      f.window = nil
      try refuses { _ = try f.capture() }
      try refuses { _ = try f.bindings.validate(good) }
    }
    test("ambiguous second live owner cannot replace the actual current owner") {
      let f = try Fixture(); _ = try f.start(); let good = try f.capture(), first = f.owner!, expected = f.gate.currentEpoch
      f.owner = NativeObject(); f.descendants.insert(ObjectIdentifier(f.owner!))
      try refuses { _ = try f.capture() }
      try check(try f.bindings.validate(good) == "owned-scene" && good.owner === first && f.gate.currentEpoch == expected, "ambiguous owner refusal preserves current exact lease")
    }
    test("root replacement invalidates old lease but late old root detach cannot revoke the fresh root") {
      let f = try Fixture(), oldRoot = try f.start(), old = try f.capture()
      f.root = NativeObject(); f.freshOwnerAndModule(); let freshRoot = try f.start(), fresh = try f.capture(), epoch = f.gate.currentEpoch
      try check(freshRoot != oldRoot && fresh.epoch != old.epoch, "genuine native root replacement rotates authority")
      try refuses { _ = try f.bindings.validate(old) }
      f.bindings.detachRoot(oldRoot)
      try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch, "late obsolete root teardown cannot affect replacement")
    }
    test("old Module destruction with reused AppContext cannot revoke a newer Module registration") {
      let f = try Fixture(); _ = try f.start(); let old = try f.capture(), oldID = f.moduleID, sameContext = f.context
      f.rotateActualNativeEpoch(); f.freshOwnerAndModule(); let fresh = try f.capture(), epoch = f.gate.currentEpoch
      try check(f.context === sameContext && fresh.moduleID != oldID, "same real context distinct native Module identities")
      f.bindings.retireModule(oldID)
      try refuses { _ = try f.bindings.validate(old) }
      try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch, "old destroy cannot close fresh Module")
    }
    test("delayed old probe teardown cannot close a genuinely admitted fresh native epoch") {
      let f = try Fixture(); _ = try f.start(); let old = try f.capture()
      f.rotateActualNativeEpoch(); let fresh = try f.capture(), epoch = f.gate.currentEpoch
      try check(fresh.id != old.id && fresh.epoch != old.epoch, "explicit fresh registration actual epoch")
      f.bindings.retireOwner(old)
      try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch, "old owner token cannot revoke new registration")
    }
    test("account change rejects old completion and old cleanup never refreshes its lease") {
      let f = try Fixture(); _ = try f.start(); let old = try f.capture()
      f.gate.accountChanging(); try refuses { _ = try f.bindings.validate(old) }
      let fresh = try f.capture(), epoch = f.gate.currentEpoch
      try check(fresh.account != old.account && fresh.epoch != old.epoch, "actual native account and epoch changed")
      f.bindings.retireOwner(old)
      try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch, "old cleanup preserves explicit fresh account lease")
    }
    test("weak native owner and root loss cannot be replaced by a global lookup") {
      let f = try Fixture(); _ = try f.start(); let owned = try f.capture()
      let weakOwner = WeakObject(f.owner); f.owner = nil
      try check(weakOwner.value == nil, "registry and lease do not retain owner")
      try refuses { _ = try f.bindings.validate(owned) }
      let weakRoot = WeakObject(f.root); f.root = nil
      try check(weakRoot.value == nil, "registry and lease do not retain root")
      try refuses { _ = try f.bindings.validate(owned) }
    }
    test("current Module teardown revokes once and repeated teardown preserves later locked-owner registration") {
      let f = try Fixture(); _ = try f.start(); let old = try f.capture(), oldID = f.moduleID
      f.bindings.retireModule(oldID); let epoch = f.gate.currentEpoch
      try check(epoch != old.epoch && f.gate.state()["phase"] as? String == "locked", "actual current owner loss restricts native gate")
      f.freshOwnerAndModule(); let fresh = try f.capture()
      f.bindings.retireModule(oldID); f.bindings.retireOwner(old)
      try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch && f.gate.state()["phase"] as? String == "locked", "new locked UI owner is provenance only, never an unlock")
    }
    test("same native window becoming inactive is not root detach while actual window loss is") {
      let f = try Fixture(), rootID = try f.start(), lease = try f.capture(), epoch = f.gate.currentEpoch
      f.active = false; f.bindings.rootWindowDidChange(rootID)
      try check(f.gate.currentEpoch == epoch, "root observer must not reinterpret owned prompt inactivity")
      f.window = nil; f.bindings.rootWindowDidChange(rootID)
      try check(f.gate.currentEpoch != epoch, "actual root window loss revokes authority")
      try refuses { _ = try f.bindings.validate(lease) }
    }
    test("delayed old registration cannot reclaim newer owner in same or different native AppContext") {
      for sameContext in [true, false] {
        let f = try Fixture(); _ = try f.start()
        let oldOwner = f.owner!, oldContext = f.context!, oldModule = f.module!, oldID = f.moduleID
        let originalExpected = f.gate.currentEpoch
        // Genuine ordering: old native callback captured its arguments, but no
        // owner was registered before the newer native view callback completed.
        f.freshOwnerAndModule(); if !sameContext { f.context = NativeObject() }
        let fresh = try f.capture(expected: originalExpected), epoch = f.gate.currentEpoch
        try check(epoch == originalExpected, "registration did not invent a new native epoch")
        // A delayed didCreate must not even admit the old Module after the
        // newer exact owner completed; no callback may claim global authority.
        try refuses {
          try f.bindings.registerModule(oldModule, context: oldContext,
            registeredModule: sameContext ? f.module! : oldModule, moduleID: oldID)
        }
        try refuses {
          _ = try f.bindings.capture(owner: oldOwner, viewContext: oldContext, module: oldModule,
            moduleContext: oldContext, moduleID: oldID, expected: originalExpected)
        }
        try check(try f.bindings.validate(fresh) == "owned-scene" && f.gate.currentEpoch == epoch, "delayed old claimant cannot replace or revoke new owner")
      }
    }
    test("repeated exact root and owner callback is idempotent and never retires its own lease") {
      let f = try Fixture(), rootID = try f.start(), first = try f.capture(), epoch = f.gate.currentEpoch
      let repeatedRoot = try f.bindings.registerRoot(f.root!)
      f.bindings.rootWindowDidChange(repeatedRoot)
      let repeated = try f.capture(expected: epoch)
      try check(repeatedRoot == rootID && repeated.id == first.id && f.gate.currentEpoch == epoch, "same native callback preserves exact registration")
      try check(try f.bindings.validate(first) == "owned-scene", "repeated bind does not retire current owner")
      f.bindings.retireOwner(first); let revoked = f.gate.currentEpoch
      try check(revoked != epoch, "genuine current detach revokes once")
      try refuses { _ = try f.capture(expected: epoch) }
      try check(f.gate.currentEpoch == revoked, "repeated old admission refusal cannot relock fresh state")
    }
    test("unregistered native create refuses before mutation and exact repeated create is harmless") {
      let f = try Fixture(); _ = try f.start(); let epoch = f.gate.currentEpoch
      try refuses { try f.bindings.registerModule(f.module!, context: f.context!, registeredModule: nil, moduleID: f.moduleID) }
      try refuses { try f.bindings.registerModule(f.module!, context: f.context!, registeredModule: NativeObject(), moduleID: f.moduleID) }
      try refuses {
        _ = try f.bindings.capture(owner: f.owner!, viewContext: f.context!, module: f.module!,
          moduleContext: f.context!, moduleID: f.moduleID, expected: epoch)
      }
      try check(f.gate.currentEpoch == epoch, "unregistered create does not rotate or claim gate authority")
      try f.admitModule(); let first = try f.capture(expected: epoch)
      try f.admitModule(); let repeated = try f.capture(expected: epoch)
      try check(first.id == repeated.id && f.gate.currentEpoch == epoch, "actual exact repeated creation is idempotent")
      f.bindings.retireModule(f.moduleID); let revoked = f.gate.currentEpoch
      try refuses { try f.admitModule() }
      try check(f.gate.currentEpoch == revoked, "retired Module create cannot resurrect or relock")
    }
    test("previously admitted old Module cannot repeat create after a newer owner and fresh public epoch") {
      let f = try Fixture(); _ = try f.start(); _ = try f.capture()
      let oldOwner = f.owner!, oldContext = f.context!, oldModule = f.module!, oldID = f.moduleID
      f.rotateActualNativeEpoch(); f.freshOwnerAndModule(); f.context = NativeObject()
      _ = try f.capture(); f.rotateActualNativeEpoch(); let publicEpoch = f.gate.currentEpoch
      try check(f.descendants.contains(ObjectIdentifier(oldOwner)), "old native view remains under exact same root")
      try refuses { try f.bindings.registerModule(oldModule, context: oldContext, registeredModule: oldModule, moduleID: oldID) }
      let fresh = try f.capture(expected: publicEpoch)
      try check(fresh.moduleID == f.moduleID && f.gate.currentEpoch == publicEpoch, "epoch rotation does not restore obsolete native Module identity")
    }
    test("previously admitted old Module view cannot capture a fresh public epoch after native successor") {
      let f = try Fixture(); _ = try f.start(); _ = try f.capture()
      let oldOwner = f.owner!, oldContext = f.context!, oldModule = f.module!, oldID = f.moduleID
      f.rotateActualNativeEpoch(); f.freshOwnerAndModule(); f.context = NativeObject()
      _ = try f.capture(); f.rotateActualNativeEpoch(); let publicEpoch = f.gate.currentEpoch
      try refuses {
        _ = try f.bindings.capture(owner: oldOwner, viewContext: oldContext, module: oldModule,
          moduleContext: oldContext, moduleID: oldID, expected: publicEpoch)
      }
      let fresh = try f.capture(expected: publicEpoch)
      try check(fresh.moduleID == f.moduleID && f.gate.currentEpoch == publicEpoch, "old current-context registry membership alone cannot reclaim a retired identity")
    }
    test("same Module obsolete view cannot displace fresh attached native owner after another epoch rotation") {
      let f = try Fixture(); _ = try f.start(); _ = try f.capture(); let oldOwner = f.owner!
      f.rotateActualNativeEpoch(); f.owner = NativeObject(); f.descendants.insert(ObjectIdentifier(f.owner!))
      let freshOwner = f.owner!; _ = try f.capture(); f.rotateActualNativeEpoch(); let publicEpoch = f.gate.currentEpoch
      try refuses {
        _ = try f.bindings.capture(owner: oldOwner, viewContext: f.context!, module: f.module!,
          moduleContext: f.context!, moduleID: f.moduleID, expected: publicEpoch)
      }
      let fresh = try f.capture(expected: publicEpoch)
      try check(fresh.owner === freshOwner && f.gate.currentEpoch == publicEpoch, "auth epoch freshness is separate from native view lifetime")
    }
    test("actual native lifecycle adapter serializes disposal after registration action commit") {
      let f = try Fixture(); _ = try f.start(); let lifecycle = MeshMessengerRootModuleLifecycle()
      let enter = DispatchSemaphore(value: 0), attempted = DispatchSemaphore(value: 0), finished = DispatchGroup()
      let disposedBeforeCommit = ValueBox(false); finished.enter()
      DispatchQueue.global().async {
        _ = enter.wait(timeout: .now() + 2); attempted.signal(); lifecycle.dispose(); finished.leave()
      }
      try lifecycle.register {
        enter.signal(); try check(attempted.wait(timeout: .now() + 2) == .success, "real worker attempted native disposal")
        disposedBeforeCommit.set(finished.wait(timeout: .now() + 0.1) == .success)
        try f.admitModule()
      }
      try check(finished.wait(timeout: .now() + 2) == .success, "worker disposal completes after registration releases its native lock")
      try refuses { try lifecycle.withRegistered { throw CheckFailure.assertion("disposed native adapter admitted action") } }
      f.bindings.retireModule(f.moduleID)
      try check(!disposedBeforeCommit.get(), "dispose cannot linearize between native eligibility and core registration/registered flag")
    }
    test("off-main native registration refuses without changing gate state") {
      let f = try Fixture(), bindings = f.bindings, root = f.root!, epoch = f.gate.currentEpoch
      let done = DispatchSemaphore(value: 0), refusal = ValueBox(false)
      DispatchQueue.global().async {
        do { _ = try bindings.registerRoot(root) } catch { refusal.set(true) }; done.signal()
      }
      try check(done.wait(timeout: .now() + 2) == .success && refusal.get() && f.gate.currentEpoch == epoch, "off-main admission is side-effect-free refusal")
    }
    test("same native host with replacement presenter refuses the old mount observation") {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture(), sameHost = f.host
      f.presenter = NativeObject()
      try check(f.host === sameHost, "host reuse is not presenter freshness")
      try refuses { _ = try f.bindings.validate(lease) }
    }
    test("canonical native registry replacement refuses another view with the same lookup tag") {
      let f = try Fixture(); _ = try f.start(); let epoch = f.gate.currentEpoch
      f.registryReplacements[ObjectIdentifier(f.owner!)] = NativeObject()
      try refuses { _ = try f.capture() }
      try check(f.gate.currentEpoch == epoch, "unmounted first owner refusal must not mutate native gate")
    }
    test("current presenter root tag resolving another native surface refuses admission") {
      let f = try Fixture(); _ = try f.start(); let epoch = f.gate.currentEpoch
      f.rootTagMatchesSurface = false
      try refuses { _ = try f.capture() }
      try check(f.gate.currentEpoch == epoch, "surface mismatch is a pre-admission refusal")
    }
    test("never admitted delayed old Module absent from canonical mount cannot displace current owner") {
      let f = try Fixture(); _ = try f.start()
      let oldOwner = f.owner!, oldModule = f.module!, oldContext = f.context!, oldID = f.moduleID
      f.freshOwnerAndModule(); f.context = NativeObject(); _ = try f.capture()
      f.rotateActualNativeEpoch(); let epoch = f.gate.currentEpoch
      f.absentOwners.insert(ObjectIdentifier(oldOwner))
      try f.bindings.registerModule(oldModule, context: oldContext, registeredModule: oldModule, moduleID: oldID)
      try refuses {
        _ = try f.bindings.capture(owner: oldOwner, viewContext: oldContext, module: oldModule,
          moduleContext: oldContext, moduleID: oldID, expected: epoch)
      }
      let fresh = try f.capture(expected: epoch)
      try check(fresh.moduleID == f.moduleID && f.gate.currentEpoch == epoch, "unmounted old first callback never retires actual current Module")
    }
    test("mount replacement between capture preparation and completion refuses the captured owner") {
      let f = try Fixture(); _ = try f.start(); try f.admitModule()
      let capture = try f.bindings.prepareCapture(owner: f.owner!, viewContext: f.context!, module: f.module!,
        moduleContext: f.context!, moduleID: f.moduleID, expected: f.gate.currentEpoch)
      let lease = try f.bindings.commitCapture(capture)
      f.presenter = NativeObject()
      try refuses { _ = try f.bindings.validate(lease) }
    }
    print("RESULT \(23 - failures)/23 root-binding groups passed")
    if failures != 0 { exit(1) }
  }
  static func runStartup() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("native protection installs before RN even when actual provider construction fails") {
      let f = try StartupFixture()
      f.startup.install(construct: { throw CheckFailure.injected }, protect: { f.protect() })
      try check(f.protectionCount == 1 && f.startup.protectionInstalled, "construction failure cannot skip process observation and native cover installation")
      try refuses { try f.worker { try f.gate.bootstrap() } }
      try check(f.gate.state()["phase"] as? String == "error", "missing mandatory services never report boot ready")
      try refuses { try f.gate.activate(f.gate.currentEpoch, ownerSceneID: "owned-scene") }
    }
    test("real policy staging cleanup and notice drain complete under installed native protection") {
      let f = try StartupFixture(); try f.seedEnabledPolicy()
      f.startup.install(construct: { try f.services() }, protect: { f.protect() })
      try check(f.protectionCount == 1, "native observation installed before bootstrap dispatch")
      try f.worker { try f.gate.bootstrap() }
      try check(f.storagePrepared && !FileManager.default.fileExists(atPath: f.orphan.path), "actual backup exclusion and owned orphan cleanup executed")
      try check(f.noticePort.pendingIDs.isEmpty && f.noticePort.deliveredIDs.isEmpty, "real notice draining path withdrew the native-port legacy set")
      try check(try Data(contentsOf: f.original) == Data("preserve-original".utf8), "native staging cleanup preserved original account data")
      try check(f.gate.state()["phase"] as? String == "locked" && f.platform.presentations == 0, "durable enabled policy remains locked; bootstrap is not OS authentication")
    }
    test("notification ownership loss fails startup closed and later restoration cannot revive it") {
      let f = try StartupFixture(); try f.seedEnabledPolicy()
      f.startup.install(construct: { try f.services() }, protect: { f.protect() })
      f.noticePort.ownsDelegate = false
      try refuses { try f.worker { try f.gate.bootstrap() } }
      try check(f.protectionCount == 1 && f.startup.protectionInstalled && f.gate.state()["phase"] as? String == "error", "environment failure keeps installed protection and error state")
      f.noticePort.ownsDelegate = true
      try refuses { try f.gate.requireEpoch(f.gate.currentEpoch) }
      try check(FileManager.default.fileExists(atPath: f.orphan.path), "untrusted startup did not proceed into protected staging IO")
    }
    print("RESULT \(3 - failures)/3 native-startup groups passed")
    if failures != 0 { exit(1) }
  }

  static func runOwnerScope() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    func scope(_ f: Fixture, _ lease: MeshMessengerRootBindings.Lease) -> MeshMessengerNativeOwnerScope {
      MeshMessengerNativeOwnerScope(gate: f.gate, lease: lease, validate: { try f.bindings.validateIdentity($0) })
    }
    test("owner-bound private data refuses a newer public epoch rather than refreshing its lease") {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture(), port = scope(f, lease)
      let original = try port.privateData(lease.epoch) { Data("original-owner-result".utf8) }
      try check(original == Data("original-owner-result".utf8), "exact disabled owner private path")
      f.rotateActualNativeEpoch(); let newer = f.gate.currentEpoch
      try refuses { _ = try port.privateData(newer) { throw CheckFailure.assertion("old port reached a newer action body") } }
      try refuses { try port.check(lease.epoch) }
    }
    test("canonical native mount replacement refuses a still-current epoch before private entry") {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture(), port = scope(f, lease)
      let expected = f.gate.currentEpoch; f.presenter = NativeObject()
      try check(expected == f.gate.currentEpoch, "replacement precedes delayed lifecycle observation")
      try refuses { _ = try port.privateData(expected) { throw CheckFailure.assertion("obsolete presenter reached private body") } }
    }
    test("native owner loss during actual private body suppresses the completed data") {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture(), port = scope(f, lease)
      try refuses { _ = try port.privateData(lease.epoch) { f.registryReplacements[ObjectIdentifier(f.owner!)] = NativeObject(); return Data("must-not-publish".utf8) } }
    }
    test("auth metadata identity survives its own epoch rotation but cannot survive a native successor or release") {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture(), port = scope(f, lease)
      try check(try port.authorization(lease.epoch) == "owned-scene", "native auth scene captured without private grant")
      f.rotateActualNativeEpoch()
      try check(try port.authorizationCompletion() == "owned-scene", "auth may return public metadata after its own epoch rotation")
      try refuses { try port.check(lease.epoch) }
      f.owner = NativeObject(); f.descendants.insert(ObjectIdentifier(f.owner!)); let fresh = try f.capture(), next = scope(f, fresh)
      try refuses { _ = try port.authorizationCompletion() }
      try next.check(fresh.epoch); port.close(); try next.check(fresh.epoch)
      next.close(); try refuses { _ = try next.authorizationCompletion() }
    }
    print("RESULT \(4 - failures)/4 native-owner-scope groups passed")
    if failures != 0 { exit(1) }
  }

  static func runPublication() {
    do {
      let f = try Fixture(); _ = try f.start(); let lease = try f.capture()
      let scope = MeshMessengerNativeOwnerScope(gate: f.gate, lease: lease, validate: { try f.bindings.validateIdentity($0) })
      let port = NativeSubmissionPort(), broker = MeshMessengerLockedNotifications(gate: f.gate, port: port, deadlineSeconds: 1)
      let expected = f.gate.currentEpoch, outcome = ValueBox<Result<Void, Error>?>(nil)
      // Exact ordering: Module admission has passed; native replacement occurs
      // during broker registration, before the actual external port submission.
      port.beforeOwnershipRead = { f.presenter = NativeObject() }
      let frame = "{\"version\":1,\"id\":\"private-event\",\"title\":\"private title\",\"body\":\"private body\",\"scope\":\"chat/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"mention\":false}"
      scope.publishNotice(frame, notices: broker, expected: expected) { outcome.set($0) }
      try check(port.adds == 0, "a replaced native mount must refuse BEFORE an actual private notice is submitted")
      guard case .failure? = outcome.get() else { throw CheckFailure.assertion("pending publication completes refusal") }
      try check(f.gate.currentEpoch == expected, "the delayed lifecycle callback has not rotated the public epoch")
      print("PASS native mount replacement during broker registration refuses before external publication")
      print("RESULT 1/1 pending-publication groups passed")
    } catch { print("FAIL native mount replacement during broker registration: \(error)"); print("RESULT 0/1 pending-publication groups passed"); exit(1) }
  }

  static func runHeadlessAdmission() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("actual native registry membership survives a refused competing UI owner registration for disabled headless data") {
      let f = try Fixture(); _ = try f.start(); let ui = try f.capture(), expected = f.gate.currentEpoch
      let headless = NativeObject(), context = NativeObject(), lifecycle = MeshMessengerRootModuleLifecycle(), id = UUID()
      try lifecycle.observeRegistryMembership(headless, registeredModule: headless)
      try refuses { try lifecycle.register {
        try f.bindings.registerModule(headless, context: context, registeredModule: headless, moduleID: id)
      } }
      try check(try f.bindings.validate(ui) == "owned-scene", "the genuine UI owner remains unchanged")
      try lifecycle.requireAlive()
      let call = try MeshMessengerNativeCall(disabled: expected, gate: f.gate) { try lifecycle.requireAlive() }
      let result = try call.data {
        try check(try f.gate.capturedCallEpoch() == expected, "actual native call carries its original epoch into the core boundary")
        return Data("fresh-disabled-native-result".utf8)
      }
      try check(result == Data("fresh-disabled-native-result".utf8) && f.platform.presentations == 0, "a real disabled gate admits data without granting another UI owner or OS authentication")
      f.gate.accountChanging()
      try refuses { _ = try call.requireExpected(f.gate.currentEpoch) }
      try refuses { _ = try call.data { throw CheckFailure.assertion("old headless call reached a new account epoch") } }
    }
    test("foreign or absent native registry snapshots cannot establish an alive Module") {
      let module = NativeObject(), lifecycle = MeshMessengerRootModuleLifecycle()
      try refuses { try lifecycle.observeRegistryMembership(module, registeredModule: nil) }
      try refuses { try lifecycle.observeRegistryMembership(module, registeredModule: NativeObject()) }
      try refuses { try lifecycle.requireAlive() }
    }
    test("native disposal prevents a delayed old registry callback from reviving private entry") {
      let f = try Fixture(); _ = try f.start(); let lifecycle = MeshMessengerRootModuleLifecycle(), module = f.module!
      try lifecycle.observeRegistryMembership(module, registeredModule: module)
      try lifecycle.register { try f.admitModule() }; try lifecycle.requireAlive()
      lifecycle.dispose()
      try refuses { try lifecycle.requireAlive() }
      try refuses { try lifecycle.observeRegistryMembership(module, registeredModule: module) }
    }
    print("RESULT \(3 - failures)/3 native-headless-admission groups passed")
    if failures != 0 { exit(1) }
  }

  static func runOwnerConstruction() {
    do {
      let f = try Fixture(); _ = try f.start(); _ = try f.capture(); f.gate.lock()
      let lease = try f.capture(), expected = f.gate.currentEpoch
      let scope = MeshMessengerNativeOwnerScope(gate: f.gate, lease: lease, validate: { try f.bindings.validateIdentity($0) })
      let call = try MeshMessengerNativeCall(scope: scope, expected: expected)
      try check(try call.scope?.authorization(expected) == "owned-scene", "locked UI must retain its native auth/metadata port")
      try refuses { _ = try call.data { throw CheckFailure.assertion("locked owner constructor granted private data") } }
      try check(f.gate.currentEpoch == expected && f.platform.presentations == 0, "constructing the owner port cannot authenticate or rotate native state")
      print("PASS locked native owner port construction keeps auth metadata without granting private data")
      print("RESULT 1/1 native-owner-construction groups passed")
    } catch { print("FAIL locked native owner port construction: \(error)"); print("RESULT 0/1 native-owner-construction groups passed"); exit(1) }
  }

  static func runAccountTransitions() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    // Foundation native admission/core boundary only. These tests do not
    // simulate a Mesh account transaction, SDK Module, or OS authority.
    test("each actual account-changing export revokes old data and blocks fresh readers until the native transaction returns") {
      for symbol in ["mesh_messenger_create_account", "mesh_messenger_complete_device_link", "mesh_messenger_account_delete", "mesh_messenger_account_discard"] {
        let f = try Fixture(), transitions = MeshMessengerNativeAccountTransitions(gate: f.gate), coreLock = NSRecursiveLock()
        let expected = f.gate.currentEpoch, pending = ValueBox<String?>(nil), callbackOutsideCore = ValueBox(true)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let account = directory.appendingPathComponent("owned-account"); try Data("old".utf8).write(to: account)
        let stop = f.gate.observe { _ in
          let done = DispatchSemaphore(value: 0)
          DispatchQueue.global().async {
            let acquired = coreLock.try(); if acquired { coreLock.unlock() }
            if !acquired { callbackOutsideCore.set(false) }; done.signal()
          }
          if done.wait(timeout: .now() + 2) != .success { callbackOutsideCore.set(false) }
        }; defer { stop() }
        let call = try MeshMessengerNativeCall(disabled: expected, gate: f.gate) { try transitions.requireIdle() }
        try refuses {
          _ = try call.data {
            try transitions.perform(symbol, expected: try f.gate.capturedCallEpoch()) { ticket in
              try check(f.gate.currentEpoch != expected, "old native epoch revoked before account IO")
              pending.set(f.gate.currentEpoch)
              try refuses {
                let fresh = try MeshMessengerNativeCall(disabled: f.gate.currentEpoch, gate: f.gate) { try transitions.requireIdle() }
                _ = try fresh.data { throw CheckFailure.assertion("fresh reader reached uncommitted account IO") }
              }
              guard let ticket else { throw CheckFailure.assertion("account IO requires its native transaction ticket") }
              coreLock.lock(); defer { coreLock.unlock() }; try ticket.consume(symbol)
              try Data("committed".utf8).write(to: account); return Data("old-scope-result".utf8)
            }
          }
        }
        try transitions.requireIdle()
        try check(try Data(contentsOf: account) == Data("committed".utf8), "already-admitted native transaction committed while old response was suppressed")
        try check(pending.get() != nil && f.gate.currentEpoch != pending.get(), "post-transaction epoch retries the current owner against committed state")
        try check(callbackOutsideCore.get(), "native revoke observers never run while the core mutex is held")
      }
    }
    test("an actual account body error survives native finalization and releases the private-read barrier") {
      final class BodyError: Error {}
      let f = try Fixture(), transitions = MeshMessengerNativeAccountTransitions(gate: f.gate), marker = BodyError()
      let original = f.gate.currentEpoch; var pending: String?
      do {
        _ = try transitions.perform("mesh_messenger_account_delete", expected: original) { ticket in
          pending = f.gate.currentEpoch
          guard let ticket else { throw CheckFailure.assertion("missing account ticket") }
          try ticket.consume("mesh_messenger_account_delete"); throw marker
        }
        throw CheckFailure.assertion("body failure was hidden")
      } catch { try check(error as AnyObject === marker, "exact native body error preserved") }
      try transitions.requireIdle()
      try check(original != pending && pending != f.gate.currentEpoch, "failed mutation also revokes both pending and original epochs")
    }
    test("native account tickets are exact once-only and competing mutation cannot enter its body") {
      let f = try Fixture(), transitions = MeshMessengerNativeAccountTransitions(gate: f.gate)
      _ = try transitions.perform("mesh_messenger_account_discard", expected: f.gate.currentEpoch) { ticket in
        guard let ticket else { throw CheckFailure.assertion("missing account ticket") }
        try refuses { try ticket.consume("mesh_messenger_create_account") }
        try ticket.consume("mesh_messenger_account_discard")
        try refuses { try ticket.consume("mesh_messenger_account_discard") }
        try refuses {
          _ = try transitions.perform("mesh_messenger_create_account", expected: f.gate.currentEpoch) { _ in
            throw CheckFailure.assertion("competing mutation reached its native account body")
          }
        }
        return Data()
      }
      try transitions.requireIdle()
    }
    test("ordinary native data exports preserve their epoch and exact response without an account ticket") {
      let f = try Fixture(), transitions = MeshMessengerNativeAccountTransitions(gate: f.gate), expected = f.gate.currentEpoch
      let value = try transitions.perform("mesh_messenger_load_profile", expected: expected) { ticket in
        try check(ticket == nil, "ordinary data has no account authority"); return Data("profile".utf8)
      }
      try check(value == Data("profile".utf8) && f.gate.currentEpoch == expected, "ordinary response and account generation are unchanged")
      try transitions.requireIdle()
    }
    print("RESULT \(4 - failures)/4 native-account-transition groups passed")
    if failures != 0 { exit(1) }
  }

  static func runHeadlessLifetime() {
    do {
      let f = try Fixture(), expected = f.gate.currentEpoch
      let call = try MeshMessengerNativeCall(disabled: expected, gate: f.gate) {}
      try refuses { _ = try call.data { call.close(); return Data("late task result".utf8) } }
      call.close()
      try refuses { _ = try call.data { throw CheckFailure.assertion("released task reached private native work") } }
      try refuses { try call.publication { throw CheckFailure.assertion("released task reached native publication") } }
      let next = try MeshMessengerNativeCall(disabled: expected, gate: f.gate) {}
      try check(try next.data { Data("next task".utf8) } == Data("next task".utf8), "releasing one task does not retire another current native Module scope")
      print("PASS released headless native port suppresses pending data and refuses later private effects without retiring a fresh task")
      print("RESULT 1/1 native-headless-lifetime groups passed")
    } catch { print("FAIL native headless lifetime: \(error)"); print("RESULT 0/1 native-headless-lifetime groups passed"); exit(1) }
  }

}
