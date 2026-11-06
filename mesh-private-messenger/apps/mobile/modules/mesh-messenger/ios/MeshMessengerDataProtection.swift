import Foundation

protocol MeshMessengerNativeMountObservation: AnyObject {
  func isCurrent() -> Bool
}

// Native-only provenance. Object/lifecycle ports are not grants; UIKit supplies
// the actual root/view/context/window/scene, and the unchanged gate owns auth.
final class MeshMessengerRootBindings {
  enum Failure: Error { case unavailable, stale, ambiguous }
  struct Surface {
    let window: AnyObject, scene: AnyObject
    let sceneID: String
    let active: Bool
    let mount: MeshMessengerNativeMountObservation?
  }
  final class Lease {
    let id = UUID(), rootID: UUID, moduleID: UUID
    let epoch: String, account: UInt64, sceneID: String
    let mount: MeshMessengerNativeMountObservation
    weak var root: AnyObject?, owner: AnyObject?, context: AnyObject?, module: AnyObject?
    weak var window: AnyObject?, scene: AnyObject?
    init(rootID: UUID, moduleID: UUID, epoch: String, account: UInt64, sceneID: String,
         root: AnyObject, owner: AnyObject, context: AnyObject, module: AnyObject,
         window: AnyObject, scene: AnyObject, mount: MeshMessengerNativeMountObservation) {
      self.rootID = rootID; self.moduleID = moduleID; self.epoch = epoch; self.account = account; self.sceneID = sceneID
      self.root = root; self.owner = owner; self.context = context; self.module = module
      self.window = window; self.scene = scene; self.mount = mount
    }
  }
  private let gate: MeshMessengerAppLock
  private let surface: (AnyObject, AnyObject) -> Surface?
  init(gate: MeshMessengerAppLock, surface: @escaping (AnyObject, AnyObject) -> Surface?) {
    self.gate = gate; self.surface = surface
  }
  private final class Root {
    let id = UUID()
    weak var object: AnyObject?, window: AnyObject?, scene: AnyObject?
    var attached = false
    init(_ object: AnyObject) { self.object = object }
  }
  private final class RegisteredModule {
    weak var object: AnyObject?, context: AnyObject?
    var retired = false
    init(_ object: AnyObject, _ context: AnyObject) { self.object = object; self.context = context }
  }
  private final class RetiredOwner {
    weak var object: AnyObject?
    init(_ object: AnyObject) { self.object = object }
  }
  private var root: Root?
  private var modules: [UUID: RegisteredModule] = [:]
  private var retiredOwners: [ObjectIdentifier: RetiredOwner] = [:]
  // Last native admission is identity provenance, not an authorized action
  // lease. It survives authentication epochs and holds native objects weakly.
  private var admittedIdentity: Lease?
  private var current: Lease?

  // Main serializes only native provenance. The unchanged gate owns its own
  // mutex/auth lifecycle; no scope or plaintext permission is created here.
  private func requireMain() throws { guard Thread.isMainThread else { throw Failure.unavailable } }
  private func currentEpoch(_ lease: Lease) -> Bool {
    lease.epoch == gate.currentEpoch && lease.account == gate.accountGeneration
  }
  private func liveCurrent(_ lease: Lease) -> Bool {
    root?.id == lease.rootID && currentEpoch(lease) && lease.root != nil && lease.owner != nil &&
      lease.context != nil && lease.module != nil && lease.window != nil && lease.scene != nil
  }
  func registerModule(_ module: AnyObject, context: AnyObject, registeredModule: AnyObject?, moduleID: UUID) throws {
    try requireMain()
    // The UIKit caller obtains this identity from the exact public AppContext
    // registry. Missing/foreign create callbacks must not change ANY state.
    guard registeredModule === module else { throw Failure.unavailable }
    if let owned = current, liveCurrent(owned), owned.moduleID != moduleID { throw Failure.ambiguous }
    if let existing = modules[moduleID] {
      guard !existing.retired, existing.object === module, existing.context === context else { throw Failure.stale }
      return
    }
    // Weak tombstones remain while the actual destroyed Module is still alive,
    // so its delayed didCreate can never resurrect it. Dead native objects do
    // not accumulate in the registry or supply a fallback root/context.
    modules = modules.filter { $0.value.object != nil && $0.value.context != nil }
    modules[moduleID] = RegisteredModule(module, context)
  }
  func registerRoot(_ object: AnyObject) throws -> UUID {
    try requireMain()
    if let root, root.object === object { return root.id }
    let replacing = root != nil, value = Root(object)
    root = value; current = nil
    if replacing { gate.lock() }
    return value.id
  }
  func rootWindowDidChange(_ rootID: UUID) {
    guard Thread.isMainThread, let root, root.id == rootID else { return }
    guard let object = root.object, let value = surface(object, object) else {
      if root.attached {
        root.attached = false; root.window = nil; root.scene = nil
        current = nil; gate.lock()
      }
      return
    }
    if root.attached && (root.window !== value.window || root.scene !== value.scene) {
      current = nil; gate.lock()
    }
    root.attached = true; root.window = value.window; root.scene = value.scene
    // Inactivity (including owned LA prompt transitions) is handled by the
    // native gate. An attached window becoming inactive is not root loss.
  }
  func detachRoot(_ rootID: UUID) {
    guard Thread.isMainThread, root?.id == rootID else { return }
    root = nil; current = nil; gate.lock()
  }
  // Native-only synchronous snapshot. No JS root/context/window/scene value
  // can construct it; production obtains all objects through actual UIKit.
  final class Capture {
    let rootID: UUID, moduleID: UUID, expected: String, account: UInt64
    let root: AnyObject, owner: AnyObject, context: AnyObject, module: AnyObject
    let surface: Surface
    fileprivate init(rootID: UUID, moduleID: UUID, expected: String, account: UInt64,
                     root: AnyObject, owner: AnyObject, context: AnyObject, module: AnyObject, surface: Surface) {
      self.rootID = rootID; self.moduleID = moduleID; self.expected = expected; self.account = account
      self.root = root; self.owner = owner; self.context = context; self.module = module; self.surface = surface
    }
  }
  func prepareCapture(owner: AnyObject, viewContext: AnyObject, module: AnyObject,
                      moduleContext: AnyObject, moduleID: UUID, expected: String) throws -> Capture {
    try requireMain()
    guard expected == gate.currentEpoch else { throw Failure.stale }
    let account = gate.accountGeneration
    guard viewContext === moduleContext, let registered = modules[moduleID], !registered.retired,
          registered.object === module, registered.context === moduleContext,
          let root, let actualRoot = root.object,
          let value = surface(actualRoot, owner), value.active, !value.sceneID.isEmpty, value.mount?.isCurrent() == true else { throw Failure.unavailable }
    guard expected == gate.currentEpoch, account == gate.accountGeneration else { throw Failure.stale }
    return Capture(rootID: root.id, moduleID: moduleID, expected: expected, account: account,
      root: actualRoot, owner: owner, context: viewContext, module: module, surface: value)
  }
  func commitCapture(_ captured: Capture) throws -> Lease {
    try requireMain()
    let owner = captured.owner, moduleID = captured.moduleID, value = captured.surface
    guard let mount = value.mount else { throw Failure.unavailable }
    guard captured.expected == gate.currentEpoch, captured.account == gate.accountGeneration,
          let root, root.id == captured.rootID, root.object === captured.root,
          let registered = modules[moduleID], !registered.retired,
          registered.object === captured.module, registered.context === captured.context else { throw Failure.stale }
    if retiredOwners[ObjectIdentifier(owner)]?.object === owner { throw Failure.stale }
    if let owned = current, liveCurrent(owned) {
      guard owned.rootID == root.id, owned.owner === owner, owned.context === captured.context,
            owned.module === captured.module, owned.moduleID == moduleID,
            owned.window === value.window, owned.scene === value.scene, owned.sceneID == value.sceneID else { throw Failure.ambiguous }
      return owned
    }
    let lease = Lease(rootID: root.id, moduleID: moduleID, epoch: captured.expected, account: captured.account,
      sceneID: value.sceneID, root: captured.root, owner: owner, context: captured.context,
      module: captured.module, window: value.window, scene: value.scene, mount: mount)
    guard currentEpoch(lease) else { throw Failure.stale }
    // Only this successfully admitted actual native successor retires prior
    // native identities; public auth epochs never clear that retirement.
    retiredOwners = retiredOwners.filter { $0.value.object != nil }
    if let prior = admittedIdentity {
      if prior.moduleID != moduleID { modules[prior.moduleID]?.retired = true }
      if let previousOwner = prior.owner, previousOwner !== owner {
        retiredOwners[ObjectIdentifier(previousOwner)] = RetiredOwner(previousOwner)
      }
    }
    root.attached = true; root.window = value.window; root.scene = value.scene
    admittedIdentity = lease; current = lease; return lease
  }
  // Portable callers exercise the same prepare/commit implementation. The
  // production Module places only commitCapture inside its lifecycle lock.
  func capture(owner: AnyObject, viewContext: AnyObject, module: AnyObject,
               moduleContext: AnyObject, moduleID: UUID, expected: String) throws -> Lease {
    let lease = try commitCapture(prepareCapture(owner: owner, viewContext: viewContext, module: module,
      moduleContext: moduleContext, moduleID: moduleID, expected: expected))
    _ = try validate(lease)
    return lease
  }
  func validate(_ lease: Lease) throws -> String {
    try requireMain()
    guard current?.id == lease.id, let root, root.id == lease.rootID,
          let registered = modules[lease.moduleID], !registered.retired else { throw Failure.stale }
    guard currentEpoch(lease) else { throw Failure.stale }
    guard let actualRoot = root.object, lease.root === actualRoot, let owner = lease.owner,
          let context = lease.context, registered.context === context,
          let module = lease.module, registered.object === module,
          let value = surface(actualRoot, owner), lease.mount.isCurrent(), value.mount?.isCurrent() == true, lease.window === value.window,
          lease.scene === value.scene, lease.sceneID == value.sceneID else {
      // A current real object's loss restricts only its own still-current epoch.
      // A delayed old lease never reaches this branch for a newer registration.
      rootWindowDidChange(lease.rootID)
      retireOwner(lease); throw Failure.unavailable
    }
    guard value.active, currentEpoch(lease) else { throw Failure.stale }
    return lease.sceneID
  }
  func currentOwner(expected: String) throws -> Lease {
    try requireMain()
    guard let owned = current, owned.epoch == expected else { throw Failure.stale }
    _ = try validate(owned)
    return owned
  }
  // Public auth metadata can finish after its own epoch rotation. This checks
  // only exact native identity/account; it never supplies private authority.
  func validateIdentity(_ lease: Lease) throws -> String {
    try requireMain()
    guard let admitted = admittedIdentity, admitted.rootID == lease.rootID,
          admitted.moduleID == lease.moduleID, admitted.owner === lease.owner,
          admitted.context === lease.context, admitted.module === lease.module,
          lease.account == gate.accountGeneration,
          let root, root.id == lease.rootID, let actualRoot = root.object,
          lease.root === actualRoot, let owner = lease.owner,
          let registered = modules[lease.moduleID], !registered.retired,
          let context = lease.context, registered.context === context,
          let module = lease.module, registered.object === module,
          let value = surface(actualRoot, owner), value.active,
          lease.mount.isCurrent(), value.mount?.isCurrent() == true,
          lease.window === value.window, lease.scene === value.scene,
          lease.sceneID == value.sceneID else { throw Failure.stale }
    return lease.sceneID
  }
  func retireOwner(_ lease: Lease) {
    guard Thread.isMainThread, current?.id == lease.id, root?.id == lease.rootID else { return }
    current = nil
    if currentEpoch(lease) { gate.lock() }
  }
  func retireModule(_ moduleID: UUID) {
    guard Thread.isMainThread else { return }
    modules[moduleID]?.retired = true
    if let owned = current, owned.moduleID == moduleID { retireOwner(owned) }
  }
}

// The native owner constructs this once. Public epochs can narrow this scope,
// but cannot retarget it to another UIView, Module or later auth action.
final class MeshMessengerNativeOwnerScope {
  let expected: String
  private let gate: MeshMessengerAppLock, lease: MeshMessengerRootBindings.Lease
  private let validate: (MeshMessengerRootBindings.Lease) throws -> String
  private let mutex = NSLock()
  private var closed = false
  init(gate: MeshMessengerAppLock, lease: MeshMessengerRootBindings.Lease,
       validate: @escaping (MeshMessengerRootBindings.Lease) throws -> String) {
    self.gate = gate; self.lease = lease; expected = lease.epoch; self.validate = validate
  }
  func close() { mutex.lock(); closed = true; mutex.unlock() }
  func authorizationCompletion() throws -> String {
    mutex.lock(); let unavailable = closed; mutex.unlock()
    guard !unavailable else { throw MeshMessengerRootBindings.Failure.stale }
    // No native/registry/Main call runs under this object's lifecycle mutex.
    return try validate(lease)
  }
  func authorization(_ supplied: String) throws -> String {
    guard supplied == expected, supplied == gate.currentEpoch else { throw MeshMessengerRootBindings.Failure.stale }
    return try authorizationCompletion()
  }
  func check(_ supplied: String) throws {
    _ = try authorization(supplied)
    try gate.requireEpoch(expected)
  }
  func privateData(_ supplied: String, body: () throws -> Data) throws -> Data {
    try check(supplied)
    var result = try gate.scopedData(expected, body: body)
    do { try check(supplied); return result }
    catch { result.resetBytes(in: result.startIndex..<result.endIndex); throw error }
  }
  func privateValue<T>(_ supplied: String, body: () throws -> T) throws -> T {
    try check(supplied)
    let result = try gate.scoped(expected, body: body)
    try check(supplied); return result
  }
  func publishNotice(_ frame: String, notices: MeshMessengerLockedNotifications, expected supplied: String,
                     completion: @escaping (Result<Void, Error>) -> Void) {
    do {
      try check(supplied)
      notices.publish(frame, expected: supplied, publication: { add in
        if Thread.isMainThread { try self.publication(supplied, body: add) }
        else { try DispatchQueue.main.sync { try self.publication(supplied, body: add) } }
      }) { result in
        do { try result.get(); try self.check(supplied); completion(.success(())) }
        catch { completion(.failure(error)) }
      }
    } catch { completion(.failure(error)) }
  }
  // Native mount/registry mutation is serialized on Main. Keep the exact
  // check and the bounded OS submission in one turn, outside all core locks.
  func publication(_ supplied: String, body: () throws -> Void) throws {
    guard Thread.isMainThread else { throw MeshMessengerRootBindings.Failure.unavailable }
    try check(supplied); try body()
  }
}


// A native owner call and a disabled data call have different provenance.
// No public boolean or caller-supplied scene selects between these cases.
final class MeshMessengerNativeCall {
  private enum Admission {
    case owner(MeshMessengerNativeOwnerScope)
    case disabled(MeshMessengerAppLock, validateModule: () throws -> Void)
  }
  let expected: String
  private let admission: Admission
  private let lifetime = NSLock()
  private var closed = false
  func close() {
    lifetime.lock(); let repeated = closed; closed = true; lifetime.unlock()
    if !repeated { scope?.close() }
  }
  func requireOpen() throws {
    lifetime.lock(); let unavailable = closed; lifetime.unlock()
    if unavailable { throw MeshMessengerRootBindings.Failure.stale }
  }
  var scope: MeshMessengerNativeOwnerScope? { if case .owner(let scope) = admission { return scope }; return nil }
  init(scope: MeshMessengerNativeOwnerScope, expected: String) throws {
    admission = .owner(scope); self.expected = expected
    // The locked owner needs auth/metadata methods. Data/publication entry
    // still calls check(), which requires the unchanged native gate grant.
    _ = try scope.authorization(expected)
  }
  init(disabled expected: String, gate: MeshMessengerAppLock, validateModule: @escaping () throws -> Void) throws {
    admission = .disabled(gate, validateModule: validateModule); self.expected = expected; try check()
  }
  func requireExpected(_ supplied: String) throws -> MeshMessengerNativeCall {
    guard supplied == expected else { throw MeshMessengerRootBindings.Failure.stale }; try check(); return self
  }
  func check() throws {
    try requireOpen()
    switch admission {
    case .owner(let scope): try scope.check(expected)
    case .disabled(let gate, let validateModule):
      try validateModule()
      guard !gate.restrictionActive else { throw MeshMessengerAppLock.Failure.locked }
      try gate.requireEpoch(expected)
    }
  }
  func data(_ body: () throws -> Data) throws -> Data {
    try requireOpen()
    switch admission {
    case .owner(let scope): return try scope.privateData(expected, body: body)
    case .disabled(let gate, _):
      try check(); var result = try gate.scopedData(expected, body: body)
      do { try check(); return result } catch { result.resetBytes(in: result.startIndex..<result.endIndex); throw error }
    }
  }
  func value<T>(_ body: () throws -> T) throws -> T {
    try requireOpen()
    switch admission {
    case .owner(let scope): return try scope.privateValue(expected, body: body)
    case .disabled(let gate, _):
      try check(); let result = try gate.scoped(expected, body: body); try check(); return result
    }
  }
  func publication(_ body: () throws -> Void) throws {
    guard Thread.isMainThread else { throw MeshMessengerRootBindings.Failure.unavailable }
    switch admission {
    case .owner(let scope): try scope.publication(expected, body: body)
    case .disabled: try check(); try body()
    }
  }
}

// Account admission is native-only. Revocation runs outside the core and
// lifecycle mutexes; a pending transaction prevents fresh-epoch account reads.
final class MeshMessengerNativeAccountTransitions {
  enum Failure: Error { case busy, spent, wrongOperation }
  final class Ticket {
    private let symbol: String
    private let mutex = NSLock()
    private var consumed = false
    fileprivate init(_ symbol: String) { self.symbol = symbol }
    func consume(_ operation: String) throws {
      mutex.lock(); defer { mutex.unlock() }
      guard operation == symbol else { throw Failure.wrongOperation }
      guard !consumed else { throw Failure.spent }; consumed = true
    }
    fileprivate func close() { mutex.lock(); consumed = true; mutex.unlock() }
  }
  private let gate: MeshMessengerAppLock
  private let mutex = NSLock()
  private var active: UUID?
  private var pending = false
  init(gate: MeshMessengerAppLock) { self.gate = gate }
  func requireIdle() throws {
    mutex.lock(); defer { mutex.unlock() }
    if pending { throw Failure.busy }
  }
  func perform(_ symbol: String, expected: String, body: (Ticket?) throws -> Data) throws -> Data {
    try requireIdle(); try gate.requireEpoch(expected)
    guard ["mesh_messenger_create_account", "mesh_messenger_complete_device_link",
      "mesh_messenger_account_delete", "mesh_messenger_account_discard"].contains(symbol) else { return try body(nil) }
    let id = UUID(), ticket = Ticket(symbol)
    mutex.lock()
    guard active == nil else { mutex.unlock(); throw Failure.busy }
    active = id; pending = true; mutex.unlock()
    do { try gate.requireEpoch(expected) }
    catch { clear(id); ticket.close(); throw error }
    gate.accountChanging()
    defer {
      ticket.close()
      // The core closure has returned and released its lock. Reads may now
      // see committed state; competing account mutations stay excluded until
      // the post-commit notification completes. Its observer can bind anew.
      mutex.lock(); if active == id { pending = false }; mutex.unlock()
      gate.accountChanging()
      clear(id)
    }
    return try body(ticket)
  }
  private func clear(_ id: UUID) {
    mutex.lock(); defer { mutex.unlock() }
    if active == id { active = nil; pending = false }
  }
}

// Shared native callback adapter. Only quick native provenance work belongs
// inside this lock: no registry lookup, gate callback, UI event or dispatch.
final class MeshMessengerRootModuleLifecycle {
  private let lock = NSLock()
  private var disposed = false, registered = false
  private weak var observedModule: AnyObject?
  func observeRegistryMembership(_ module: AnyObject, registeredModule: AnyObject?) throws {
    lock.lock(); defer { lock.unlock() }
    guard !disposed, registeredModule === module, observedModule == nil || observedModule === module else { throw MeshMessengerRootBindings.Failure.unavailable }
    observedModule = module
  }
  // Current registry membership admits the Module lifetime only. The separate
  // UI registered flag and native mount lease still gate every owner binding.
  func requireAlive() throws {
    lock.lock(); defer { lock.unlock() }
    guard !disposed, observedModule != nil else { throw MeshMessengerRootBindings.Failure.unavailable }
  }
  func register(_ action: () throws -> Void) throws {
    lock.lock(); defer { lock.unlock() }
    guard !disposed && !registered else { return }
    try action(); registered = true
  }
  func withRegistered<T>(_ action: () throws -> T) throws -> T {
    lock.lock(); defer { lock.unlock() }
    guard !disposed && registered else { throw MeshMessengerRootBindings.Failure.unavailable }
    return try action()
  }
  func dispose() { lock.lock(); disposed = true; lock.unlock() }
}

// Installs process protection once even when native service construction fails.
// Hook bodies always reach the actual provider/notice objects or throw the
// original construction failure; a missing service can never report ready.
final class MeshMessengerNativeStartup {
  struct Services {
    let files: MeshMessengerProtectedFiles, notices: MeshMessengerLockedNotifications
    let prepareStorage: () throws -> Void
  }
  enum Failure: Error { case unavailable }
  private let mutex = NSLock()
  private var started = false, protected = false
  private var services: Services?, retainedNotices: MeshMessengerLockedNotifications?
  private var failure: Error?
  var protectionInstalled: Bool { mutex.lock(); defer { mutex.unlock() }; return protected }
  var hasFailure: Bool { mutex.lock(); defer { mutex.unlock() }; return failure != nil }
  func retainNotices(_ notices: MeshMessengerLockedNotifications) { mutex.lock(); retainedNotices = notices; mutex.unlock() }
  private func recordFailure(_ error: Error) { mutex.lock(); if failure == nil { failure = error }; mutex.unlock() }
  func install(construct: () throws -> Services, protect: () throws -> Void) {
    mutex.lock(); guard !started else { mutex.unlock(); return }; started = true; mutex.unlock()
    do {
      let value = try construct()
      mutex.lock(); services = value; retainedNotices = value.notices; mutex.unlock()
    } catch { recordFailure(error) }
    // Required protection is installed on the failure path as well. Its real
    // hooks retain the construction error, so bootstrap cannot become ready.
    do {
      try protect()
      mutex.lock(); protected = true; mutex.unlock()
    } catch { recordFailure(error) }
  }
  private func required() throws -> Services {
    mutex.lock(); let value = services, error = failure; mutex.unlock()
    if let error { throw error }; guard let value else { throw Failure.unavailable }; return value
  }
  func protectedFiles() throws -> MeshMessengerProtectedFiles { try required().files }
  func lockedNotices() throws -> MeshMessengerLockedNotifications { try required().notices }
  func clean() throws { let value = try required(); try value.prepareStorage(); try value.files.cleanOrphans() }
  func drain() throws {
    mutex.lock(); let value = retainedNotices; mutex.unlock()
    guard let value else { throw Failure.unavailable }; try value.drainLegacy()
  }
  func validate() throws { let value = try required(); try value.notices.checkOwnership() }
  func revoke() { mutex.lock(); let value = services?.files; mutex.unlock(); value?.revoke() }
}

#if canImport(UIKit)
import UIKit
import ExpoModulesCore
import ExpoNotifications
import UserNotifications

private final class MeshMessengerAppCurrentMount: MeshMessengerNativeMountObservation {
  private let snapshot: MeshMessengerCurrentMountSnapshot
  private weak var factory: NSObject?
  private let currentFactory: () -> NSObject?
  init(snapshot: MeshMessengerCurrentMountSnapshot, factory: NSObject, currentFactory: @escaping () -> NSObject?) {
    self.snapshot = snapshot; self.factory = factory; self.currentFactory = currentFactory
  }
  func isCurrent() -> Bool {
    guard Thread.isMainThread, let factory, currentFactory() === factory else { return false }
    return snapshot.isCurrent()
  }
}

@MainActor private final class MeshMessengerSelectionOwnerContext: MeshMessengerProtectedSelectionContext {
  private weak var root: AnyObject?, owner: AnyObject?, context: AnyObject?, module: AnyObject?
  private weak var window: AnyObject?, scene: AnyObject?
  private let account: UInt64
  init(_ lease: MeshMessengerRootBindings.Lease) {
    root = lease.root; owner = lease.owner; context = lease.context; module = lease.module
    window = lease.window; scene = lease.scene; account = lease.account
  }
  nonisolated func validate(expected: String) throws {
    if Thread.isMainThread { try MainActor.assumeIsolated { try validateOnMain(expected) } }
    else { try DispatchQueue.main.sync { try MainActor.assumeIsolated { try validateOnMain(expected) } } }
  }
  private func validateOnMain(_ expected: String) throws {
    let current = try MeshMessengerDataProtection.currentNativeOwner(expected: expected)
    guard let root, let owner, let context, let module, let window, let scene,
          current.root === root, current.owner === owner, current.context === context,
          current.module === module, current.window === window, current.scene === scene,
          current.account == account else { throw MeshMessengerRootBindings.Failure.stale }
  }
}

/// Keeps message data off device backups and out of the app switcher.
///
/// Both are properties of the device the app runs on rather than of the
/// messenger protocol, so they live at the native boundary.
public enum MeshMessengerDataProtection {
  private final class SentinelRecord {
    let id: UUID
    weak var view: MeshMessengerRootSentinel?
    init(_ view: MeshMessengerRootSentinel) { id = view.id; self.view = view }
  }
  // Shared by every Module generation and the native profile adapter. No
  // UIKit/registry observation or Main dispatch occurs while holding this lock.
  static let coreLock = NSRecursiveLock()
  private static let accountTransitions = MeshMessengerNativeAccountTransitions(gate: .shared)
  static func requirePrivateReady() throws { try accountTransitions.requireIdle() }
  static func accountMutation(_ symbol: String, body: (MeshMessengerNativeAccountTransitions.Ticket?) throws -> Data) throws -> Data {
    let expected = try MeshMessengerAppLock.shared.capturedCallEpoch()
    return try accountTransitions.perform(symbol, expected: expected, body: body)
  }

  private static let startup = MeshMessengerNativeStartup()

  // Expo's subscriber initialization must have already installed its actual
  // manager. Unknown ownership fails closed; never reinstall Expo over us.
  public static func installAtLaunch() {
    guard Thread.isMainThread else { MeshMessengerAppLock.shared.nativeEnvironmentLost(); return }
    startup.install(construct: {
      let center = UNUserNotificationCenter.current(), expected = NotificationCenterManager.shared
      guard center.delegate === expected else { throw MeshMessengerNativeStartup.Failure.unavailable }
      let notices = try MeshMessengerLockedNotifications.installNative(gate: .shared, center: center, prior: expected)
      startup.retainNotices(notices)
      let manager = FileManager.default
      guard let documents = manager.urls(for: .documentDirectory, in: .userDomainMask).first,
            let cache = manager.urls(for: .cachesDirectory, in: .userDomainMask).first,
            documents.isFileURL, cache.isFileURL else { throw MeshMessengerNativeStartup.Failure.unavailable }
      let chooser = MeshMessengerNativeProtectedChooser(gate: .shared) { expected in
        try nativePresentation(expected: expected)
      }
      let files = MeshMessengerProtectedFiles(gate: .shared,
        root: cache.appendingPathComponent("morse-app-lock-files-v1", isDirectory: true), documents: documents,
        profile: { expected in try nativeProfile(expected: expected) }, nativeChooser: chooser)
      return MeshMessengerNativeStartup.Services(files: files, notices: notices,
        prepareStorage: { try prepareProtectedStorage() })
    }, protect: {
      try MeshMessengerAppLock.shared.install(cleanStaging: { try startup.clean() },
        drainNotices: { try startup.drain() }, validateEnvironment: { try startup.validate() },
        revokePrivate: { startup.revoke() })
    })
    if !startup.protectionInstalled {
      MeshMessengerAppLock.shared.nativeEnvironmentLost()
      NSLog("Morse native startup protection unavailable")
    } else if startup.hasFailure { NSLog("Morse native startup services unavailable") }
  }
  static func connectToNativeLaunch() {
    // OnCreate cannot repair a launch that admitted JS before native protection.
    if !startup.protectionInstalled { MeshMessengerAppLock.shared.nativeEnvironmentLost() }
  }
  fileprivate static func currentNativeOwner(expected: String) throws -> MeshMessengerRootBindings.Lease {
    guard Thread.isMainThread else { throw MeshMessengerRootBindings.Failure.unavailable }
    try MeshMessengerAppLock.shared.requireEpoch(expected)
    let lease = try rootBindings.currentOwner(expected: expected)
    try MeshMessengerAppLock.shared.consentForeground(ownerSceneID: lease.sceneID, expected: expected)
    return lease
  }
  @MainActor private static func nativePresentation(expected: String) throws -> (UIViewController, MeshMessengerProtectedSelectionContext) {
    let lease = try currentNativeOwner(expected: expected)
    guard let root = lease.root as? UIView, let window = lease.window as? UIWindow,
          root.window === window, let controller = window.rootViewController,
          let view = controller.viewIfLoaded, root === view || root.isDescendant(of: view) else {
      throw MeshMessengerRootBindings.Failure.unavailable
    }
    var presenter = controller, seen = Set<ObjectIdentifier>()
    while let next = presenter.presentedViewController {
      guard seen.insert(ObjectIdentifier(presenter)).inserted, seen.count <= 32,
            next.viewIfLoaded?.window === window, !next.isBeingDismissed else { throw MeshMessengerRootBindings.Failure.unavailable }
      presenter = next
    }
    guard presenter.viewIfLoaded?.window === window, !presenter.isBeingPresented,
          !presenter.isBeingDismissed, presenter.transitionCoordinator == nil else { throw MeshMessengerRootBindings.Failure.unavailable }
    return (presenter, MeshMessengerSelectionOwnerContext(lease))
  }
  static func initializeNativeCore() throws {
    coreLock.lock(); defer { coreLock.unlock() }
    try MeshLibrary.initialize()
    let status = MeshMessengerRegisterAppleHostCallbacks()
    guard status == MESH_LIBRARY_OK else {
      throw MeshLibraryFailure(status: status, payload: Data("host_callback_registration_failed".utf8))
    }
  }
  private static let nativeConsentKey = "app.morse.native-consent-scope-v1"
  static func withNativeConsent<T>(_ scope: MeshMessengerNativeOwnerScope, body: () throws -> T) throws -> T {
    try scope.check(scope.expected)
    let dictionary = Thread.current.threadDictionary, previous = dictionary[nativeConsentKey]
    dictionary[nativeConsentKey] = scope
    defer { if let previous { dictionary[nativeConsentKey] = previous } else { dictionary.removeObject(forKey: nativeConsentKey) } }
    return try body()
  }
  fileprivate static func captureNativeConsent() -> MeshMessengerNativeOwnerScope? {
    guard let scope = Thread.current.threadDictionary[nativeConsentKey] as? MeshMessengerNativeOwnerScope,
          (try? scope.check(scope.expected)) != nil else { return nil }
    return scope
  }
  @MainActor fileprivate static func nativeConsentPresenter(_ scope: MeshMessengerNativeOwnerScope) throws -> UIViewController {
    try scope.check(scope.expected)
    return try nativePresentation(expected: scope.expected).0
  }
  private static func nativeProfile(expected: String) throws -> Data {
    guard !Thread.isMainThread else { throw MeshMessengerRootBindings.Failure.unavailable }
    let capture: (MeshMessengerSelectionOwnerContext, URL) = try DispatchQueue.main.sync {
      try MainActor.assumeIsolated {
        let lease = try currentNativeOwner(expected: expected)
        guard let context = lease.context as? AppContext, let documents = context.config.documentDirectory,
              documents.isFileURL else { throw MeshMessengerRootBindings.Failure.unavailable }
        return (MeshMessengerSelectionOwnerContext(lease), documents.appendingPathComponent("morse.db"))
      }
    }
    try capture.0.validate(expected: expected)
    var result = try MeshMessengerAppLock.shared.scopedData(expected) {
      coreLock.lock(); defer { coreLock.unlock() }
      try initializeNativeCore()
      return try MeshLibrary.load_profile_export(Data(capture.1.path.utf8))
    }
    do { try capture.0.validate(expected: expected); return result }
    catch { result.resetBytes(in: result.startIndex..<result.endIndex); throw error }
  }
  private static func prepareProtectedStorage() throws {
    guard !Thread.isMainThread else { throw MeshMessengerNativeStartup.Failure.unavailable }
    let manager = FileManager.default
    let directories: [FileManager.SearchPathDirectory] = [.documentDirectory, .applicationSupportDirectory, .cachesDirectory]
    for directory in directories {
      var url = try manager.url(for: directory, in: .userDomainMask, appropriateFor: nil, create: true)
      var values = URLResourceValues(); values.isExcludedFromBackup = true
      try url.setResourceValues(values)
      guard try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else {
        throw MeshMessengerNativeStartup.Failure.unavailable
      }
    }
  }

  private static var sentinels: [UUID: SentinelRecord] = [:]
  private static weak var rootFactory: NSObject?
  private static var currentFactory: (() -> NSObject?)?
  private static let rootBindings = MeshMessengerRootBindings(gate: .shared) { root, owner in
    guard Thread.isMainThread, let root = root as? UIView, let owner = owner as? UIView,
          owner === root || owner.isDescendant(of: root), let window = root.window,
          owner.window === window, let scene = window.windowScene,
          let factory = rootFactory, let currentFactory, currentFactory() === factory else { return nil }
    // A root-window observation does not pretend the hosting root is an Expo
    // component. Owner capture below always requires an opaque native mount.
    let snapshot = owner === root ? nil : MeshMessengerCurrentMount.capture(factory: factory, root: root, owner: owner)
    guard owner === root || snapshot != nil else { return nil }
    let mount = snapshot.map { MeshMessengerAppCurrentMount(snapshot: $0, factory: factory, currentFactory: currentFactory) }
    return MeshMessengerRootBindings.Surface(window: window, scene: scene,
      sceneID: scene.session.persistentIdentifier, active: scene.activationState == .foregroundActive, mount: mount)
  }

  // Called only by the actual native ReactNativeDelegate.customize UIView.
  // A pending/unattached root supplies no foreground authority or JS grant.
  public static func bindReactNativeRoot(_ root: UIView, factory: NSObject,
                                         currentFactory: @escaping () -> NSObject?) {
    guard Thread.isMainThread else { return }
    // The exact native AppDelegate supplies this weak resolver. A delayed
    // callback from an obsolete factory cannot select or retire the root.
    guard currentFactory() === factory else { return }
    do {
      let repeated = sentinels.values.contains { $0.view?.superview === root }
      if !repeated { MeshMessengerAppLock.shared.foreground(ownerSceneID: nil, active: false, cancelPending: true) }
      rootFactory = factory
      self.currentFactory = currentFactory
      let id = try rootBindings.registerRoot(root)
      if let previous = sentinels[id]?.view, previous.superview === root { return }
      for obsolete in Array(sentinels.keys) where obsolete != id {
        let previous = sentinels.removeValue(forKey: obsolete)?.view
        previous?.removeFromSuperview()
      }
      let sentinel = MeshMessengerRootSentinel(rootID: id)
      sentinels[id] = SentinelRecord(sentinel)
      root.addSubview(sentinel)
      observeRoot(id, sentinelID: sentinel.id)
    } catch { MeshMessengerAppLock.shared.lock() }
  }
  fileprivate static func observeRoot(_ rootID: UUID, sentinelID: UUID) {
    guard Thread.isMainThread, sentinels[rootID]?.id == sentinelID else { return }
    rootBindings.rootWindowDidChange(rootID)
    if let window = sentinels[rootID]?.view?.window, let scene = window.windowScene {
      MeshMessengerAppLock.shared.foreground(ownerSceneID: scene.session.persistentIdentifier,
        active: scene.activationState == .foregroundActive)
    } else { MeshMessengerAppLock.shared.foreground(ownerSceneID: nil, active: false, cancelPending: true) }
  }
  fileprivate static func retireSentinel(_ rootID: UUID, sentinelID: UUID) {
    guard Thread.isMainThread, sentinels[rootID]?.id == sentinelID else { return }
    sentinels.removeValue(forKey: rootID); rootBindings.detachRoot(rootID)
    MeshMessengerAppLock.shared.foreground(ownerSceneID: nil, active: false, cancelPending: true)
  }
  // Snapshot comes only from this actual Module's native AppContext lookup,
  // before the lifecycle mutex. Never reenter Expo's registry under that mutex.
  static func registerModule(_ module: AnyObject, context: AppContext,
                             registeredModule: AnyObject?, moduleID: UUID) throws {
    guard Thread.isMainThread else { throw MeshMessengerRootBindings.Failure.unavailable }
    try rootBindings.registerModule(module, context: context,
      registeredModule: registeredModule, moduleID: moduleID)
  }
  static func prepareOwner(_ owner: MeshMessengerAppLockOwnerView, module: AnyObject,
                           moduleContext: AppContext, registeredModule: AnyObject?, moduleID: UUID,
                           expected: String) throws -> MeshMessengerRootBindings.Capture {
    guard Thread.isMainThread, let context = owner.appContext, context === moduleContext,
          registeredModule === module else { throw MeshMessengerRootBindings.Failure.unavailable }
    return try rootBindings.prepareCapture(owner: owner, viewContext: context, module: module,
      moduleContext: moduleContext, moduleID: moduleID, expected: expected)
  }
  static func commitOwner(_ captured: MeshMessengerRootBindings.Capture) throws -> MeshMessengerRootBindings.Lease {
    try rootBindings.commitCapture(captured)
  }
  static func validateOwner(_ lease: MeshMessengerRootBindings.Lease) throws { _ = try rootBindings.validate(lease) }
  static func validateOwnerIdentity(_ lease: MeshMessengerRootBindings.Lease) throws -> String { try rootBindings.validateIdentity(lease) }
  static func protectedFiles() throws -> MeshMessengerProtectedFiles { try startup.protectedFiles() }
  static func lockedNotices() throws -> MeshMessengerLockedNotifications { try startup.lockedNotices() }
  static func retireOwner(_ lease: MeshMessengerRootBindings.Lease) { rootBindings.retireOwner(lease) }
  static func retireModule(_ moduleID: UUID) { rootBindings.retireModule(moduleID) }

}

// Weak exact root/window observation. Key-window focus and LA prompt inactivity
// are not root detachment and are owned by the native gate's scene lifecycle.
private final class MeshMessengerRootSentinel: UIView {
  let id = UUID(), rootID: UUID
  init(rootID: UUID) { self.rootID = rootID; super.init(frame: .zero); isUserInteractionEnabled = false; isAccessibilityElement = false }
  @available(*, unavailable) required init?(coder: NSCoder) { fatalError("init(coder:) unavailable") }
  override func didMoveToWindow() {
    super.didMoveToWindow(); MeshMessengerDataProtection.observeRoot(rootID, sentinelID: id)
  }
  deinit {
    let rootID = rootID, sentinelID = id
    DispatchQueue.main.async { MeshMessengerDataProtection.retireSentinel(rootID, sentinelID: sentinelID) }
  }
}

// Expo injects the actual AppContext; no view tag/JS prop supplies a root or
// scene identity. Owner-bearing methods also compare their Module context.
final class MeshMessengerAppLockOwnerView: ExpoView {
  let onOwnerAttached = EventDispatcher()
  private var lease: MeshMessengerRootBindings.Lease?
  required init(appContext: AppContext? = nil) { super.init(appContext: appContext) }
  func prepareOwner(expected: String, module: AnyObject, moduleContext: AppContext,
                    registeredModule: AnyObject?, moduleID: UUID) throws -> MeshMessengerRootBindings.Capture {
    try MeshMessengerDataProtection.prepareOwner(self, module: module, moduleContext: moduleContext,
      registeredModule: registeredModule, moduleID: moduleID, expected: expected)
  }
  func bindOwner(_ prepared: MeshMessengerRootBindings.Capture) throws -> MeshMessengerRootBindings.Lease {
    guard prepared.owner === self else { throw MeshMessengerRootBindings.Failure.unavailable }
    let captured = try MeshMessengerDataProtection.commitOwner(prepared)
    lease = captured; return captured
  }
  func finishOwnerBinding(_ captured: MeshMessengerRootBindings.Lease) throws {
    guard lease?.id == captured.id else { throw MeshMessengerRootBindings.Failure.stale }
    try MeshMessengerDataProtection.validateOwner(captured)
  }
  override func didMoveToWindow() {
    super.didMoveToWindow()
    if window == nil, let owned = lease { lease = nil; MeshMessengerDataProtection.retireOwner(owned) }
    else if window != nil { onOwnerAttached([:]) } // Empty attach wake, never an auth result.
  }
  deinit {
    if let owned = lease { DispatchQueue.main.async { MeshMessengerDataProtection.retireOwner(owned) } }
  }
}
// Called only by the existing native wallet authorize callback on its worker.
// The token is captured before Main dispatch and remains tied to that action.
@objc(MeshMessengerAppLockConsent) public final class MeshMessengerAppLockConsent: NSObject {
  private final class Weak { weak var value: MeshMessengerAppLockConsent?; init(_ value: MeshMessengerAppLockConsent) { self.value = value } }
  // Accessed only on Main, alongside actual prompt presentation/dismissal.
  private static var pending: [UUID: Weak] = [:]
  private let id = UUID()
  private let scope: MeshMessengerNativeOwnerScope
  private var finished = false
  private var alert: UIAlertController?
  private var complete: ((Bool) -> Void)?
  private var removeRevoke: (() -> Void)?
  private init(_ scope: MeshMessengerNativeOwnerScope) { self.scope = scope; super.init() }
  @objc public static func capture() -> MeshMessengerAppLockConsent? {
    guard !Thread.isMainThread, let scope = MeshMessengerDataProtection.captureNativeConsent() else { return nil }
    return MeshMessengerAppLockConsent(scope)
  }
  static func cancelInvalidatedBeforeEvent() {
    let cancel = {
      for (id, record) in Array(pending) {
        guard let value = record.value else { pending.removeValue(forKey: id); continue }
        if (try? value.scope.check(value.scope.expected)) == nil { value.finish(false) }
      }
    }
    if Thread.isMainThread { cancel() } else { DispatchQueue.main.sync(execute: cancel) }
  }
  @objc(presentWithTitle:message:confirmation:completion:)
  public func present(title: String, message: String, confirmation: String, completion: @escaping (Bool) -> Void) {
    DispatchQueue.main.async { [self] in
      guard !finished, complete == nil else { completion(false); return }
      complete = completion
      Self.pending[id] = Weak(self)
      do {
        let owner = try MainActor.assumeIsolated { try MeshMessengerDataProtection.nativeConsentPresenter(scope) }
        guard owner.presentedViewController == nil, !owner.isBeingPresented, !owner.isBeingDismissed,
              owner.transitionCoordinator == nil else { finish(false); return }
        let value = UIAlertController(title: title, message: message, preferredStyle: .alert); alert = value
        value.addAction(UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in self?.finish(false) })
        value.addAction(UIAlertAction(title: confirmation, style: .default) { [weak self] _ in self?.finish(true) })
        removeRevoke = MeshMessengerAppLock.shared.onRevoke { [weak self] in
          let cancel = { self?.finish(false) }
          if Thread.isMainThread { cancel() } else { DispatchQueue.main.sync(execute: cancel) }
        }
        // Recheck after observer installation and immediately before presenting.
        try scope.check(scope.expected)
        owner.present(value, animated: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { [weak self] in self?.finish(false) }
      } catch { finish(false) }
    }
  }
  private func finish(_ approval: Bool) {
    guard Thread.isMainThread, !finished else { return }; finished = true
    Self.pending.removeValue(forKey: id)
    let callback = complete; complete = nil
    let remove = removeRevoke; removeRevoke = nil; remove?()
    alert?.dismiss(animated: false); alert = nil
    guard let callback else { return }
    if approval {
      do { try scope.publication(scope.expected) { callback(true) } }
      catch { callback(false) }
    } else { callback(false) }
  }
}

#endif
