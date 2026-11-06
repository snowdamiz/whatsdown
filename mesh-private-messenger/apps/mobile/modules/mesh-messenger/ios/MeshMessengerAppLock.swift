import Foundation

protocol MeshMessengerAppLockPolicyPort {
  func load() throws -> MeshMessengerAppLockPolicy.Record
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record
}
extension MeshMessengerAppLockPolicy: MeshMessengerAppLockPolicyPort {}

// Native-only ports; neither completion nor lifecycle observations are JS APIs.
protocol MeshMessengerAppLockPlatform: AnyObject {
  var monotonicTime: TimeInterval { get }
  var canAuthenticate: Bool { get }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void)
  func cancel(requestID: String)
  func copyText(_ text: String)
  // A queued UI adapter must re-read presentation() on Main before uncovering.
  func render(state: [String: Any], uncover: Bool)
}

final class MeshMessengerAppLock {
  enum Failure: String, Error {
    case staleEpoch = "stale_epoch", unavailable = "app_lock_unavailable", locked = "app_locked"
    case cancelled = "authentication_cancelled", timeout = "authentication_timeout"
    case policyUnreadable = "policy_unreadable", policyRecoveryRequired = "policy_recovery_required"
    case authenticationInProgress = "authentication_in_progress"
  }
  private final class Request {
    let id = UUID().uuidString.lowercased()
    let startingEpoch: String
    let owner: String
    let account: UInt64
    let record: MeshMessengerAppLockPolicy.Record
    let deadline: TimeInterval
    let done = DispatchSemaphore(value: 0)
    var approved = false
    var callbackConsumed = false
    var cancelled = false
    var mayRestoreDisabled = true
    var failure: Failure?
    init(epoch: String, owner: String, account: UInt64, record: MeshMessengerAppLockPolicy.Record, now: TimeInterval) {
      self.startingEpoch = epoch; self.owner = owner; self.account = account; self.record = record; self.deadline = now + 120
    }
  }
  private let mutex = NSRecursiveLock()
  private let operation = NSLock()
  private let platform: MeshMessengerAppLockPlatform
  private let makeStore: () throws -> MeshMessengerAppLockPolicyPort
  private let cleanStaging: () throws -> Void
  private let drainNotices: () throws -> Void
  private let validateEnvironment: () throws -> Void
  private let callKey = "morse.app-lock.scope." + UUID().uuidString
  private var store: MeshMessengerAppLockPolicyPort?
  private var record: MeshMessengerAppLockPolicy.Record?
  private var epoch = UUID().uuidString.lowercased()
  private var account: UInt64 = 0
  private var owner: String?
  private var active = false
  private var restricted = true
  private var phase = "booting"
  private var fault: String?
  private var readyEpoch: String?
  private var request: Request?
  private var observers: [UUID: ([String: Any]) -> Void] = [:]
  private var revocations: [UUID: () -> Void] = [:]
  private var inboxObservers: [UUID: () -> Void] = [:]
  private var pendingInbox = false
  private struct NoticeAuthority {
    let epoch: String
    let account: UInt64
    let record: MeshMessengerAppLockPolicy.Record
    let owner: String
    let scope: String
  }
  private enum IssuedNotice { case unused(NoticeAuthority), used }
  private var issuedNotices: [String: IssuedNotice] = [:]
  private var pendingNotice: (identifier: String, authority: NoticeAuthority)?
  private var bootStarted = false
  private var bootReady = false
  private var bootMustRestrict = false
  private var environmentFailed = false

  init(platform: MeshMessengerAppLockPlatform, makeStore: @escaping () throws -> MeshMessengerAppLockPolicyPort,
       cleanStaging: @escaping () throws -> Void, drainNotices: @escaping () throws -> Void,
       validateEnvironment: @escaping () throws -> Void = {}) {
    self.platform = platform; self.makeStore = makeStore; self.cleanStaging = cleanStaging; self.drainNotices = drainNotices; self.validateEnvironment = validateEnvironment
  }
  private func synchronized<T>(_ body: () throws -> T) rethrows -> T { mutex.lock(); defer { mutex.unlock() }; return try body() }
  func bootstrap() throws {
    guard !Thread.isMainThread else { throw Failure.unavailable }
    try synchronized { guard !bootStarted, !environmentFailed else { throw Failure.unavailable }; bootStarted = true }
    do {
      try validateEnvironment()
      let store = try makeStore(), value = try store.load()
      synchronized { self.store = store; record = value; restricted = bootMustRestrict || value.policy != "disabled" }
      try cleanStaging()
      if restrictionActive { try drainNotices() }
      try validateEnvironment()
      try synchronized { guard !environmentFailed else { throw Failure.unavailable }; bootReady = true; phase = restricted ? "locked" : "disabled"; fault = nil }
      emit()
    } catch {
      synchronized { restricted = true; phase = "error"; fault = Failure.policyUnreadable.rawValue }
      emit(); throw error
    }
  }
  var currentEpoch: String { synchronized { epoch } }
  var accountGeneration: UInt64 { synchronized { account } }
  var restrictionActive: Bool { synchronized { restricted || record?.policy != "disabled" } }
  // Losing a required native owner makes this process untrustworthy for private
  // admission. Revoke immediately; schedule UI/cleanup after all nested state
  // locks unwind. Restoring the delegate cannot revive the previous session.
  private func checkEnvironmentLocked() throws {
    guard !environmentFailed else { throw Failure.unavailable }
    do { try validateEnvironment() }
    catch {
      quarantineEnvironmentLocked()
      throw error
    }
  }
  // Only native owners may report a loss. Preserve the observation even if the
  // delegate has been restored before this gate acquires its state lock.
  func nativeEnvironmentLost() { synchronized { quarantineEnvironmentLocked() } }
  private func quarantineEnvironmentLocked() {
    guard !environmentFailed else { return }
    environmentFailed = true; bootMustRestrict = true; restricted = true
    phase = "error"; fault = Failure.unavailable.rawValue
    request?.mayRestoreDisabled = false; rotateEpochLocked()
    let cancelled = cancelLocked()
    DispatchQueue.main.async { [weak self] in self?.revoked(cancelled) }
  }
  func state() -> [String: Any] {
    synchronized {
      var value: [String: Any] = ["version": 1, "epoch": epoch, "policy": record?.policy ?? "unknown", "phase": phase,
                                "capability": platform.canAuthenticate ? "available" : "unavailable"]
      if let request { value["requestId"] = request.id }; if let fault { value["error"] = fault }; return value
    }
  }
  func presentation() -> (state: [String: Any], uncover: Bool, owner: String?) {
    synchronized {
      let environmentOK = (try? checkEnvironmentLocked()) != nil
      return (state(), environmentOK && readyEpoch == epoch && active && (phase == "unlocked" || phase == "disabled"), owner)
    }
  }
  // Only the immediate native hide is admitted here; building/layout stays out.
  func commitUncover(_ expected: String, ownerSceneID: String, action: () -> Void) -> Bool {
    guard Thread.isMainThread else { return false }
    return synchronized {
      guard (try? checkEnvironmentLocked()) != nil else { return false }
      guard expected == epoch, readyEpoch == epoch, active, owner == ownerSceneID,
            phase == "unlocked" || phase == "disabled" else { return false }
      action(); return true
    }
  }
  private func emit() {
    let value = presentation(), listeners = synchronized { Array(observers.values) }
    platform.render(state: value.state, uncover: value.uncover)
    listeners.forEach { $0(value.state) }
  }
  func observe(_ body: @escaping ([String: Any]) -> Void) -> () -> Void {
    let id = UUID(); synchronized { observers[id] = body }; return { [weak self] in _ = self?.synchronized { self?.observers.removeValue(forKey: id) } }
  }
  func onRevoke(_ body: @escaping () -> Void) -> () -> Void {
    let id = UUID(); synchronized { revocations[id] = body }; return { [weak self] in _ = self?.synchronized { self?.revocations.removeValue(forKey: id) } }
  }
  func observeInbox(_ body: @escaping () -> Void) -> () -> Void {
    let id = UUID(); synchronized { inboxObservers[id] = body }; return { [weak self] in _ = self?.synchronized { self?.inboxObservers.removeValue(forKey: id) } }
  }
  func recordInboxOpen() {
    let listeners = synchronized { pendingInbox = true; pendingNotice = nil; return Array(inboxObservers.values) }; listeners.forEach { $0() }
  }
  func consumeInbox(_ expected: String) throws -> Bool {
    try synchronized { try requireEpoch(expected); let pending = pendingInbox; pendingInbox = false; return pending }
  }
  // Private routing is volatile and bound to the actual native publication.
  // A response's untrusted scope cannot be relabeled into a later account.
  private func validNoticeScope(_ scope: String) -> Bool {
    scope.utf8.count <= 70 && scope.range(of: "\\A(?:chat/[a-f0-9]{32}|group/[a-f0-9]{64})\\z", options: .regularExpression) != nil
  }
  private func matchesNotice(_ value: NoticeAuthority) -> Bool {
    do { try checkEnvironmentLocked() } catch { dropPrivateNoticesLocked(); return false }
    return bootReady && !restricted && phase == "disabled" && record?.policy == "disabled"
      && value.epoch == epoch && value.account == account && value.record == record && value.owner == owner
  }
  func registerNotice(_ identifier: String, scope: String, expected: String) throws -> Bool {
    try synchronized {
      try requireEpoch(expected)
      guard !restrictionActive else { return false }
      guard UUID(uuidString: identifier) != nil, validNoticeScope(scope), let record, let owner,
            phase == "disabled", issuedNotices[identifier] == nil, issuedNotices.count < 128 else { throw Failure.unavailable }
      issuedNotices[identifier] = .unused(NoticeAuthority(epoch: epoch, account: account, record: record, owner: owner, scope: scope))
      return true
    }
  }
  func forgetNotice(_ identifier: String) {
    synchronized {
      issuedNotices.removeValue(forKey: identifier)
      if pendingNotice?.identifier == identifier { pendingNotice = nil; pendingInbox = true }
    }
  }
  func recordNotice(_ identifier: String, scope: String?) {
    let listeners: [() -> Void] = synchronized {
      if case .used? = issuedNotices[identifier] { return [] }
      let issued = issuedNotices[identifier]
      pendingNotice = nil; pendingInbox = true
      if case .unused(let value)? = issued {
        issuedNotices[identifier] = .used // No private scope in the tombstone.
        if scope == value.scope, matchesNotice(value) {
          pendingNotice = (identifier, value); pendingInbox = false
        }
      }
      return Array(inboxObservers.values)
    }
    listeners.forEach { $0() }
  }
  func consumeNotice(_ expected: String, ownerSceneID: String) throws -> String {
    try synchronized {
      try requireEpoch(expected)
      guard active, owner == ownerSceneID else { throw Failure.locked }
      if let value = pendingNotice {
        pendingNotice = nil
        if matchesNotice(value.authority) {
          return "{\"version\":1,\"kind\":\"scope\",\"scope\":\"\(value.authority.scope)\"}"
        }
        pendingInbox = true
      }
      let kind = pendingInbox ? "inbox" : "none"; pendingInbox = false
      return "{\"version\":1,\"kind\":\"\(kind)\"}"
    }
  }
  // Only the short native presentation completion runs within this ordering.
  func commitNoticePresentation(_ identifier: String, scope: String, action: () -> Void) -> Bool {
    synchronized {
      guard case .unused(let value)? = issuedNotices[identifier], scope == value.scope, matchesNotice(value) else { return false }
      action(); return true
    }
  }
  private func rotateEpochLocked() {
    epoch = UUID().uuidString.lowercased(); readyEpoch = nil
    dropPrivateNoticesLocked()
  }
  private func dropPrivateNoticesLocked() {
    issuedNotices.removeAll()
    if pendingNotice != nil { pendingNotice = nil; pendingInbox = true }
  }
  private func cancelLocked() -> String? {
    guard let request else { return nil }
    request.cancelled = true; request.failure = request.failure ?? .cancelled; request.done.signal(); return request.id
  }
  // Callbacks execute outside the state mutex. UI covering never waits for the
  // operation mutex, Keychain, notification drain or an admitted core call.
  private func revoked(_ cancelled: String?) {
    emit()
    if let cancelled { platform.cancel(requestID: cancelled) }
    let listeners = synchronized { Array(revocations.values) }; listeners.forEach { $0() }
  }
  func foreground(ownerSceneID: String?, active: Bool, cancelPending: Bool = false) {
    do { try synchronized { try checkEnvironmentLocked() } }
    catch {
      let cancelled = synchronized { () -> String? in
        owner = ownerSceneID; self.active = false; restricted = true
        rotateEpochLocked(); phase = "error"; fault = Failure.unavailable.rawValue
        request?.mayRestoreDisabled = false; return cancelLocked()
      }
      revoked(cancelled); return
    }
    let change: (Bool, String?) = synchronized {
      let ownerChanged = owner != ownerSceneID
      owner = ownerSceneID; self.active = active && ownerSceneID != nil
      if !self.active || ownerChanged || cancelPending {
        rotateEpochLocked()
        let cancelled = (cancelPending || ownerChanged || ownerSceneID == nil) ? cancelLocked() : nil
        if bootReady { phase = request != nil ? "authenticating" : (record?.policy == "disabled" && !restricted ? "disabled" : "locked") }
        return (true, cancelled)
      }
      if let request, request.approved, !request.cancelled, request.owner == owner, self.active { request.done.signal() }
      return (false, nil)
    }
    if change.0 { revoked(change.1) } else { emit() }
  }
  func lock() {
    let cancelled = synchronized { if !bootReady { bootMustRestrict = true }; request?.mayRestoreDisabled = false; restricted = true; rotateEpochLocked(); if bootReady { phase = "locked" }; return cancelLocked() }
    revoked(cancelled)
  }
  func accountChanging() {
    let cancelled = synchronized {
      request?.mayRestoreDisabled = false
      // Saturation still revokes every epoch; the process can never wrap back.
      if account < UInt64.max { account += 1 }
      rotateEpochLocked()
      if bootReady { phase = record?.policy == "disabled" && !restricted ? "disabled" : "locked" }
      return cancelLocked()
    }
    revoked(cancelled)
  }
  func cancel(_ requestID: String?, ownerSceneID: String) {
    let cancelled: String? = synchronized {
      guard let value = request, requestID == value.id, ownerSceneID == value.owner, ownerSceneID == owner else { return nil }
      rotateEpochLocked(); return cancelLocked()
    }
    if cancelled != nil { revoked(cancelled) }
  }
  func requireEpoch(_ expected: String) throws {
    try synchronized {
      guard expected == epoch else { throw Failure.staleEpoch }
      try checkEnvironmentLocked()
      guard bootReady, record != nil, phase != "booting", phase != "error" else { throw Failure.unavailable }
      if restricted || record?.policy != "disabled" {
        guard record?.policy == "enabled", phase == "unlocked", active, owner != nil else { throw Failure.locked }
      }
    }
  }
  func publication(_ expected: String) throws { try requireEpoch(expected) }
  func copyProtectedText(_ text: String, expected: String) throws {
    guard Thread.isMainThread, text.utf8.count <= 1_048_576 else { throw Failure.unavailable }
    // The bounded local clipboard commit and revocation share one ordering.
    // Never use this critical section for provider, network, file or policy IO.
    try synchronized { try requireEpoch(expected); platform.copyText(text) }
  }
  func activate(_ expected: String, ownerSceneID: String) throws {
    guard Thread.isMainThread else { throw Failure.unavailable }
    try synchronized { try requireEpoch(expected); guard active, owner == ownerSceneID else { throw Failure.locked }; readyEpoch = expected }
    emit()
  }
  func scoped<T>(_ expected: String, body: () throws -> T) throws -> T {
    try requireEpoch(expected)
    let dictionary = Thread.current.threadDictionary, previous = dictionary[callKey]
    dictionary[callKey] = expected
    defer { if let previous { dictionary[callKey] = previous } else { dictionary.removeObject(forKey: callKey) } }
    let value = try body(); try requireEpoch(expected); return value
  }
  // Private bridge byte responses use this overload so the owned Data value is
  // cleared if revoke wins before completion. It cannot wipe unrelated copies
  // retained by a provider; providers retain their own cleanup obligations.
  func scopedData(_ expected: String, body: () throws -> Data) throws -> Data {
    try requireEpoch(expected)
    let dictionary = Thread.current.threadDictionary, previous = dictionary[callKey]
    dictionary[callKey] = expected
    defer { if let previous { dictionary[callKey] = previous } else { dictionary.removeObject(forKey: callKey) } }
    var value = try body()
    do { try requireEpoch(expected); return value }
    catch { value.resetBytes(in: value.startIndex..<value.endIndex); throw error }
  }
  func capturedCallEpoch() throws -> String {
    guard let expected = Thread.current.threadDictionary[callKey] as? String else { throw Failure.unavailable }
    try requireEpoch(expected); return expected
  }
  private func validate(_ value: Request) throws {
    try synchronized {
      guard request === value else { throw Failure.cancelled }
      try checkEnvironmentLocked()
      if let failure = value.failure { throw failure }
      guard request === value, !value.cancelled, value.approved, value.account == account,
            value.owner == owner, active else { throw Failure.cancelled }
      guard platform.monotonicTime <= value.deadline else { throw Failure.timeout }
    }
  }
  private func completed(_ value: Request, success: Bool) {
    synchronized {
      guard request === value, !value.cancelled, !value.callbackConsumed else { return }
      value.callbackConsumed = true
      if !success || platform.monotonicTime > value.deadline {
        value.failure = platform.monotonicTime > value.deadline ? .timeout : .cancelled
        value.cancelled = true; value.done.signal(); return
      }
      value.approved = true
      if active && owner == value.owner { value.done.signal() }
    }
  }
  func authenticate(_ expected: String, ownerSceneID: String, desired: Bool? = nil) throws -> [String: Any] {
    guard !Thread.isMainThread else { throw Failure.unavailable }
    guard operation.try() else { throw Failure.authenticationInProgress }
    var admitted = false, authenticated = false
    var original: MeshMessengerAppLockPolicy.Record?
    var firstOptIn = false, recoveringDisable = false
    var owned: Request?
    defer {
      let id = synchronized { () -> String? in
        guard let owned else { return nil }
        if request === owned { request = nil }
        return owned.id
      }
      if let id { platform.cancel(requestID: id) }; operation.unlock()
      if admitted { emit() }
    }
    do {
      let value: Request? = try synchronized {
        guard bootReady else { throw Failure.unavailable }
        try checkEnvironmentLocked()
        guard expected == epoch, active, let owner, owner == ownerSceneID, let record, phase != "booting", phase != "error" else { throw Failure.staleEpoch }
        guard request == nil else { throw Failure.authenticationInProgress }
        original = record; firstOptIn = record.policy == "disabled" && !restricted && desired == true
        recoveringDisable = record.policy == "disabled" && restricted
        admitted = true
        if desired == nil && record.policy == "disabled" && !restricted { return nil }
        let value = Request(epoch: expected, owner: owner, account: account, record: record, now: platform.monotonicTime)
        restricted = true; rotateEpochLocked(); phase = "authenticating"; fault = nil; request = value
        return value
      }
      guard let value else { return state() }; owned = value
      revoked(nil)
      guard platform.canAuthenticate else { throw Failure.unavailable }
      platform.present(requestID: value.id, ownerSceneID: value.owner) { [weak self, weak value] success in
        if let value { self?.completed(value, success: success) }
      }
      guard value.done.wait(timeout: .now() + 120) == .success else { throw Failure.timeout }
      try validate(value); authenticated = true
      guard let store = synchronized({ self.store }), let original else { throw Failure.policyUnreadable }
      guard try store.load() == value.record else { throw Failure.policyRecoveryRequired }
      try validate(value)
      // Native policy IO is outside the state mutex; a revoke can win at every
      // write/readback boundary and must be rechecked before publishing success.
      if desired == nil && original.policy != "enabled" && !recoveringDisable { throw Failure.policyRecoveryRequired }
      if let desired {
        let final = desired ? "enabled" : "disabled", pending = desired ? "enable_pending" : "disable_pending"
        if original.policy != final {
          if original.policy != pending {
            let next = try store.transition(previous: original, desired: pending); synchronized { record = next }
          }
          try validate(value)
          if desired { try drainNotices() }
          try validate(value)
          guard let previous = synchronized({ record }) else { throw Failure.policyUnreadable }
          let next = try store.transition(previous: previous, desired: final); synchronized { record = next }
        }
      }
      return try synchronized {
        try validate(value); restricted = record?.policy != "disabled"
        rotateEpochLocked(); phase = restricted ? "unlocked" : "disabled"; fault = nil
        request = nil
        return state()
      }
    } catch {
      guard admitted else { throw error }
      let durable = try? synchronized({ store })?.load()
      let environmentOK = synchronized { (try? checkEnvironmentLocked()) != nil }
      synchronized {
        if let durable { record = durable }
        if environmentOK && firstOptIn && !authenticated && owned?.approved != true && owned?.mayRestoreDisabled == true && durable == original && durable?.policy == "disabled" {
          restricted = false; phase = "disabled"; fault = nil
        } else {
          restricted = true; phase = durable == nil || !environmentOK ? "error" : "locked"
          fault = durable == nil ? Failure.policyUnreadable.rawValue : ((error as? Failure)?.rawValue ?? "authentication_failed")
        }
        rotateEpochLocked()
      }
      throw error
    }
  }
}

#if canImport(UIKit)
import UIKit
import LocalAuthentication

extension MeshMessengerAppLock {
  private static let nativeHooks = NativeHooks()
  static let shared: MeshMessengerAppLock = {
    let platform = IOSAppLockPlatform()
    let value = MeshMessengerAppLock(platform: platform, makeStore: { try MeshMessengerAppLockPolicy() },
      cleanStaging: { try nativeHooks.clean() }, drainNotices: { try nativeHooks.drain() }, validateEnvironment: { try nativeHooks.validate() })
    platform.gate = value
    return value
  }()
  // Install from native launch before RN/Expo can admit private callbacks.
  // All hooks are required; missing providers cannot become a successful boot.
  func install(cleanStaging: @escaping () throws -> Void, drainNotices: @escaping () throws -> Void,
               validateEnvironment: @escaping () throws -> Void, revokePrivate: @escaping () -> Void) throws {
    guard Thread.isMainThread, self === Self.shared, let native = platform as? IOSAppLockPlatform else { throw Failure.unavailable }
    guard !Self.nativeHooks.installed else { return }
    Self.nativeHooks.cleanStaging = cleanStaging; Self.nativeHooks.drainNotices = drainNotices; Self.nativeHooks.validateEnvironment = validateEnvironment; Self.nativeHooks.installed = true
    _ = onRevoke(revokePrivate)
    native.install()
    DispatchQueue.global(qos: .userInitiated).async { _ = try? self.bootstrap() }
  }
  func consentForeground(ownerSceneID: String, expected: String) throws {
    guard Thread.isMainThread else { throw Failure.unavailable }
    try synchronized {
      guard owner == ownerSceneID, active else { throw Failure.locked }
      try requireEpoch(expected)
    }
  }
  private final class NativeHooks {
    var installed = false
    var cleanStaging: (() throws -> Void)?
    var drainNotices: (() throws -> Void)?
    var validateEnvironment: (() throws -> Void)?
    func validate() throws { guard let validateEnvironment else { throw Failure.unavailable }; try validateEnvironment() }
    func clean() throws { guard let cleanStaging else { throw Failure.unavailable }; try cleanStaging() }
    func drain() throws { guard let drainNotices else { throw Failure.unavailable }; try drainNotices() }
  }
}

private final class IOSAppLockPlatform: MeshMessengerAppLockPlatform {
  weak var gate: MeshMessengerAppLock?
  private var observers: [NSObjectProtocol] = []
  private var covers: [String: UIWindow] = [:]
  private var contexts: [String: LAContext] = [:]
  private let capabilityLock = NSLock()
  private var capability = false
  var monotonicTime: TimeInterval { ProcessInfo.processInfo.systemUptime }
  var canAuthenticate: Bool { capabilityLock.lock(); defer { capabilityLock.unlock() }; return capability }
  private func main(_ body: @escaping () -> Void) { if Thread.isMainThread { body() } else { DispatchQueue.main.async(execute: body) } }
  private func refreshCapability() {
    let context = LAContext(); context.interactionNotAllowed = true
    let possible = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    context.invalidate(); capabilityLock.lock(); capability = possible; capabilityLock.unlock()
  }
  func install() {
    precondition(Thread.isMainThread)
    refreshCapability()
    let center = NotificationCenter.default
    for name in [UIScene.willConnectNotification, UIScene.didActivateNotification, UIScene.willDeactivateNotification,
                 UIScene.didEnterBackgroundNotification, UIScene.didDisconnectNotification] {
      observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in self?.sceneEvent(note) })
    }
    observers.append(center.addObserver(forName: UIWindow.didBecomeVisibleNotification, object: nil, queue: .main) { [weak self] note in
      guard let self, let window = note.object as? UIWindow, !self.covers.values.contains(where: { $0 === window }) else { return }
      self.renderNow()
    })
    // A global inactive/background observation covers all scenes immediately;
    // scene notifications provide exact owner identity for subsequent admission.
    observers.append(center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
      guard let self else { return }; self.gate?.foreground(ownerSceneID: self.gate?.presentation().owner, active: false)
    })
    observers.append(center.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
      guard let self else { return }; self.gate?.foreground(ownerSceneID: self.gate?.presentation().owner, active: false, cancelPending: true)
    })
    let active = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.filter { $0.activationState == .foregroundActive }
    // Ambiguous simultaneous scenes start covered until one exact scene event.
    gate?.foreground(ownerSceneID: active.count == 1 ? active[0].session.persistentIdentifier : nil, active: active.count == 1)
    renderNow()
  }
  private func sceneEvent(_ note: Notification) {
    guard let scene = note.object as? UIWindowScene, let gate else { return }
    let id = scene.session.persistentIdentifier
    switch note.name {
    case UIScene.didActivateNotification:
      refreshCapability(); gate.foreground(ownerSceneID: id, active: true)
    case UIScene.willDeactivateNotification:
      if gate.presentation().owner == id { gate.foreground(ownerSceneID: id, active: false) }
    case UIScene.didEnterBackgroundNotification, UIScene.didDisconnectNotification:
      if gate.presentation().owner == id { gate.foreground(ownerSceneID: note.name == UIScene.didDisconnectNotification ? nil : id, active: false, cancelPending: true) }
      if note.name == UIScene.didDisconnectNotification { covers.removeValue(forKey: id)?.isHidden = true }
    default: break
    }
    renderNow()
  }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) {
    main { [weak self] in
      guard let self, let gate = self.gate, gate.state()["requestId"] as? String == requestID,
            let scene = UIApplication.shared.connectedScenes.first(where: { $0.session.persistentIdentifier == ownerSceneID }),
            scene.activationState == .foregroundActive else { completion(false); return }
      let context = LAContext()
      context.touchIDAuthenticationAllowableReuseDuration = 0
      context.localizedCancelTitle = NSLocalizedString("morse_al1_cancel", value: "Cancel", comment: "Cancel device authentication")
      self.contexts[requestID] = context
      guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { self.contexts.removeValue(forKey: requestID); context.invalidate(); completion(false); return }
      context.evaluatePolicy(.deviceOwnerAuthentication,
        localizedReason: NSLocalizedString("morse_al1_unlock_description", value: "Unlock Morse with biometrics or your device passcode.", comment: "Device authentication reason")) { [weak self, weak context] success, _ in
          self?.main {
            guard let self, let context, self.contexts[requestID] === context else { return }
            completion(success)
          }
      }
    }
  }
  func copyText(_ text: String) { precondition(Thread.isMainThread); UIPasteboard.general.string = text }
  func cancel(requestID: String) { main { [weak self] in self?.contexts.removeValue(forKey: requestID)?.invalidate() } }
  func render(state: [String: Any], uncover: Bool) { main { [weak self] in self?.renderNow() } }
  private func renderNow() {
    precondition(Thread.isMainThread)
    guard let gate else { return }
    let value = gate.presentation()
    for scene in UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }) {
      let id = scene.session.persistentIdentifier
      if value.uncover, let expected = value.state["epoch"] as? String, scene.activationState == .foregroundActive,
         gate.commitUncover(expected, ownerSceneID: id, action: { self.covers.removeValue(forKey: id)?.isHidden = true }) { continue }
      let cover: UIWindow
      if let existing = covers[id] { cover = existing }
      else {
        cover = UIWindow(windowScene: scene); covers[id] = cover
        cover.rootViewController = IOSAppLockCoverController()
        cover.backgroundColor = UIColor(red: 0.04, green: 0.04, blue: 0.05, alpha: 1)
      }
      let appLevels = scene.windows.filter { $0 !== cover }.map { $0.windowLevel.rawValue }
      cover.windowLevel = UIWindow.Level(rawValue: max(UIWindow.Level.alert.rawValue, appLevels.max() ?? 0) + 1)
      (cover.rootViewController as? IOSAppLockCoverController)?.configure(gate: gate, state: value.state, ownerSceneID: id)
      // Keep app/OS focus ownership; making this key could cancel an LA prompt.
      cover.isHidden = false
    }
  }
}

private final class IOSAppLockCoverController: UIViewController {
  private let stack = UIStackView()
  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = UIColor(red: 0.04, green: 0.04, blue: 0.05, alpha: 1)
    stack.axis = .vertical; stack.alignment = .center; stack.spacing = 18; stack.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(stack)
    NSLayoutConstraint.activate([stack.centerXAnchor.constraint(equalTo: view.centerXAnchor), stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
      stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
      stack.trailingAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24)])
  }
  func configure(gate: MeshMessengerAppLock, state: [String: Any], ownerSceneID: String) {
    loadViewIfNeeded()
    stack.arrangedSubviews.forEach { stack.removeArrangedSubview($0); $0.removeFromSuperview() }
    let title = UILabel(); title.text = NSLocalizedString("morse_al1_locked", value: "Morse is locked", comment: "Native app-lock cover")
    title.textColor = .white; title.font = .preferredFont(forTextStyle: .title2); stack.addArrangedSubview(title)
    if state["error"] != nil {
      let error = UILabel(); error.numberOfLines = 0; error.textAlignment = .center; error.textColor = .white
      error.text = NSLocalizedString("morse_al1_unlock_failed", value: "Could not unlock. Your messages remain protected.", comment: "Authentication failure")
      stack.addArrangedSubview(error)
    }
    func control(_ key: String, _ fallback: String, _ action: @escaping () -> Void) {
      let button = UIButton(type: .system); button.setTitle(NSLocalizedString(key, value: fallback, comment: "Native app-lock control"), for: .normal)
      button.addAction(UIAction { _ in action() }, for: .touchUpInside); stack.addArrangedSubview(button)
    }
    func authenticate(_ desired: Bool?) {
      guard view.window?.windowScene?.session.persistentIdentifier == ownerSceneID, let expected = state["epoch"] as? String else { return }
      DispatchQueue.global(qos: .userInitiated).async { _ = try? gate.authenticate(expected, ownerSceneID: ownerSceneID, desired: desired) }
    }
    if let id = state["requestId"] as? String { control("morse_al1_cancel", "Cancel") { gate.cancel(id, ownerSceneID: ownerSceneID) } }
    else if state["policy"] as? String == "enable_pending" || state["policy"] as? String == "disable_pending" {
      control("morse_al1_finish_enable", "Finish enabling") { authenticate(true) }
      control("morse_al1_disable", "Disable app lock") { authenticate(false) }
    } else { control("morse_al1_unlock_title", "Unlock Morse") { authenticate(nil) } }
  }
}
#endif
