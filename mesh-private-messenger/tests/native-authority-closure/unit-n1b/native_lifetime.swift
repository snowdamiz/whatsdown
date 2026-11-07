import Foundation
import CoreFoundation

// Foundation lifetime ports, not UIKit/Expo substitutes or qualification.
// RootBindings, its original predicates, and the retirement dispatcher are
// compiled from production. The retained generated library owns every sink.
private final class Object {}
private final class Mount: MeshMessengerNativeMountObservation {
  func isCurrent() -> Bool { true }
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  let record = MeshMessengerAppLockPolicy.Record(install: UUID().uuidString.lowercased(), sequence: 0, policy: "disabled")
  func load() throws -> MeshMessengerAppLockPolicy.Record { record }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record {
    throw MeshMessengerAppLock.Failure.unavailable
  }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval { ProcessInfo.processInfo.systemUptime }
  var canAuthenticate: Bool { false }
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) { completion(false) }
  func cancel(requestID: String) {}
  func copyText(_ text: String) {}
  func render(state: [String: Any], uncover: Bool) {}
}
private final class Owner {
  let bindings: MeshMessengerRootBindings
  var lease: MeshMessengerRootBindings.Lease?
  init(_ bindings: MeshMessengerRootBindings) { self.bindings = bindings }
  deinit {
    if let owned = lease {
      let bindings = bindings
      #if N1B_BASELINE
      MeshMessengerNativeRetirement.onMain { bindings.retireOwner(owned) }
      #else
      MeshMessengerNativeRetirement.onMain(retiring: owned.retirement) { bindings.retireOwner(owned) }
      #endif
    }
  }
}
private final class Sentinel {
  let id = UUID()
  let bindings: MeshMessengerRootBindings, rootID: UUID
  #if !N1B_BASELINE
  let retirement: MeshMessengerNativeRetirementNode?
  #endif
  init(_ bindings: MeshMessengerRootBindings, _ rootID: UUID) throws {
    self.bindings = bindings; self.rootID = rootID
    #if !N1B_BASELINE
    retirement = try bindings.registerSentinel(rootID, sentinelID: id)
    #endif
  }
  deinit {
    let bindings = bindings, rootID = rootID, id = id
    #if N1B_BASELINE
    MeshMessengerNativeRetirement.onMain { bindings.detachRoot(rootID) }
    #else
    MeshMessengerNativeRetirement.onMain(retiring: retirement) { bindings.detachRoot(rootID, sentinelID: id) }
    #endif
  }
}

private final class Fixture {
  let gate: MeshMessengerAppLock
  let bindings: MeshMessengerRootBindings
  let context = Object(), module = Object(), window = Object(), scene = Object()
  let moduleID = UUID()
  var root = Object(), owner: Owner?, sentinel: Sentinel?
  var obsoleteSentinel: Sentinel?
  var oldLease: MeshMessengerRootBindings.Lease!
  var freshLease: MeshMessengerRootBindings.Lease?
  var oldEpoch: String!
  #if N1B_BASELINE
  let domain: OpaquePointer
  let rootNode: OpaquePointer, ownerNode: OpaquePointer
  #else
  let domain: MeshMessengerNativeRetirementDomain
  #endif
  init(_ image: String) throws {
    precondition(Thread.isMainThread)
    #if N1B_BASELINE
    var rawDomain: OpaquePointer?, rawRoot: OpaquePointer?, rawOwner: OpaquePointer?
    precondition(mesh_authority_domain_create_v2(&rawDomain) == 0)
    domain = rawDomain!
    precondition(mesh_authority_generation_v2(domain, &rawRoot) == 0)
    precondition(mesh_authority_generation_v2(domain, &rawOwner) == 0)
    rootNode = rawRoot!; ownerNode = rawOwner!
    #else
    domain = try MeshMessengerNativeRetirementDomain(imagePath: image)
    #endif
    let policy = Policy()
    gate = MeshMessengerAppLock(platform: Platform(), makeStore: { policy }, cleanStaging: {}, drainNotices: {})
    let window = window, scene = scene
    #if N1B_BASELINE
    bindings = MeshMessengerRootBindings(gate: gate) { _, _ in
      .init(window: window, scene: scene, sceneID: "scene", active: true, mount: Mount())
    }
    #else
    bindings = MeshMessengerRootBindings(gate: gate, retirementDomain: domain) { _, _ in
      .init(window: window, scene: scene, sceneID: "scene", active: true, mount: Mount())
    }
    #endif
    let ready = DispatchSemaphore(value: 0), gate = gate
    DispatchQueue.global().async { _ = try? gate.bootstrap(); ready.signal() }
    precondition(ready.wait(timeout: .now() + 5) == .success)
    gate.foreground(ownerSceneID: "scene", active: true)
    try bindings.registerModule(module, context: context, registeredModule: module, moduleID: moduleID)
    let id = try bindings.registerRoot(root)
    sentinel = try Sentinel(bindings, id)
    #if !N1B_BASELINE
    let repeated = try bindings.registerSentinel(id, sentinelID: sentinel!.id)
    precondition(repeated === sentinel!.retirement)
    #endif
    owner = Owner(bindings)
    oldLease = try bindings.capture(owner: owner!, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: gate.currentEpoch)
    owner!.lease = oldLease
    oldEpoch = gate.currentEpoch
  }
  func successor() throws {
    precondition(Thread.isMainThread)
    root = Object()
    let id = try bindings.registerRoot(root)
    sentinel = try Sentinel(bindings, id)
    owner = Owner(bindings)
    freshLease = try bindings.capture(owner: owner!, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: gate.currentEpoch)
    owner!.lease = freshLease
  }
  func replaceSentinelOnSameRoot() throws {
    precondition(Thread.isMainThread)
    obsoleteSentinel = sentinel
    gate.foreground(ownerSceneID: nil, active: false, cancelPending: true)
    let id = try bindings.registerRoot(root)
    sentinel = try Sentinel(bindings, id)
    bindings.rootWindowDidChange(id)
    gate.foreground(ownerSceneID: "scene", active: true)
    freshLease = try bindings.capture(owner: owner!, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: gate.currentEpoch)
    owner!.lease = freshLease
    oldEpoch = gate.currentEpoch
  }
  func replaceSentinelAcrossCapture() throws -> Bool {
    precondition(Thread.isMainThread)
    let captured = try bindings.prepareCapture(owner: owner!, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: gate.currentEpoch)
    let epoch = gate.currentEpoch
    obsoleteSentinel = sentinel
    sentinel = try Sentinel(bindings, oldLease.rootID)
    precondition(gate.currentEpoch == epoch)
    do { _ = try bindings.commitCapture(captured); return false }
    catch MeshMessengerRootBindings.Failure.stale {}
    freshLease = try bindings.capture(owner: owner!, viewContext: context, module: module,
      moduleContext: context, moduleID: moduleID, expected: epoch)
    owner!.lease = freshLease
    return true
  }
  #if N1B_BASELINE
  deinit {
    mesh_authority_generation_release_v2(ownerNode)
    mesh_authority_generation_release_v2(rootNode)
    mesh_authority_domain_release_v2(domain)
  }
  #endif
}

private func fixture(_ pointer: UnsafeMutableRawPointer) -> Fixture {
  Unmanaged<Fixture>.fromOpaque(pointer).takeUnretainedValue()
}
@_cdecl("n1b_create") public func create(_ path: UnsafePointer<CChar>) -> UnsafeMutableRawPointer? {
  do { return Unmanaged.passRetained(try Fixture(String(cString: path))).toOpaque() }
  catch { print("native fixture refused: \(error)"); return nil }
}
@_cdecl("n1b_domain") public func domain(_ pointer: UnsafeMutableRawPointer) -> UnsafeRawPointer {
  #if N1B_BASELINE
  return UnsafeRawPointer(fixture(pointer).domain)
  #else
  return fixture(pointer).domain.nativeDomain
  #endif
}
@_cdecl("n1b_node") public func node(_ pointer: UnsafeMutableRawPointer, _ which: Int32) -> UnsafeRawPointer? {
  let f = fixture(pointer)
  #if N1B_BASELINE
  return UnsafeRawPointer(which == 0 ? f.rootNode : f.ownerNode)
  #else
  switch which {
  case 0: return f.oldLease.rootRetirement?.nativeNode
  case 1: return f.oldLease.retirement?.nativeNode
  case 2: return f.freshLease?.retirement?.nativeNode
  case 3: return f.freshLease?.rootRetirement?.nativeNode
  case 4: return f.oldLease.sentinelRetirement?.nativeNode
  default: return f.freshLease?.sentinelRetirement?.nativeNode
  }
  #endif
}
@_cdecl("n1b_drop") public func drop(_ pointer: UnsafeMutableRawPointer, _ which: Int32) {
  precondition(!Thread.isMainThread)
  if which == 0 { fixture(pointer).sentinel = nil } else { fixture(pointer).owner = nil }
}
@_cdecl("n1b_drop_main") public func dropMain(_ pointer: UnsafeMutableRawPointer, _ which: Int32) {
  precondition(Thread.isMainThread)
  if which == 0 { fixture(pointer).sentinel = nil } else { fixture(pointer).owner = nil }
}
@_cdecl("n1b_same_root") public func sameRoot(_ pointer: UnsafeMutableRawPointer) -> Int32 {
  do { try fixture(pointer).replaceSentinelOnSameRoot(); return 1 } catch { return 0 }
}
@_cdecl("n1b_stale_capture") public func staleCapture(_ pointer: UnsafeMutableRawPointer) -> Int32 {
  do { return try fixture(pointer).replaceSentinelAcrossCapture() ? 1 : 0 } catch { return 0 }
}
@_cdecl("n1b_drop_obsolete") public func dropObsolete(_ pointer: UnsafeMutableRawPointer, _ ignored: Int32) {
  precondition(!Thread.isMainThread)
  fixture(pointer).obsoleteSentinel = nil
}
@_cdecl("n1b_hold_capture") public func holdCapture(_ pointer: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
  let f = fixture(pointer)
  do {
    let captured = try f.bindings.prepareCapture(owner: f.owner!, viewContext: f.context, module: f.module,
      moduleContext: f.context, moduleID: f.moduleID, expected: f.gate.currentEpoch)
    return Unmanaged.passRetained(captured).toOpaque()
  } catch { return nil }
}
@_cdecl("n1b_commit_capture") public func commitCapture(_ pointer: UnsafeMutableRawPointer, _ capture: UnsafeMutableRawPointer) -> Int32 {
  let captured = Unmanaged<MeshMessengerRootBindings.Capture>.fromOpaque(capture).takeUnretainedValue()
  do { return try fixture(pointer).bindings.commitCapture(captured) === fixture(pointer).oldLease ? 1 : 0 }
  catch { return 0 }
}
@_cdecl("n1b_release_capture") public func releaseCapture(_ capture: UnsafeMutableRawPointer) {
  precondition(!Thread.isMainThread)
  Unmanaged<MeshMessengerRootBindings.Capture>.fromOpaque(capture).release()
}
@_cdecl("n1b_epoch_unchanged") public func unchanged(_ pointer: UnsafeMutableRawPointer) -> Int32 {
  fixture(pointer).gate.currentEpoch == fixture(pointer).oldEpoch ? 1 : 0
}
@_cdecl("n1b_successor") public func successor(_ pointer: UnsafeMutableRawPointer) -> Int32 {
  do { try fixture(pointer).successor(); return 1 } catch { return 0 }
}
@_cdecl("n1b_drain") public func drain(_ pointer: UnsafeMutableRawPointer) -> Int32 {
  precondition(Thread.isMainThread)
  let f = fixture(pointer), epoch = f.gate.currentEpoch, loop = CFRunLoopGetMain()
  var finished = false
  DispatchQueue.main.async { finished = true; CFRunLoopStop(loop) }
  CFRunLoopRunInMode(.defaultMode, 5, false)
  guard finished, epoch == f.gate.currentEpoch, let fresh = f.freshLease,
        (try? f.bindings.validate(fresh)) != nil else { return 0 }
  return 1
}
@_cdecl("n1b_release") public func release(_ pointer: UnsafeMutableRawPointer) {
  Unmanaged<Fixture>.fromOpaque(pointer).release()
}
