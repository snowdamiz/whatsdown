import Foundation
import CoreFoundation

struct MeshMessengerNotice {
  let identifier: String
  let generic: Bool
  let title: String
  let body: String
  let scope: String?
  let mention: Bool
}

// Internal native-only port: adds are registered through completion; removals
// have no implied completion and must be checked by subsequent OS queries.
protocol MeshMessengerNoticePort: AnyObject {
  var ownsDelegate: Bool { get }
  func add(_ notice: MeshMessengerNotice, completion: @escaping (Error?) -> Void)
  func pending(_ completion: @escaping ([String]) -> Void)
  func delivered(_ completion: @escaping ([String]) -> Void)
  func removePending(_ identifiers: [String])
  func removeAllPending()
  func removeAllDelivered()
  func removeDelivered(_ identifiers: [String])
}

final class MeshMessengerLockedNotifications {
  enum Failure: Error { case invalidFrame, unavailable, draining, timeout, limit, stale }
  private final class Reply {
    private let mutex = NSLock()
    private var consumed = false
    func claim() -> Bool { mutex.lock(); defer { mutex.unlock() }; if consumed { return false }; consumed = true; return true }
    var pending: Bool { mutex.lock(); defer { mutex.unlock() }; return !consumed }
  }
  private let gate: MeshMessengerAppLock
  private let port: MeshMessengerNoticePort
  private let deadlineSeconds: TimeInterval
  private let condition = NSCondition()
  private var adding = Set<String>()
  private var completing = Set<String>()
  private var draining = false
  init(gate: MeshMessengerAppLock, port: MeshMessengerNoticePort, deadlineSeconds: TimeInterval = 5) {
    self.gate = gate; self.port = port; self.deadlineSeconds = deadlineSeconds
  }
  func checkOwnership() throws {
    guard port.ownsDelegate else { gate.nativeEnvironmentLost(); throw Failure.unavailable }
  }
  func receiveMessage(_ identifier: String, scope: String?) {
    guard (try? checkOwnership()) != nil else { return }
    gate.recordNotice(identifier, scope: scope)
  }
  func presentMessage(_ identifier: String, scope: String?, completion: (Bool) -> Void) {
    guard (try? checkOwnership()) != nil, let scope else { completion(false); return }
    if !gate.commitNoticePresentation(identifier, scope: scope, action: { completion((try? checkOwnership()) != nil) }) { completion(false) }
  }
  private func decode(_ frame: String) throws -> MeshMessengerNotice {
    guard frame.utf8.count <= 16_384, let bytes = frame.data(using: .utf8),
          let fields = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
          Set(fields.keys) == Set(["version", "id", "title", "body", "scope", "mention"]),
          let version = fields["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
          let mention = fields["mention"] as? NSNumber, CFGetTypeID(mention) == CFBooleanGetTypeID() else { throw Failure.invalidFrame }
    func text(_ key: String, _ limit: Int) throws -> String {
      guard let value = fields[key] as? String, value.utf8.count <= limit, !value.contains("\0") else { throw Failure.invalidFrame }
      return value
    }
    let id = try text("id", 1024), scope = try text("scope", 1024)
    guard !id.isEmpty, !scope.isEmpty else { throw Failure.invalidFrame }
    // Private deduplication remains in the existing message journal; the OS ID
    // contains no thread/account identifier even when previews are permitted.
    return try MeshMessengerNotice(identifier: UUID().uuidString.lowercased(), generic: false,
      title: text("title", 4096), body: text("body", 8192), scope: scope, mention: mention.boolValue)
  }
  private func generic() -> MeshMessengerNotice {
    MeshMessengerNotice(identifier: UUID().uuidString.lowercased(), generic: true, title: "", body: "", scope: nil, mention: false)
  }
  typealias Publication = (_ add: () throws -> Void) throws -> Void
  func publish(_ frame: String, expected: String, publication: Publication = { try $0() }, completion: @escaping (Result<Void, Error>) -> Void) {
    do { try gate.requireEpoch(expected); try submit(decode(frame), expected: expected, publication: publication, completion: completion) }
    catch { completion(.failure(error)) }
  }
  func genericWakeup(completion: @escaping (Result<Void, Error>) -> Void) {
    do { try submit(generic(), expected: nil, completion: completion) }
    catch { completion(.failure(error)) }
  }
  private func submit(_ requested: MeshMessengerNotice, expected: String?, publication: Publication = { try $0() }, completion: @escaping (Result<Void, Error>) -> Void) throws {
    condition.lock()
    let notice: MeshMessengerNotice
    do {
      try checkOwnership()
      guard !draining else { throw Failure.draining }
      guard adding.count < 128 else { throw Failure.limit }
      if let expected { try gate.requireEpoch(expected) }
      if !requested.generic, let expected, let scope = requested.scope {
        notice = try gate.registerNotice(requested.identifier, scope: scope, expected: expected) ? requested : generic()
      } else { notice = gate.restrictionActive ? generic() : requested }
      adding.insert(notice.identifier)
      condition.unlock()
    } catch { condition.unlock(); throw error }
    let reply = Reply(), identifier = notice.identifier
    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + deadlineSeconds) { [self] in
      guard reply.claim() else { return }
      gate.forgetNotice(identifier)
      port.removePending([identifier]); port.removeDelivered([identifier])
      // Keep the add in the registry: a caller timeout is not an OS completion.
      // A future successful drain still has to wait for that actual callback.
      completion(.failure(Failure.timeout))
    }
    // Registration precedes leaving this boundary. Drain accounts for an add
    // even if its OS invocation or completion is delayed by another thread.
    var submitted = false
    do {
      // The owner adapter encloses this actual external call in the same Main
      // turn as exact native revalidation. No broker mutex is held here.
      try publication {
        guard !submitted, reply.pending else { throw Failure.timeout }
        try checkOwnership()
        if let expected { try gate.requireEpoch(expected) }
        submitted = true
        port.add(notice) { [self] error in
      condition.lock()
      guard adding.contains(notice.identifier), !completing.contains(notice.identifier) else { condition.unlock(); return }
      completing.insert(notice.identifier); condition.unlock()
      var result: Result<Void, Error> = .success(())
      do {
        try checkOwnership()
        if let error { throw error }
        if let expected { try gate.requireEpoch(expected) }
        if !notice.generic && gate.restrictionActive { throw Failure.stale }
      } catch {
        gate.forgetNotice(notice.identifier)
        port.removePending([notice.identifier]); port.removeDelivered([notice.identifier])
        result = .failure(error)
      }
      let deliver = reply.claim()
      if !deliver { gate.forgetNotice(notice.identifier); port.removePending([notice.identifier]); port.removeDelivered([notice.identifier]) }
      condition.lock(); completing.remove(notice.identifier); adding.remove(notice.identifier); condition.broadcast(); condition.unlock()
      if deliver { completion(result) }
        }
      }
    } catch {
      gate.forgetNotice(identifier)
      port.removePending([identifier]); port.removeDelivered([identifier])
      // If the OS call has started its actual callback still owns removal,
      // just as on timeout. Refusal before submission leaves no pending add.
      if !submitted { condition.lock(); adding.remove(identifier); condition.broadcast(); condition.unlock() }
      if reply.claim() { completion(.failure(error)) }
    }
  }
  private func identifiers(_ request: (@escaping ([String]) -> Void) -> Void, deadline: TimeInterval) throws -> [String] {
    let done = DispatchSemaphore(value: 0), mutex = NSLock()
    var result: [String]?
    request { values in
      mutex.lock(); defer { mutex.unlock() }
      guard result == nil else { return }
      result = values; done.signal()
    }
    let remaining = deadline - ProcessInfo.processInfo.systemUptime
    guard remaining > 0, done.wait(timeout: .now() + remaining) == .success else { throw Failure.timeout }
    mutex.lock(); let ids = result!; mutex.unlock()
    guard ids.count <= 10_000 else { throw Failure.limit }
    var total = 0
    for id in ids {
      let size = id.utf8.count
      guard size > 0, size <= 1024, !id.contains("\0") else { throw Failure.limit }
      total += size; guard total <= 1_048_576 else { throw Failure.limit }
    }
    return ids
  }
  func drainLegacy() throws {
    guard !Thread.isMainThread else { throw Failure.unavailable }
    let deadline = ProcessInfo.processInfo.systemUptime + deadlineSeconds
    condition.lock()
    guard !draining else { condition.unlock(); throw Failure.draining }
    draining = true
    defer { condition.lock(); draining = false; condition.broadcast(); condition.unlock() }
    while !adding.isEmpty {
      let remaining = deadline - ProcessInfo.processInfo.systemUptime
      if remaining <= 0 { condition.unlock(); throw Failure.timeout }
      _ = condition.wait(until: Date(timeIntervalSinceNow: min(remaining, 0.05)))
    }
    condition.unlock()
    var removed = false
    repeat {
      try checkOwnership()
      let pending = try identifiers(port.pending, deadline: deadline)
      let delivered = try identifiers(port.delivered, deadline: deadline)
      try checkOwnership()
      guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.timeout }
      if removed && pending.isEmpty && delivered.isEmpty { return }
      port.removePending(pending); port.removeDelivered(delivered)
      // Apple excludes delivered location notifications from enumeration. Its
      // app-scoped remove-all API also withdraws those unenumerable requests.
      port.removeAllPending(); port.removeAllDelivered(); removed = true
      guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.timeout }
      Thread.sleep(forTimeInterval: 0.01)
    } while true
  }
}

#if canImport(UIKit)
import UIKit
import UserNotifications

extension MeshMessengerLockedNotifications {
  // The native launch adapter initializes Expo's manager first and passes the
  // actual installed delegate. Never call Expo.installAs... after this wrapper:
  // doing so would chain Expo back to us and create a forwarding cycle.
  static func installNative(gate: MeshMessengerAppLock, center: UNUserNotificationCenter = .current(),
                            prior: UNUserNotificationCenterDelegate) throws -> MeshMessengerLockedNotifications {
    guard Thread.isMainThread, center.delegate === prior, !(prior is IOSNoticeDelegate) else { throw Failure.unavailable }
    let port = IOSNoticePort(center: center)
    let notices = MeshMessengerLockedNotifications(gate: gate, port: port)
    let wrapper = IOSNoticeDelegate(gate: gate, notices: notices, port: port, prior: prior)
    port.wrapper = wrapper; center.delegate = wrapper
    try notices.checkOwnership()
    return notices
  }
}

private final class IOSNoticePort: MeshMessengerNoticePort {
  static let kind = "morse-encrypted-activity-v1"
  let center: UNUserNotificationCenter
  var wrapper: IOSNoticeDelegate?
  init(center: UNUserNotificationCenter) { self.center = center }
  var ownsDelegate: Bool { if let wrapper { return center.delegate === wrapper }; return false }
  static var title: String { NSLocalizedString("morse_al1_app_name", value: "Morse", comment: "Generic notification title") }
  static var body: String { NSLocalizedString("morse_al1_generic_activity", value: "New encrypted activity", comment: "Generic notification body") }
  func add(_ notice: MeshMessengerNotice, completion: @escaping (Error?) -> Void) {
    let content = UNMutableNotificationContent(); content.sound = .default
    if notice.generic {
      content.title = Self.title; content.body = Self.body
      content.userInfo = ["morseKind": Self.kind]
    } else {
      content.title = notice.title; content.body = notice.body
      content.userInfo = ["body": ["kind": "message", "scope": notice.scope ?? "", "mention": notice.mention]]
    }
    center.add(UNNotificationRequest(identifier: notice.identifier, content: content, trigger: nil), withCompletionHandler: completion)
  }
  func pending(_ completion: @escaping ([String]) -> Void) { center.getPendingNotificationRequests { completion($0.map(\.identifier)) } }
  func delivered(_ completion: @escaping ([String]) -> Void) { center.getDeliveredNotifications { completion($0.map { $0.request.identifier }) } }
  func removePending(_ identifiers: [String]) { center.removePendingNotificationRequests(withIdentifiers: identifiers) }
  func removeDelivered(_ identifiers: [String]) { center.removeDeliveredNotifications(withIdentifiers: identifiers) }
  func removeAllPending() { center.removeAllPendingNotificationRequests() }
  func removeAllDelivered() { center.removeAllDeliveredNotifications() }
  static func isGeneric(_ request: UNNotificationRequest) -> Bool {
    let c = request.content
    return UUID(uuidString: request.identifier) != nil && c.title == title && c.body == body
      && c.subtitle.isEmpty && c.attachments.isEmpty && c.categoryIdentifier.isEmpty
      && c.threadIdentifier.isEmpty && c.targetContentIdentifier == nil
      && NSDictionary(dictionary: c.userInfo).isEqual(to: ["morseKind": kind])
  }
  static func messageScope(_ request: UNNotificationRequest) -> String? {
    let content = request.content
    guard Set(content.userInfo.keys.compactMap { $0 as? String }) == Set(["body"]), content.userInfo.count == 1,
          let body = content.userInfo["body"] as? [String: Any], Set(body.keys) == Set(["kind", "scope", "mention"]),
          body["kind"] as? String == "message", let scope = body["scope"] as? String, scope.utf8.count <= 70,
          scope.range(of: "\\A(?:chat/[a-f0-9]{32}|group/[a-f0-9]{64})\\z", options: .regularExpression) != nil,
          let mention = body["mention"] as? NSNumber, CFGetTypeID(mention) == CFBooleanGetTypeID() else { return nil }
    return scope
  }
}

private final class IOSNoticeDelegate: NSObject, UNUserNotificationCenterDelegate {
  private let gate: MeshMessengerAppLock
  private weak var notices: MeshMessengerLockedNotifications?
  private weak var port: IOSNoticePort?
  private let prior: UNUserNotificationCenterDelegate
  init(gate: MeshMessengerAppLock, notices: MeshMessengerLockedNotifications, port: IOSNoticePort,
       prior: UNUserNotificationCenterDelegate) {
    self.gate = gate; self.notices = notices; self.port = port; self.prior = prior
  }
  func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                              withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    guard port?.ownsDelegate == true else { gate.nativeEnvironmentLost(); completionHandler([]); return }
    if IOSNoticePort.isGeneric(notification.request) { completionHandler([.banner, .list, .sound]); return }
    guard let notices else { completionHandler([]); return }
    var shown = false
    notices.presentMessage(notification.request.identifier, scope: IOSNoticePort.messageScope(notification.request)) {
      shown = $0; completionHandler($0 ? [.banner, .list, .sound] : [])
    }
    // Never feed private presentation objects into Expo's retained event paths.
    // The fixed generic replacement is scheduled outside the gate mutex.
    if !shown { notices.genericWakeup { _ in } }
  }
  func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                              withCompletionHandler completionHandler: @escaping () -> Void) {
    guard port?.ownsDelegate == true else { gate.nativeEnvironmentLost(); completionHandler(); return }
    guard response.actionIdentifier != UNNotificationDismissActionIdentifier else { completionHandler(); return }
    let request = response.notification.request
    let scope = response.actionIdentifier == UNNotificationDefaultActionIdentifier ? IOSNoticePort.messageScope(request) : nil
    notices?.receiveMessage(request.identifier, scope: scope)
    // A full response must never enter Expo pendingResponses/lastResponse.
    completionHandler()
  }
  func userNotificationCenter(_ center: UNUserNotificationCenter, openSettingsFor notification: UNNotification?) {
    guard port?.ownsDelegate == true else { gate.nativeEnvironmentLost(); return }
    prior.userNotificationCenter?(center, openSettingsFor: nil)
  }
}
#endif
