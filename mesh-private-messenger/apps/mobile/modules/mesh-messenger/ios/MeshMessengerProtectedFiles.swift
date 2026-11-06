import Foundation
import CryptoKit
import Darwin
import CoreFoundation
import ImageIO
import UniformTypeIdentifiers

// Native validation may be called by a provider callback; UIKit observations
// must be serialized internally on Main without waiting for a UI result.
protocol MeshMessengerProtectedSelectionContext: AnyObject {
  func validate(expected: String) throws
}
protocol MeshMessengerProtectedPhoto: AnyObject {
  func importAvatar(expected: String, completion: @escaping (Result<String?, Error>) -> Void) -> MeshMessengerProtectedCleanup
}
final class MeshMessengerProtectedSelection {
  enum Payload { case documents([URL]), photo(MeshMessengerProtectedPhoto) }
  let payload: Payload, context: MeshMessengerProtectedSelectionContext
  init(_ payload: Payload, context: MeshMessengerProtectedSelectionContext) { self.payload = payload; self.context = context }
}
protocol MeshMessengerProtectedChooser: AnyObject {
  func choose(purpose: String, multiple: Bool, expected: String,
              completion: @escaping (Result<MeshMessengerProtectedSelection?, Error>) -> Void) -> MeshMessengerProtectedCleanup
}

protocol MeshMessengerProtectedOutput: AnyObject {
  func write(_ bytes: Data) throws
  func close() throws
}

// Synchronous native accessor lifetime. This is a provider IO seam only;
// neither the coordinated URL nor the port supplies native lock authority.
protocol MeshMessengerProtectedCoordinator: AnyObject {
  func read(_ url: URL, body: (URL) throws -> Void) throws
  func write(_ url: URL, body: (URL) throws -> Void) throws
  func cancel()
}
private extension MeshMessengerProtectedCoordinator {
  func access(_ url: URL, writing: Bool, body: (URL) throws -> Void) throws {
    if writing { try write(url, body: body) }
    else { try read(url, body: body) }
  }
}

// One native Foundation object per operation. This adapter lends only the
// synchronous effective URL; neither coordination nor cancellation grants auth.
final class MeshMessengerNativeProtectedCoordinator: MeshMessengerProtectedCoordinator {
  private let coordinator: NSFileCoordinator
  private let timeout: TimeInterval
  private let mutex = NSLock()
  private let cancellation: MeshMessengerProtectedCleanup
  private var admitted = false, finished = false, cancelled = false
  private var callbacks = 0, invalidCallback = false
  init(coordinator: NSFileCoordinator = NSFileCoordinator(filePresenter: nil), timeout: TimeInterval = 30) {
    self.coordinator = coordinator; self.timeout = timeout
    cancellation = MeshMessengerProtectedCleanup { coordinator.cancel() }
  }
  private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
    mutex.lock(); defer { mutex.unlock() }; return try body()
  }
  deinit { cancellation.run() }
  func read(_ url: URL, body: (URL) throws -> Void) throws { try access(url, writing: false, body: body) }
  func write(_ url: URL, body: (URL) throws -> Void) throws { try access(url, writing: true, body: body) }
  func cancel() {
    synchronized { cancelled = true }
    // Foundation explicitly allows cancellation from another thread and does
    // not recall an accessor already running. Never hold our mutex across it.
    cancellation.run()
  }
  private func foundation(_ url: URL, writing: Bool, body: (URL) -> Void) -> NSError? {
    var error: NSError?
    if writing { coordinator.coordinate(writingItemAt: url, options: [], error: &error, byAccessor: body) }
    else { coordinator.coordinate(readingItemAt: url, options: [], error: &error, byAccessor: body) }
    return error
  }
  private func access(_ url: URL, writing: Bool, body: (URL) throws -> Void) throws {
    guard !Thread.isMainThread, url.isFileURL, timeout.isFinite, timeout > 0, timeout <= 30 else {
      throw MeshMessengerProtectedFiles.Failure.unavailable
    }
    try synchronized {
      guard !admitted, !finished, !cancelled else { throw MeshMessengerProtectedFiles.Failure.unavailable }
      admitted = true
    }
    let deadline = DispatchWorkItem { [weak self] in self?.cancel() }
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: deadline)
    defer { deadline.cancel(); synchronized { finished = true } }
    try synchronized {
      guard !cancelled, !finished else { throw MeshMessengerProtectedFiles.Failure.unavailable }
    }
    var callbackError: Error?
    let error = foundation(url, writing: writing) { effective in
      let allowed = self.synchronized { () -> Bool in
        self.callbacks += 1
        guard self.callbacks == 1, !self.finished, !self.cancelled else {
          self.invalidCallback = true; return false
        }
        return true
      }
      guard allowed else { return }
      do {
        guard effective.isFileURL else { throw MeshMessengerProtectedFiles.Failure.storage }
        try body(effective)
      } catch { callbackError = error }
    }
    let complete = synchronized { () -> Bool in
      finished = true
      return !cancelled && !invalidCallback && callbacks == 1
    }
    // Keep the exact original accessor outcome even if Foundation also reports
    // a disposition. Caller-owned byte cleanup remains in the provider scope.
    if let callbackError { throw callbackError }
    if let error { throw error }
    guard complete else { throw MeshMessengerProtectedFiles.Failure.unavailable }
  }
}

// Native-only ports and resource ownership. Neither is exposed to JS or
// accepted as authentication; the gate remains the authority at every action.
protocol MeshMessengerProtectedScopePort: AnyObject {
  func start(_ url: URL) -> Bool
  func stop(_ url: URL)
}
private final class NativeProtectedScopePort: MeshMessengerProtectedScopePort {
  func start(_ url: URL) -> Bool { url.startAccessingSecurityScopedResource() }
  func stop(_ url: URL) { url.stopAccessingSecurityScopedResource() }
}
final class MeshMessengerProtectedCleanup {
  private let mutex = NSLock()
  private var action: (() -> Void)?
  init(_ action: @escaping () -> Void) { self.action = action }
  func run() {
    mutex.lock(); let owned = action; action = nil; mutex.unlock()
    // Reentrant/duplicate callers cannot take the same lease. IO and scope
    // release stay outside the ownership lock and the controller state mutex.
    owned?()
  }
}
final class MeshMessengerProtectedScopeLease {
  private let cleanup: MeshMessengerProtectedCleanup
  init(_ url: URL, port: MeshMessengerProtectedScopePort) {
    let acquired = port.start(url)
    cleanup = MeshMessengerProtectedCleanup { if acquired { port.stop(url) } }
  }
  func close() { cleanup.run() }
}

/// Portable native IO core. URLs enter only through the native picker port;
/// caller frames contain opaque choices/handles, never arbitrary paths.
final class MeshMessengerProtectedFiles {
  enum Failure: Error { case unavailable, invalidFrame, staleResource, storage, integrity }
  private static let chunk = 65_536, small = 16_777_216, large = 536_870_912, backup = 16_796_864
  private static let backupName = "morse-backup.morsebackup", backupMIME = "application/octet-stream"
  private struct Identity: Equatable { let generation: UInt64; let account: String; let device: String }
  private struct Context: Equatable {
    let purpose: String
    var source = "", name = "", mime = "", size = 0
  }
  private struct Selection {
    let id: String; let url: URL; let name: String; let mime: String; let size: Int
    let attributes: stat
  }
  private final class Choice {
    let id = UUID().uuidString.lowercased(), identity: Identity, context: Context, urls: [URL], selected: [Selection]
    let expires = ProcessInfo.processInfo.systemUptime + 120
    let nativeSelection: MeshMessengerProtectedSelection?, requestId: String?
    var claimed = Set<String>()
    init(_ identity: Identity, _ context: Context, _ urls: [URL], _ selected: [Selection], nativeSelection: MeshMessengerProtectedSelection? = nil, requestId: String? = nil) {
      self.requestId = requestId; self.identity = identity; self.context = context; self.urls = urls; self.selected = selected; self.nativeSelection = nativeSelection
    }
  }
  private struct BackupRequest {
    let identity: Identity, context: Context, expected: String
    let expires = ProcessInfo.processInfo.systemUptime + 120
  }
  private var backupRequests: [String: BackupRequest] = [:]
  private class Resource {
    let id = UUID().uuidString.lowercased(), epoch: String, identity: Identity
    let expires = ProcessInfo.processInfo.systemUptime + 900
    let busy = NSLock()
    var closed = false
    private let release: MeshMessengerProtectedCleanup
    init(_ epoch: String, _ identity: Identity, cleanup: @escaping () -> Void = {}) {
      self.epoch = epoch; self.identity = identity; release = MeshMessengerProtectedCleanup(cleanup)
    }
    func invalidate() { closed = true }
    func cleanup() { release.run() }
  }
  private final class Preview: Resource {
    let url: URL
    init(_ epoch: String, _ identity: Identity, _ url: URL) {
      self.url = url; super.init(epoch, identity, cleanup: { try? FileManager.default.removeItem(at: url) })
    }
  }
  private final class Source: Resource {
    let selected: Selection, attributes: stat, context: Context?
    init(_ epoch: String, _ identity: Identity, _ selected: Selection, _ attributes: stat, _ lease: MeshMessengerProtectedScopeLease, context: Context? = nil) {
      self.selected = selected; self.attributes = attributes; self.context = context
      // Source descriptors never leave a coordinated accessor. The retained
      // native selection owns only metadata and its once-only scope lease.
      super.init(epoch, identity, cleanup: { lease.close() })
    }
  }
  private final class CoordinatedAccess {
    let epoch: String
    let cancel: MeshMessengerProtectedCleanup
    var callbacks = 0, finished = false
    init(_ coordinator: MeshMessengerProtectedCoordinator, expected: String) {
      epoch = expected
      cancel = MeshMessengerProtectedCleanup { coordinator.cancel() }
    }
  }
  private final class Export: Resource {
    let context: Context, destination: URL, url: URL, output: FileHandle
    let prefix: Data
    var key: Data?
    var contextHash = Data()
    var written = 0, count = 0, sealed = false
    init(_ epoch: String, _ identity: Identity, _ context: Context, _ destination: URL, _ url: URL, _ output: FileHandle) {
      self.context = context; self.destination = destination; self.url = url; self.output = output
      key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      prefix = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0.prefix(4)) }
      super.init(epoch, identity, cleanup: { try? output.close(); try? FileManager.default.removeItem(at: url) })
    }
    override func invalidate() {
      super.invalidate()
      if var value = key { value.resetBytes(in: value.startIndex..<value.endIndex) }
      key = nil
    }
  }

  private let gate: MeshMessengerAppLock, root: URL, documents: URL
  private let profile: (String) throws -> Data
  private let chooseNative: ((String, Bool) throws -> [URL]?)?
  private let nativeChooser: MeshMessengerProtectedChooser?
  private let output: (URL) throws -> MeshMessengerProtectedOutput
  private let securityScope: MeshMessengerProtectedScopePort
  // Production defaults to a fresh Foundation object for every native access.
  // Explicit native-only factories support deterministic provider/host ports.
  private let makeCoordinator: () -> MeshMessengerProtectedCoordinator
  // This map lock never spans core/profile/provider IO. Revoke closes admission
  // and drops keys immediately, then disposes busy descriptors off the caller.
  private let mutex = NSRecursiveLock()
  private let cleanup: DispatchQueue
  // Cancellation cannot queue behind descriptor cleanup waiting for the same
  // accessor to finish; native revoke must never wait for provider IO.
  private let cancellations = DispatchQueue(label: "app.morse.app-lock.files.cancel", attributes: .concurrent)
  private var accesses: [UUID: CoordinatedAccess] = [:]
  private var resources: [String: Resource] = [:], choices: [String: Choice] = [:]
  private var choosing = false
  private final class AsyncOperation {
    let id = UUID(), expected: String, selecting: Bool
    let backupRequestId: String?
    private let mutex = NSLock()
    private var callbackClaimed = false, finished = false
    private var token: MeshMessengerProtectedCleanup?
    let completion: (Result<Any, Error>) -> Void
    init(expected: String, selecting: Bool, backupRequestId: String? = nil, completion: @escaping (Result<Any, Error>) -> Void) {
      self.backupRequestId = backupRequestId; self.expected = expected; self.selecting = selecting; self.completion = completion
    }
    func install(_ value: MeshMessengerProtectedCleanup) {
      mutex.lock(); let alreadyFinished = finished
      if !alreadyFinished { token = value }; mutex.unlock()
      if alreadyFinished { value.run() }
    }
    func claimCallback() -> Bool {
      mutex.lock(); defer { mutex.unlock() }
      guard !finished, !callbackClaimed else { return false }; callbackClaimed = true; return true
    }
    func finish(_ value: Result<Any, Error>) -> Bool {
      mutex.lock(); guard !finished else { mutex.unlock(); return false }
      finished = true; let cleanup = token; token = nil; mutex.unlock()
      cleanup?.run(); completion(value); return true
    }
  }
  private var asyncOperations: [UUID: AsyncOperation] = [:]

  init(gate: MeshMessengerAppLock, root: URL, documents: URL,
       profile: @escaping (String) throws -> Data,
       choose: ((String, Bool) throws -> [URL]?)? = nil,
       nativeChooser: MeshMessengerProtectedChooser? = nil,
       output: ((URL) throws -> MeshMessengerProtectedOutput)? = nil,
       securityScope: MeshMessengerProtectedScopePort? = nil,
       makeCoordinator: (() -> MeshMessengerProtectedCoordinator)? = nil,
       cleanupQueue: DispatchQueue? = nil) {
    self.gate = gate; self.root = root; self.documents = documents
    self.profile = profile; self.chooseNative = choose; self.nativeChooser = nativeChooser; self.output = output ?? { try LocalOutput($0) }
    self.securityScope = securityScope ?? NativeProtectedScopePort()
    self.makeCoordinator = makeCoordinator ?? { MeshMessengerNativeProtectedCoordinator() }
    self.cleanup = cleanupQueue ?? DispatchQueue(label: "app.morse.app-lock.files.cleanup")
  }
  private func synchronized<T>(_ body: () throws -> T) rethrows -> T { mutex.lock(); defer { mutex.unlock() }; return try body() }
  private func worker() throws { guard !Thread.isMainThread else { throw Failure.unavailable } }
  private func coordinated<T>(_ url: URL, expected: String, writing: Bool = false,
                              _ body: (URL) throws -> T) throws -> T {
    try gate.requireEpoch(expected)
    let coordinator = makeCoordinator(), access = CoordinatedAccess(coordinator, expected: expected), token = UUID()
    do {
      try synchronized {
        guard accesses.count < 4 else { throw Failure.unavailable }
        accesses[token] = access
      }
    } catch { access.cancel.run(); throw error }
    defer {
      synchronized { access.finished = true; accesses.removeValue(forKey: token) }
      access.cancel.run()
    }
    var value: T?, callbackError: Error?
    do {
      try gate.requireEpoch(expected)
      try coordinator.access(url, writing: writing) { effective in
        try self.synchronized {
          guard !access.finished else { throw Failure.staleResource }
          access.callbacks += 1
          guard access.callbacks == 1 else { throw Failure.invalidFrame }
        }
        do {
          try self.gate.requireEpoch(expected)
          guard effective.isFileURL else { throw Failure.storage }
          value = try body(effective)
        } catch { callbackError = error; throw error }
      }
      if let callbackError { throw callbackError }
      guard synchronized({ !access.finished && access.callbacks == 1 }), let result = value else { throw Failure.storage }
      try gate.requireEpoch(expected)
      value = nil
      return result
    } catch {
      // Clear only the owned byte result when coordination/completion refuses.
      // The genuine body error keeps its original identity even if a native
      // coordination port also reports a disposition after that callback.
      if var bytes = value as? Data { value = nil; bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
      else { value = nil }
      throw callbackError ?? error
    }
  }
  private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
  private func u32(_ value: Int) -> Data {
    Data([UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
  }
  private func packet(_ fields: [String]) -> Data {
    var value = Data()
    for field in fields { let bytes = Data(field.utf8); value.append(u32(bytes.count)); value.append(bytes) }
    return value
  }
  private func decodeProfile(_ value: Data) throws -> [Data] {
    guard value.count >= 16 && value.count <= 36_134 else { throw Failure.invalidFrame }
    var cursor = 0
    func number() throws -> Int {
      guard cursor + 4 <= value.count else { throw Failure.invalidFrame }
      let number = value[cursor..<cursor+4].reduce(0) { ($0 << 8) | Int($1) }; cursor += 4; return number
    }
    var fields: [Data] = []
    for maximum in [64, 32, 16, 36_006] {
      let length = try number()
      guard length <= maximum && length <= value.count - cursor else { throw Failure.invalidFrame }
      fields.append(value.subdata(in: cursor..<cursor+length)); cursor += length
    }
    guard cursor == value.count && fields[1].count == 32 && fields[2].count == 16 else { throw Failure.invalidFrame }
    return fields
  }
  private func identity(_ expected: String, nativeProfile: ((String) throws -> Data)? = nil) throws -> Identity {
    try gate.requireEpoch(expected)
    var value = try (nativeProfile ?? profile)(expected); defer { value.resetBytes(in: value.startIndex..<value.endIndex) }
    var fields = try decodeProfile(value); defer { for index in fields.indices { fields[index].resetBytes(in: fields[index].startIndex..<fields[index].endIndex) } }
    let owner = Identity(generation: gate.accountGeneration, account: hex(fields[1]), device: hex(fields[2]))
    try gate.requireEpoch(expected); return owner
  }
  private func checked(_ text: String, _ keys: Set<String>) throws -> [String: Any] {
    guard text.utf8.count <= 16_384, let bytes = text.data(using: .utf8),
      let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      let version = value["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(),
      version.intValue == 1 && version.doubleValue == 1,
      Set(value.keys).isSubset(of: keys.union(["version"])) else { throw Failure.invalidFrame }
    return value
  }
  private func string(_ row: [String: Any], _ key: String, _ maximum: Int = 4096) throws -> String {
    guard let value = row[key] as? String, !value.isEmpty, value.utf8.count <= maximum,
      !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw Failure.invalidFrame }
    return value
  }
  private func number(_ row: [String: Any], _ key: String) throws -> Int {
    guard let value = row[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
      value.doubleValue.isFinite, value.doubleValue >= 0, value.doubleValue <= Double(Self.large),
      value.doubleValue.rounded(.towardZero) == value.doubleValue else { throw Failure.invalidFrame }
    return value.intValue
  }
  private func id(_ row: [String: Any], _ key: String = "handle") throws -> String {
    let value = try string(row, key, 36)
    guard UUID(uuidString: value)?.uuidString.lowercased() == value else { throw Failure.invalidFrame }; return value
  }
  private func json(_ row: [String: Any] = [:]) throws -> String {
    let value = row.merging(["version": 1]) { _, new in new }
    let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    return String(decoding: bytes, as: UTF8.self)
  }
  private func context(_ row: [String: Any]) throws -> Context {
    let purpose = try string(row, "purpose", 16)
    if purpose == "avatar" || purpose == "attachment" { return Context(purpose: purpose) }
    if purpose == "backup-source" || purpose == "backup-export" {
      guard row["sourceContext"] == nil, row["filename"] == nil, row["mimeType"] == nil, row["size"] == nil else { throw Failure.invalidFrame }
      return Context(purpose: purpose)
    }
    guard purpose == "export" else { throw Failure.invalidFrame }
    let name = try string(row, "filename", 255), mime = try string(row, "mimeType", 255), size = try number(row, "size")
    guard name != "." && name != ".." && !name.contains("/") && !name.contains("\\"),
      mime.range(of: #"\A[-a-zA-Z0-9.+]+/[-a-zA-Z0-9.+]+\z"#, options: .regularExpression) != nil,
      size > 0 else { throw Failure.invalidFrame }
    return Context(purpose: purpose, source: try string(row, "sourceContext"), name: name, mime: mime, size: size)
  }
  private func destination(_ context: Context) -> Bool { context.purpose == "export" || context.purpose == "backup-export" }
  private func backupPurpose(_ context: Context) -> Bool { context.purpose == "backup-source" || context.purpose == "backup-export" }
  private func requireBackupOwner(_ context: Context, _ expected: String) throws {
    guard backupPurpose(context) else { return }
    try gate.requireEpoch(expected)
    let presentation = gate.presentation()
    guard presentation.uncover, presentation.owner != nil else { throw Failure.unavailable }
  }
  private func backupSourceContext(_ row: [String: Any], prefix: String, expected: String) throws -> String {
    let source = try string(row, "sourceContext"), parts = source.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 3, parts[0] == prefix, parts[1] == expected,
      let counter = Int(parts[2]), counter > 0, counter <= 9_007_199_254_740_991, String(counter) == parts[2] else { throw Failure.invalidFrame }
    return source
  }
  private func backupExportContext(_ row: [String: Any], expected: String) throws -> Context {
    let name = try string(row, "filename", 255), mime = try string(row, "mimeType", 255), size = try number(row, "size")
    guard try string(row, "purpose", 16) == "backup-export", name == Self.backupName, mime == Self.backupMIME,
      size > 0, size <= Self.backup else { throw Failure.invalidFrame }
    return Context(purpose: "backup-export", source: try backupSourceContext(row, prefix: "backup-export", expected: expected), name: name, mime: mime, size: size)
  }
  private func backupRequest(_ row: [String: Any], context: Context, expected: String) throws -> String? {
    guard backupPurpose(context) else { guard row["requestId"] == nil else { throw Failure.invalidFrame }; return nil }
    let name = try id(row, "requestId"), owner = try identity(expected)
    guard synchronized({ backupRequests[name].map { $0.identity == owner && $0.context == context && $0.expected == expected && $0.expires >= ProcessInfo.processInfo.systemUptime } ?? false }) else { throw Failure.staleResource }
    return name
  }
  private func retainBackupChoice(_ choice: Choice) throws {
    if let name = choice.requestId {
      guard let request = backupRequests[name], request.identity == choice.identity, request.context == choice.context,
        request.expires >= ProcessInfo.processInfo.systemUptime else { throw Failure.staleResource }
      backupRequests.removeValue(forKey: name)
    }
    choices[choice.id] = choice
  }
  private func requireResource(_ value: Resource, _ expected: String) throws {
    try gate.requireEpoch(expected)
    let valid = synchronized { !value.closed && value.epoch == expected && value.identity.generation == gate.accountGeneration && value.expires >= ProcessInfo.processInfo.systemUptime }
    guard valid else { throw Failure.staleResource }
  }
  private func use<T: Resource, R>(_ name: String, _ expected: String, _ body: (T) throws -> R) throws -> R {
    try gate.requireEpoch(expected)
    guard let value = synchronized({ resources[name] as? T }), value.busy.try() else { throw Failure.staleResource }
    defer { value.busy.unlock() }
    try requireResource(value, expected); return try body(value)
  }
  private func remember(_ value: Resource) throws {
    try requireResource(value, value.epoch)
    try synchronized {
      guard !value.closed && resources.count < 4 else { throw Failure.unavailable }
      resources[value.id] = value
    }
    do { try requireResource(value, value.epoch) }
    catch { discard(value.id, value.epoch); throw error }
    cleanup.asyncAfter(deadline: .now() + max(0, value.expires - ProcessInfo.processInfo.systemUptime)) { [weak self] in
      self?.discard(value.id, value.epoch)
    }
  }
  private func discard(_ name: String, _ expected: String) {
    let value: Resource? = synchronized {
      guard let value = resources[name], value.epoch == expected else { return nil }
      resources.removeValue(forKey: name); value.invalidate(); return value
    }
    guard let value else { return }
    // Current IO may hold this lock while revoke runs. Cover/key revocation
    // never waits for it; cleanup waits only on its dedicated queue.
    cleanup.async { value.busy.lock(); defer { value.busy.unlock() }; value.cleanup() }
  }
  func revoke() {
    let revoked: ([Resource], [CoordinatedAccess]) = synchronized {
      // A prior gate callback can arrive after genuinely new native admission.
      // Observe current authority inside this map lock so fresh insertion cannot
      // cross the snapshot. Error/boot/restriction refusal preserves nothing.
      let current = gate.currentEpoch
      let admitted = (try? gate.requireEpoch(current)) != nil
      let values = resources.values.filter { !admitted || $0.epoch != current }
      for value in values { resources.removeValue(forKey: value.id); value.invalidate() }
      let obsolete = accesses.filter { !admitted || $0.value.epoch != current }
      for (token, access) in obsolete { accesses.removeValue(forKey: token); access.finished = true }
      choices = choices.filter { $0.value.identity.generation == gate.accountGeneration && $0.value.expires >= ProcessInfo.processInfo.systemUptime }
      return (values, Array(obsolete.values))
    }
    let oldOperations: [AsyncOperation] = synchronized {
      let current = gate.currentEpoch
      let admitted = (try? gate.requireEpoch(current)) != nil
      let old = asyncOperations.values.filter { !admitted || $0.expected != current }
      for operation in old { asyncOperations.removeValue(forKey: operation.id); if operation.selecting { choosing = false } }
      return old
    }
    for operation in oldOperations { _ = operation.finish(.failure(Failure.staleResource)) }
    for access in revoked.1 { cancellations.async { access.cancel.run() } }
    for value in revoked.0 { cleanup.async { value.busy.lock(); defer { value.busy.unlock() }; value.cleanup() } }
  }
  private func ensureRoot() throws {
    guard root.isFileURL && documents.isFileURL else { throw Failure.storage }
    if !FileManager.default.fileExists(atPath: root.path) {
      try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    var attributes = stat()
    guard lstat(root.path, &attributes) == 0 && attributes.st_mode & S_IFMT == S_IFDIR,
      chmod(root.path, 0o700) == 0 else { throw Failure.storage }
    var owned = root
    var values = URLResourceValues(); values.isExcludedFromBackup = true
    try owned.setResourceValues(values)
    guard try owned.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else { throw Failure.storage }
  }
  private func createOwned(_ url: URL) throws -> FileHandle {
    try ensureRoot()
    let descriptor = open(url.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
    guard descriptor >= 0 else { throw Failure.storage }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
#if os(iOS)
      try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
#endif
      var owned = url, values = URLResourceValues(); values.isExcludedFromBackup = true
      try owned.setResourceValues(values)
      guard try owned.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else { throw Failure.storage }
      return handle
    } catch { try? handle.close(); try? FileManager.default.removeItem(at: url); throw error }
  }
  func cleanOrphans() throws {
    try worker(); try ensureRoot()
    guard synchronized({ resources.isEmpty }) else { throw Failure.unavailable }
    let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
    guard files.count <= 10_000 else { throw Failure.storage }
    // Validate the full set before deleting anything. No nested directories or
    // symlinks are traversed, and the caller supplies no cleanup filename.
    for file in files {
      var value = stat()
      guard lstat(file.path, &value) == 0 && value.st_mode & S_IFMT == S_IFREG else { throw Failure.storage }
    }
    for file in files { try FileManager.default.removeItem(at: file) }
  }
  private func choiceJSON(_ value: Choice) throws -> String {
    if value.context.purpose != "attachment" && value.context.purpose != "backup-source" {
      var row: [String:Any] = ["choiceId":value.id]; if let request = value.requestId { row["requestId"] = request }; return try json(row)
    }
    let remaining = synchronized { value.selected.filter { !value.claimed.contains($0.id) } }
    var row: [String:Any] = ["choiceId": value.id, "files": remaining.map { ["selectionId": $0.id, "filename": $0.name, "mimeType": $0.mime, "size": $0.size] as [String: Any] }]
    if let request = value.requestId { row["requestId"] = request }; return try json(row)
  }
  private func exactChoice(_ name: String, _ expected: String, _ context: Context? = nil) throws -> Choice {
    let owner = try identity(expected)
    guard let value = synchronized({ choices[name] }), value.identity == owner,
      value.expires >= ProcessInfo.processInfo.systemUptime, context == nil || value.context == context else { throw Failure.staleResource }
    try value.nativeSelection?.context.validate(expected: expected)
    return value
  }
  private func choose(_ context: Context, _ expected: String, requestId: String? = nil) throws -> Choice? {
    let owner = try identity(expected)
    try requireBackupOwner(context, expected)
    try synchronized {
      choices = choices.filter { $0.value.identity.generation == owner.generation && $0.value.expires >= ProcessInfo.processInfo.systemUptime }
      guard !choosing && choices.count < 4, !backupPurpose(context) || !choices.values.contains(where: { $0.identity == owner && $0.context == context }) else { throw Failure.unavailable }; choosing = true
    }
    defer { synchronized { choosing = false; if let name = requestId { backupRequests.removeValue(forKey:name) } } }
    guard let chooseNative else { throw Failure.unavailable }
    guard let urls = try chooseNative(context.purpose, context.purpose == "attachment") else { return nil }
    guard owner.generation == gate.accountGeneration, !urls.isEmpty, urls.count <= (context.purpose == "attachment" ? 10 : 1),
      urls.allSatisfy({ $0.isFileURL }) else { throw Failure.staleResource }
    var selected: [Selection] = []
    if !destination(context) {
      for url in urls {
        let lease = MeshMessengerProtectedScopeLease(url, port: securityScope); defer { lease.close() }
        let value: stat = try coordinated(url, expected: expected) { effective in
          var attributes = stat()
          guard lstat(effective.path, &attributes) == 0 && attributes.st_mode & S_IFMT == S_IFREG,
            attributes.st_size > 0 && attributes.st_size <= (context.purpose == "backup-source" ? Self.backup : Self.large) else { throw Failure.storage }
          return attributes
        }
        let name = url.lastPathComponent
        guard !name.isEmpty && name.utf8.count <= 255 else { throw Failure.invalidFrame }
        selected.append(Selection(id: UUID().uuidString.lowercased(), url: url, name: name, mime: "application/octet-stream", size: Int(value.st_size), attributes: value))
      }
    }
    let value = Choice(owner, context, urls, selected, requestId: requestId)
    try synchronized {
      guard owner.generation == gate.accountGeneration && choices.count < 4 else { throw Failure.staleResource }
      try retainBackupChoice(value)
    }
    // This non-authority choice can survive picker inactivity. The enclosing
    // scope still rejects its old response; a fresh explicit action must claim it.
    return value
  }
  private func crypt(_ value: Export, _ index: Int, _ length: Int, _ bytes: Data, seal: Bool) throws -> Data {
    var key = try synchronized { () throws -> Data in
      guard !value.closed, let key = value.key else { throw Failure.staleResource }
      return key.withUnsafeBytes { Data($0) }
    }
    defer { key.resetBytes(in: key.startIndex..<key.endIndex) }
    var nonce = value.prefix
    let counter = UInt64(index)
    nonce.append(contentsOf: (0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> ($0 * 8)) })
    let iv = try AES.GCM.Nonce(data: nonce), aad = value.contextHash + u32(index) + u32(length)
    if seal {
      let box = try AES.GCM.seal(bytes, using: SymmetricKey(data: key), nonce: iv, authenticating: aad)
      return box.ciphertext + box.tag
    }
    guard bytes.count == length + 16 else { throw Failure.integrity }
    let box = try AES.GCM.SealedBox(nonce: iv, ciphertext: bytes.prefix(length), tag: bytes.suffix(16))
    do { return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad) }
    catch { throw Failure.integrity }
  }
  private func scan(_ value: Export, _ expected: String, _ consume: (inout Data) throws -> Void) throws {
    let descriptor = open(value.url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw Failure.integrity }
    let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); defer { try? input.close() }
    var attributes = stat()
    guard fstat(descriptor, &attributes) == 0 && attributes.st_mode & S_IFMT == S_IFREG &&
      attributes.st_size > 0 && attributes.st_size <= value.context.size + value.count * 28 else { throw Failure.integrity }
    func read(_ count: Int) throws -> Data {
      guard let bytes = try input.read(upToCount: count), bytes.count == count else { throw Failure.integrity }; return bytes
    }
    func integer() throws -> Int { try read(4).reduce(0) { ($0 << 8) | Int($1) } }
    var total = 0
    for index in 0..<value.count {
      try requireResource(value, expected)
      guard try integer() == index else { throw Failure.integrity }
      let length = try integer(), encryptedLength = try integer()
      guard length > 0 && length <= Self.chunk && encryptedLength == length + 16 && total + length <= value.context.size else { throw Failure.integrity }
      var ciphertext = try read(encryptedLength)
      var chunk: Data
      do { chunk = try crypt(value, index, length, ciphertext, seal: false) }
      catch { ciphertext.resetBytes(in: ciphertext.startIndex..<ciphertext.endIndex); throw error }
      ciphertext.resetBytes(in: ciphertext.startIndex..<ciphertext.endIndex)
      defer { chunk.resetBytes(in: chunk.startIndex..<chunk.endIndex) }
      guard chunk.count == length else { throw Failure.integrity }
      try requireResource(value, expected); try consume(&chunk); total += length
    }
    let trailing = try input.read(upToCount: 1) ?? Data()
    guard total == value.context.size && trailing.isEmpty else { throw Failure.integrity }
  }
  private func rememberAsync(expected: String, selecting: Bool, backupRequestId: String? = nil,
                             completion: @escaping (Result<Any, Error>) -> Void) throws -> AsyncOperation {
    try synchronized {
      guard asyncOperations.count < 4, !selecting || !choosing else { throw Failure.unavailable }
      let value = AsyncOperation(expected: expected, selecting: selecting, backupRequestId: backupRequestId, completion: completion)
      asyncOperations[value.id] = value
      if selecting { choosing = true }
      return value
    }
  }
  private func finishAsync(_ operation: AsyncOperation, _ result: Result<Any, Error>) {
    synchronized {
      if let name = operation.backupRequestId { backupRequests.removeValue(forKey:name) }
      if asyncOperations.removeValue(forKey: operation.id) != nil, operation.selecting { choosing = false }
    }
    _ = operation.finish(result)
  }
  private func nativeChoice(_ selection: MeshMessengerProtectedSelection, context: Context,
                            identity: Identity, expected: String, requestId: String? = nil) throws -> Choice {
    let urls: [URL], selected: [Selection]
    switch selection.payload {
    case .photo:
      guard context.purpose == "avatar" else { throw Failure.invalidFrame }
      urls = []; selected = [] // Only the actual NSItemProvider capability is retained.
    case .documents(let picked):
      guard context.purpose != "avatar", !picked.isEmpty, picked.count <= (context.purpose == "attachment" ? 10 : 1),
            picked.allSatisfy({ $0.isFileURL }) else { throw Failure.invalidFrame }
      try selection.context.validate(expected: expected)
      urls = picked
      if destination(context) { selected = [] }
      else {
        selected = try picked.map { url in
          let lease = MeshMessengerProtectedScopeLease(url, port: securityScope); defer { lease.close() }
          let attributes: stat = try coordinated(url, expected: expected) { effective in
            var value = stat()
            guard lstat(effective.path, &value) == 0 && value.st_mode & S_IFMT == S_IFREG,
                  value.st_size > 0 && value.st_size <= (context.purpose == "backup-source" ? Self.backup : Self.large) else { throw Failure.storage }
            return value
          }
          let name = url.lastPathComponent
          guard !name.isEmpty, name.utf8.count <= 255 else { throw Failure.invalidFrame }
          return Selection(id: UUID().uuidString.lowercased(), url: url, name: name,
            mime: "application/octet-stream", size: Int(attributes.st_size), attributes: attributes)
        }
      }
    }
    let value = Choice(identity, context, urls, selected, nativeSelection: selection, requestId: requestId)
    try synchronized {
      choices = choices.filter { $0.value.identity.generation == gate.accountGeneration && $0.value.expires >= ProcessInfo.processInfo.systemUptime }
      guard identity.generation == gate.accountGeneration, choices.count < 4 else { throw Failure.staleResource }
      try retainBackupChoice(value)
    }
    return value
  }
  private func canonicalAvatar(_ text: String) throws -> String {
    let prefix = "data:image/jpeg;base64,"
    guard text.utf8.count <= 12_288, text.hasPrefix(prefix),
          var bytes = Data(base64Encoded: String(text.dropFirst(prefix.count))), !bytes.isEmpty,
          bytes.base64EncodedString() == String(text.dropFirst(prefix.count)) else { throw Failure.invalidFrame }
    defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
    guard let source = CGImageSourceCreateWithData(bytes as CFData, nil),
          CGImageSourceGetType(source) as String? == UTType.jpeg.identifier,
          CGImageSourceGetCount(source) == 1,
          let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
          (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue == 160,
          (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue == 160 else { throw Failure.invalidFrame }
    return text
  }
  // Selection and provider loading are callback based. The UI thread never
  // waits for a synchronous document/photo chooser or an import completion.
  func dispatchAsync(_ operation: String, frame: String, bytes: Data, expected: String,
                     completion: @escaping (Result<Any, Error>) -> Void) {
    guard let nativeChooser, ["chooseSource", "chooseDestination", "importAvatar"].contains(operation) else {
      DispatchQueue.global(qos: .userInitiated).async { [self] in
        completion(Result { try dispatch(operation, frame: frame, bytes: bytes, expected: expected) })
      }
      return
    }
    DispatchQueue.global(qos: .userInitiated).async { [self] in
      do {
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        if operation == "importAvatar" {
          let choice: Choice = try gate.scoped(expected) {
            let row = try checked(frame, ["choiceId", "purpose"]), choice = try exactChoice(id(row, "choiceId"), expected)
            guard row["purpose"] == nil || row["purpose"] as? String == "avatar" else { throw Failure.invalidFrame }
            guard choice.context.purpose == "avatar", let selection = choice.nativeSelection,
                  case .photo = selection.payload else { throw Failure.invalidFrame }
            guard synchronized({ choices.removeValue(forKey: choice.id) != nil }) else { throw Failure.staleResource }
            return choice
          }
          guard let selection = choice.nativeSelection, case .photo(let photo) = selection.payload else { throw Failure.invalidFrame }
          let pending = try rememberAsync(expected: expected, selecting: false, completion: completion)
          let token = photo.importAvatar(expected: expected) { [self] result in
            guard pending.claimCallback() else { return }
            DispatchQueue.global(qos: .userInitiated).async { [self] in
            let fenced: Result<Any, Error> = Result {
              try gate.scoped(expected) {
                guard choice.identity.generation == gate.accountGeneration else { throw Failure.staleResource }
                try selection.context.validate(expected: expected)
                guard let uri = try result.get() else { return try json(["cancelled": true]) }
                return try json(["avatar": try canonicalAvatar(uri)])
              }
            }
            finishAsync(pending, fenced)
            }
          }
          pending.install(token)
        } else {
          let (context, owner, requestId) = try gate.scoped(expected) { () throws -> (Context, Identity, String?) in
            let row = try checked(frame, ["purpose", "sourceContext", "filename", "mimeType", "size", "requestId"]), context = try context(row)
            try requireBackupOwner(context, expected)
            guard (operation == "chooseDestination") == destination(context) else { throw Failure.invalidFrame }
            return (context, try identity(expected), try backupRequest(row, context: context, expected: expected))
          }
          let pending = try rememberAsync(expected: expected, selecting: true, backupRequestId: requestId, completion: completion)
          let token = nativeChooser.choose(purpose: context.purpose, multiple: context.purpose == "attachment", expected: expected) { [self] result in
            guard pending.claimCallback() else { return }
            DispatchQueue.global(qos: .userInitiated).async { [self] in
            let fenced: Result<Any, Error> = Result {
              guard owner.generation == gate.accountGeneration else { throw Failure.staleResource }
              guard let selection = try result.get() else {
                return try gate.scoped(expected) { try json(["cancelled": true]) }
              }
              let choice = try nativeChoice(selection, context: context, identity: owner, expected: expected, requestId: requestId)
              return try gate.scoped(expected) { try choiceJSON(choice) }
            }
            finishAsync(pending, fenced)
            }
          }
          pending.install(token)
        }
      } catch { completion(.failure(error)) }
    }
  }
  func dispatch(_ operation: String, frame: String, bytes: Data, expected: String) throws -> Any {
    try worker()
    if ["abortExport", "releasePreview", "closeSource", "discardPreviews"].contains(operation) {
      guard bytes.isEmpty else { throw Failure.invalidFrame }
      let row = try checked(frame, operation == "discardPreviews" ? [] : ["handle"])
      if operation == "discardPreviews" {
        let ids = synchronized { resources.values.filter { $0 is Preview && $0.epoch == expected }.map(\.id) }
        for name in ids { discard(name, expected) }
      } else {
        let name = try id(row)
        if let value = synchronized({ resources[name] }) {
          guard value.epoch == expected,
            (operation == "abortExport" && value is Export) || (operation == "releasePreview" && value is Preview) || (operation == "closeSource" && value is Source) else { throw Failure.staleResource }
          discard(name, expected)
        }
      }
      return try json()
    }
    if operation == "readSource" {
      return try gate.scopedData(expected) {
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["handle", "offset", "length"]), name = try id(row)
        return try use(name, expected) { (value: Source) in
          let offset = try number(row, "offset"), count = try number(row, "length")
          guard count > 0 && count <= Self.chunk && offset <= value.selected.size - count else { throw Failure.invalidFrame }
          return try coordinated(value.selected.url, expected: expected) { effective in
            try requireResource(value, expected)
            let descriptor = open(effective.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw Failure.storage }
            let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); defer { try? input.close() }
            func unchanged() throws {
              var current = stat(), path = stat()
              guard fstat(descriptor, &current) == 0 && lstat(effective.path, &path) == 0 && path.st_mode & S_IFMT == S_IFREG &&
                path.st_dev == current.st_dev && path.st_ino == current.st_ino &&
                current.st_dev == value.attributes.st_dev && current.st_ino == value.attributes.st_ino &&
                current.st_size == value.attributes.st_size && current.st_mtimespec.tv_sec == value.attributes.st_mtimespec.tv_sec &&
                current.st_mtimespec.tv_nsec == value.attributes.st_mtimespec.tv_nsec else { throw Failure.staleResource }
            }
            try unchanged(); try input.seek(toOffset: UInt64(offset))
            guard var result = try input.read(upToCount: count), result.count == count else { throw Failure.storage }
            do { try unchanged(); try requireResource(value, expected); return result }
            catch { result.resetBytes(in: result.startIndex..<result.endIndex); throw error }
          }
        }
      }
    }
    return try gate.scoped(expected) {
      switch operation {
      case "digest":
        _ = try checked(frame, [])
        guard bytes.count > 0 && bytes.count <= Self.small else { throw Failure.invalidFrame }
        return try json(["digest": hex(Data(SHA256.hash(data: bytes)))])
      case "pendingChoice", "chooseSource", "chooseDestination":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["purpose", "sourceContext", "filename", "mimeType", "size", "requestId"]), context = try context(row)
            try requireBackupOwner(context, expected)
        if operation == "pendingChoice" {
          let owner = try identity(expected)
          let matches = synchronized { () -> [Choice] in
            choices = choices.filter { $0.value.identity.generation == owner.generation && $0.value.expires >= ProcessInfo.processInfo.systemUptime }
            return choices.values.filter { $0.identity == owner && $0.context == context }
          }
          guard matches.count <= 1 else { throw Failure.staleResource }
          return try matches.first.map(choiceJSON) ?? json()
        }
        guard (operation == "chooseDestination") == destination(context) else { throw Failure.invalidFrame }
        return try choose(context, expected, requestId: backupRequest(row, context: context, expected: expected)).map(choiceJSON) ?? json(["cancelled": true])
      case "beginBackupChoice":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["purpose"]), context = try context(row)
        guard backupPurpose(context) else { throw Failure.invalidFrame }
        try requireBackupOwner(context, expected)
        let owner = try identity(expected), name = UUID().uuidString.lowercased()
        try synchronized {
          backupRequests = backupRequests.filter { $0.value.identity.generation == gate.accountGeneration && $0.value.expected == expected && $0.value.expires >= ProcessInfo.processInfo.systemUptime }
          guard backupRequests.count < 4 else { throw Failure.unavailable }
          backupRequests[name] = BackupRequest(identity:owner, context:context, expected:expected)
        }
        return try json(["requestId":name])
      case "discardBackupChoice":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["purpose", "choiceId", "requestId"]), context = try context(row)
        guard backupPurpose(context), (row["choiceId"] == nil) != (row["requestId"] == nil) else { throw Failure.invalidFrame }
        try requireBackupOwner(context, expected)
        let owner = try identity(expected)
        if row["requestId"] != nil {
          let name = try id(row, "requestId")
          let pending: [AsyncOperation] = try synchronized {
            if let request = backupRequests[name] { guard request.identity == owner, request.context == context else { throw Failure.staleResource } }
            let selected = choices.values.filter { $0.requestId == name }
            guard selected.allSatisfy({ $0.identity == owner && $0.context == context }) else { throw Failure.staleResource }
            backupRequests.removeValue(forKey: name)
            for choice in selected { choices.removeValue(forKey: choice.id) }
            let cancelled = asyncOperations.values.filter { $0.backupRequestId == name }
            for operation in cancelled {
              asyncOperations.removeValue(forKey: operation.id)
              if operation.selecting { choosing = false }
            }
            return cancelled
          }
          for operation in pending { _ = operation.finish(.failure(Failure.staleResource)) }
        } else {
          let name = try id(row, "choiceId")
          if synchronized({ choices[name] }) != nil {
            _ = try exactChoice(name, expected, context)
            synchronized { _ = choices.removeValue(forKey: name) }
          }
        }
        return try json()
      case "claimSource":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["choiceId", "selectionId", "size", "purpose", "sourceContext"]), choice = try exactChoice(id(row, "choiceId"), expected)
        var sourceContext: Context?
        if choice.context.purpose == "backup-source" {
          try requireBackupOwner(choice.context, expected)
          guard try string(row, "purpose", 16) == "backup-source" else { throw Failure.invalidFrame }
          sourceContext = Context(purpose: "backup-source", source: try backupSourceContext(row, prefix: "backup-import", expected: expected))
        } else {
          guard row["purpose"] == nil, row["sourceContext"] == nil else { throw Failure.invalidFrame }
        }
        let selectionID = try id(row, "selectionId")
        let declaredSize = try number(row, "size")
        let selected = try synchronized { () throws -> Selection in
          guard (choice.context.purpose == "attachment" || choice.context.purpose == "backup-source"),
            let selected = choice.selected.first(where: { $0.id == selectionID && !choice.claimed.contains($0.id) }),
            selected.size == declaredSize else { throw Failure.staleResource }
          // Reserve exactly once before any provider IO. A failed claim stays
          // consumed; a second action cannot race the same native selection.
          choice.claimed.insert(selected.id)
          if choice.claimed.count == choice.selected.count { choices.removeValue(forKey: choice.id) }
          return selected
        }
        let lease = MeshMessengerProtectedScopeLease(selected.url, port: securityScope)
        do {
          let attributes: stat = try coordinated(selected.url, expected: expected) { effective in
            let descriptor = open(effective.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw Failure.storage }
            let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); defer { try? input.close() }
            var attributes = stat()
            guard fstat(descriptor, &attributes) == 0 && attributes.st_mode & S_IFMT == S_IFREG && attributes.st_size == selected.size &&
              attributes.st_dev == selected.attributes.st_dev && attributes.st_ino == selected.attributes.st_ino &&
              attributes.st_mtimespec.tv_sec == selected.attributes.st_mtimespec.tv_sec &&
              attributes.st_mtimespec.tv_nsec == selected.attributes.st_mtimespec.tv_nsec else { throw Failure.staleResource }
            return attributes
          }
          let value = Source(expected, choice.identity, selected, attributes, lease, context: sourceContext)
          do { try remember(value) } catch { value.cleanup(); throw error }
          return try json(["handle": value.id, "size": selected.size])
        } catch { lease.close(); throw error }
      case "beginExport":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["purpose", "sourceContext", "filename", "mimeType", "size", "choiceId"])
        let isBackup = row["purpose"] as? String == "backup-export"
        let context = try isBackup ? backupExportContext(row, expected: expected) : self.context(row)
        try requireBackupOwner(context, expected)
        let choice = try exactChoice(id(row, "choiceId"), expected, isBackup ? Context(purpose: "backup-export") : context)
        guard destination(context), let directory = choice.urls.first else { throw Failure.invalidFrame }
        let removed = synchronized { choices.removeValue(forKey: choice.id) != nil }; guard removed else { throw Failure.staleResource }
        let url = root.appendingPathComponent(UUID().uuidString.lowercased()), file = try createOwned(url)
        let value = Export(expected, choice.identity, context, directory.appendingPathComponent(context.name), url, file)
        value.contextHash = Data(SHA256.hash(data: packet(["AL1-stage-v1", value.id, String(choice.identity.generation), choice.identity.account,
          choice.identity.device, expected, context.source, context.name, context.mime, String(context.size)])))
        do { try remember(value) } catch { value.invalidate(); value.cleanup(); throw error }
        return try json(["handle": value.id])
      case "writeExport":
        let row = try checked(frame, ["handle", "offset"])
        return try use(id(row), expected) { (value: Export) in
          guard try !value.sealed && value.count < 8192 && number(row, "offset") == value.written &&
            bytes.count > 0 && bytes.count <= Self.chunk && value.written + bytes.count <= value.context.size else { throw Failure.invalidFrame }
          do {
            var encrypted = try crypt(value, value.count, bytes.count, bytes, seal: true)
            defer { encrypted.resetBytes(in: encrypted.startIndex..<encrypted.endIndex) }
            try requireResource(value, expected)
            try value.output.write(contentsOf: u32(value.count) + u32(bytes.count) + u32(encrypted.count) + encrypted)
            try requireResource(value, expected); value.written += bytes.count; value.count += 1; return try json()
          } catch { discard(value.id, expected); throw error }
        }
      case "commitExport":
        guard bytes.isEmpty else { throw Failure.invalidFrame }
        let row = try checked(frame, ["handle"])
        return try use(id(row), expected) { (value: Export) in
          guard !value.sealed && value.written == value.context.size else { throw Failure.integrity }
          value.sealed = true
          defer {
            synchronized { resources.removeValue(forKey: value.id); value.invalidate() }
            value.cleanup()
          }
          try value.output.synchronize(); try value.output.close()
          try scan(value, expected) { chunk in chunk.resetBytes(in: chunk.startIndex..<chunk.endIndex) }
          try requireResource(value, expected)
          let directory = value.destination.deletingLastPathComponent(), lease = MeshMessengerProtectedScopeLease(directory, port: securityScope)
          defer { lease.close() }
          try coordinated(value.destination, expected: expected, writing: true) { effective in
            // Coordination may have waited across a revoke. Open only after
            // this callback's immutable expected epoch is still admitted.
            try requireResource(value, expected); try gate.publication(expected)
            let target = try output(effective); defer { try? target.close() }
            try requireResource(value, expected)
            try scan(value, expected) { chunk in try requireResource(value, expected); try gate.publication(expected); try target.write(chunk) }
            try requireResource(value, expected); try target.close(); try requireResource(value, expected)
          }
          return try json()
        }
      case "writePreview":
        let row = try checked(frame, ["key", "mimeType"]); _ = try string(row, "key", 256)
        let mime = try string(row, "mimeType", 255)
        guard ["image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "image/heic", "image/heif"].contains(mime),
          bytes.count > 0 && bytes.count <= Self.small else { throw Failure.invalidFrame }
        let value = Preview(expected, try identity(expected), root.appendingPathComponent(UUID().uuidString.lowercased()))
        // Hold the descriptor lifetime lock before registration so revoke's
        // deferred cleanup cannot run before this operation creates its file.
        value.busy.lock(); defer { value.busy.unlock() }
        try remember(value)
        do {
          let file = try createOwned(value.url); defer { try? file.close() }
          try requireResource(value, expected); try file.write(contentsOf: bytes); try requireResource(value, expected)
          return try json(["handle": value.id, "uri": value.url.absoluteString])
        } catch { discard(value.id, expected); throw error }
      default: throw Failure.invalidFrame
      }
    }
  }
  func requireNativeDocuments(_ value: URL) throws {
    guard value.isFileURL, value.standardizedFileURL == documents.standardizedFileURL else { throw Failure.unavailable }
  }
  private func legacy(_ supplied: Data, _ kind: String, _ expected: String, nativeProfile: ((String) throws -> Data)? = nil) throws -> URL {
    guard ["read-state", "notification-state", "receipt-marks", "read-receipts", "notification-preview"].contains(kind) else { throw Failure.invalidFrame }
    var actual = try (nativeProfile ?? profile)(expected); defer { actual.resetBytes(in: actual.startIndex..<actual.endIndex) }
    guard actual == supplied else { throw Failure.staleResource }
    var fields = try decodeProfile(supplied); defer { for index in fields.indices { fields[index].resetBytes(in: fields[index].startIndex..<fields[index].endIndex) } }
    let suffix = ["read-state", "notification-state", "receipt-marks"].contains(kind) ? ".json" : ""
    return documents.appendingPathComponent(kind + "-" + hex(fields[1]) + suffix)
  }
  func readLegacy(_ profile: Data, kind: String, expected: String, nativeProfile: ((String) throws -> Data)? = nil) throws -> String? {
    try worker()
    return try gate.scoped(expected) {
      let url = try legacy(profile, kind, expected, nativeProfile: nativeProfile)
      let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      if descriptor < 0 && errno == ENOENT { return nil }
      guard descriptor >= 0 else { throw Failure.storage }
      let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); defer { try? handle.close() }
      var attributes = stat()
      guard fstat(descriptor, &attributes) == 0 && attributes.st_mode & S_IFMT == S_IFREG &&
        attributes.st_size <= 1_048_576 else { throw Failure.storage }
      try gate.publication(expected)
      guard var bytes = try handle.read(upToCount: Int(attributes.st_size)), bytes.count == attributes.st_size,
        let text = String(data: bytes, encoding: .utf8) else { throw Failure.storage }
      defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
      try gate.requireEpoch(expected); return text
    }
  }
  func removeLegacy(_ profile: Data, kind: String, expected: String, nativeProfile: ((String) throws -> Data)? = nil) throws {
    try worker()
    try gate.scoped(expected) {
      let url = try legacy(profile, kind, expected, nativeProfile: nativeProfile)
      try gate.publication(expected)
      if unlink(url.path) != 0 && errno != ENOENT { throw Failure.storage }
    }
  }
  func forgetLegacy(_ account: String, expected: String, nativeProfile: ((String) throws -> Data)? = nil) throws {
    try worker()
    try gate.scoped(expected) {
      let owner = try identity(expected, nativeProfile: nativeProfile); guard account == owner.account else { throw Failure.staleResource }
      var value = try (nativeProfile ?? profile)(expected); defer { value.resetBytes(in: value.startIndex..<value.endIndex) }
      try removeLegacy(value, kind: "read-receipts", expected: expected, nativeProfile: nativeProfile)
      try removeLegacy(value, kind: "notification-preview", expected: expected, nativeProfile: nativeProfile)
    }
  }
}

private final class LocalOutput: MeshMessengerProtectedOutput {
  private let handle: FileHandle
  private var closed = false
  init(_ url: URL) throws {
    guard url.isFileURL else { throw MeshMessengerProtectedFiles.Failure.storage }
    let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
    guard descriptor >= 0 else { throw MeshMessengerProtectedFiles.Failure.storage }
    handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
  }
  func write(_ bytes: Data) throws { guard !closed else { throw MeshMessengerProtectedFiles.Failure.storage }; try handle.write(contentsOf: bytes) }
  func close() throws { if !closed { closed = true; try handle.synchronize(); try handle.close() } }
}

#if canImport(UIKit)
import UIKit
import PhotosUI

private func protectedOnMain(_ body: @escaping @MainActor () -> Void) {
  if Thread.isMainThread { MainActor.assumeIsolated { body() } }
  else { DispatchQueue.main.async { body() } }
}

// The resolver is native-only and must use the exact current root/owner lease.
// It is never constructed from a JS scene, URI, view tag or factory handle.
final class MeshMessengerNativeProtectedChooser: MeshMessengerProtectedChooser {
  typealias Owner = @MainActor (String) throws -> (UIViewController, MeshMessengerProtectedSelectionContext)
  private let gate: MeshMessengerAppLock
  private let owner: Owner
  @MainActor private var pickers: [UUID: NativeSelectionRequest] = [:]
  @MainActor private var imports: [UUID: NativePhotoImport] = [:]
  init(gate: MeshMessengerAppLock, owner: @escaping Owner) { self.gate = gate; self.owner = owner }
  func choose(purpose: String, multiple: Bool, expected: String,
              completion: @escaping (Result<MeshMessengerProtectedSelection?, Error>) -> Void) -> MeshMessengerProtectedCleanup {
    let token = UUID()
    protectedOnMain { [weak self] in
      guard let self else { completion(.failure(MeshMessengerProtectedFiles.Failure.unavailable)); return }
      do {
        guard self.pickers.isEmpty else { throw MeshMessengerProtectedFiles.Failure.unavailable }
        let (presenter, context) = try self.owner(expected)
        try context.validate(expected: expected)
        let value = NativeSelectionRequest(purpose: purpose, multiple: multiple, expected: expected,
          context: context, chooser: self) { [weak self] result in
          self?.pickers.removeValue(forKey: token); completion(result)
        }
        self.pickers[token] = value
        value.present(from: presenter)
      } catch { completion(.failure(error)) }
    }
    return MeshMessengerProtectedCleanup { [weak self] in
      protectedOnMain { self?.pickers[token]?.cancel() }
    }
  }
  fileprivate func importPhoto(_ provider: NSItemProvider, type: String,
                               context: MeshMessengerProtectedSelectionContext, expected: String,
                               completion: @escaping (Result<String?, Error>) -> Void) -> MeshMessengerProtectedCleanup {
    let token = UUID()
    protectedOnMain { [weak self] in
      guard let self else { completion(.failure(MeshMessengerProtectedFiles.Failure.unavailable)); return }
      do {
        guard self.imports.count < 4, provider.hasItemConformingToTypeIdentifier(type),
              UTType(type)?.conforms(to: .image) == true else { throw MeshMessengerProtectedFiles.Failure.unavailable }
        try context.validate(expected: expected)
        let (presenter, _) = try self.owner(expected)
        let value = NativePhotoImport(provider: provider, type: type, gate: self.gate,
          context: context, expected: expected, presenter: presenter) { [weak self] result in
          self?.imports.removeValue(forKey: token); completion(result)
        }
        self.imports[token] = value; value.start()
      } catch { completion(.failure(error)) }
    }
    return MeshMessengerProtectedCleanup { [weak self] in
      protectedOnMain { self?.imports[token]?.cancel() }
    }
  }
}

@MainActor private final class NativeSelectionRequest: NSObject, UIDocumentPickerDelegate, PHPickerViewControllerDelegate {
  private let purpose: String, multiple: Bool, expected: String
  private let context: MeshMessengerProtectedSelectionContext
  private weak var chooser: MeshMessengerNativeProtectedChooser?
  private let completion: (Result<MeshMessengerProtectedSelection?, Error>) -> Void
  private var controller: UIViewController?
  private var finished = false
  init(purpose: String, multiple: Bool, expected: String, context: MeshMessengerProtectedSelectionContext,
       chooser: MeshMessengerNativeProtectedChooser,
       completion: @escaping (Result<MeshMessengerProtectedSelection?, Error>) -> Void) {
    self.purpose = purpose; self.multiple = multiple; self.expected = expected
    self.context = context; self.chooser = chooser; self.completion = completion
  }
  func present(from presenter: UIViewController) {
    do {
      try context.validate(expected: expected)
      guard presenter.viewIfLoaded?.window != nil, presenter.presentedViewController == nil,
            !presenter.isBeingPresented, !presenter.isBeingDismissed, presenter.transitionCoordinator == nil else { throw MeshMessengerProtectedFiles.Failure.unavailable }
      if purpose == "avatar" {
        var config = PHPickerConfiguration(); config.filter = .images; config.selectionLimit = 1
        config.preferredAssetRepresentationMode = .current
        let picker = PHPickerViewController(configuration: config); picker.delegate = self
        controller = picker; presenter.present(picker, animated: true)
      } else {
        guard ["attachment", "export", "backup-source", "backup-export"].contains(purpose) else { throw MeshMessengerProtectedFiles.Failure.invalidFrame }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: (purpose == "export" || purpose == "backup-export") ? [.folder] : [.data], asCopy: false)
        picker.allowsMultipleSelection = purpose == "attachment" && multiple; picker.delegate = self
        controller = picker; presenter.present(picker, animated: true)
      }
    } catch { finish(.failure(error)) }
  }
  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { finish(.success(nil)) }
  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    finish(.success(MeshMessengerProtectedSelection(.documents(urls), context: context)))
  }
  func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
    guard results.count <= 1 else { finish(.failure(MeshMessengerProtectedFiles.Failure.unavailable)); return }
    guard let result = results.first else { finish(.success(nil)); return }
    // Selection records only the actual provider and a registered image type.
    // Loading, temporary file access and image decoding happen only on import.
    guard let chooser, let type = result.itemProvider.registeredTypeIdentifiers.first(where: {
      UTType($0)?.conforms(to: .image) == true && result.itemProvider.hasItemConformingToTypeIdentifier($0)
    }) else { finish(.failure(MeshMessengerProtectedFiles.Failure.unavailable)); return }
    let photo = NativeSelectedPhoto(provider: result.itemProvider, type: type, context: context, chooser: chooser)
    finish(.success(MeshMessengerProtectedSelection(.photo(photo), context: context)))
  }
  func cancel() { finish(.failure(MeshMessengerProtectedFiles.Failure.staleResource)) }
  private func finish(_ result: Result<MeshMessengerProtectedSelection?, Error>) {
    guard !finished else { return }; finished = true
    let fenced = Result<MeshMessengerProtectedSelection?, Error> {
      try context.validate(expected: expected); return try result.get()
    }
    let current = controller; controller = nil
    if let current { current.dismiss(animated: false) { self.completion(fenced) } }
    else { completion(fenced) }
  }
}

private final class NativeSelectedPhoto: MeshMessengerProtectedPhoto {
  private let provider: NSItemProvider, type: String
  private let context: MeshMessengerProtectedSelectionContext
  private weak var chooser: MeshMessengerNativeProtectedChooser?
  init(provider: NSItemProvider, type: String, context: MeshMessengerProtectedSelectionContext,
       chooser: MeshMessengerNativeProtectedChooser) {
    self.provider = provider; self.type = type; self.context = context; self.chooser = chooser
  }
  func importAvatar(expected: String, completion: @escaping (Result<String?, Error>) -> Void) -> MeshMessengerProtectedCleanup {
    guard let chooser else {
      completion(.failure(MeshMessengerProtectedFiles.Failure.unavailable))
      return MeshMessengerProtectedCleanup {} // No resource was started or retained.
    }
    return chooser.importPhoto(provider, type: type, context: context, expected: expected, completion: completion)
  }
}

// Provider/UIKit objects are MainActor-owned; cancellation and callback state
// are mutex-owned. The gate and native context expose thread-safe validation.
private final class NativePhotoImport: @unchecked Sendable {
  private static let maximum = 20 * 1024 * 1024
  @MainActor private let provider: NSItemProvider
  private let type: String, expected: String
  private let gate: MeshMessengerAppLock, context: MeshMessengerProtectedSelectionContext
  @MainActor private weak var presenter: UIViewController?
  @MainActor private var editor: NativeAvatarEditor?
  private let completion: @MainActor (Result<String?, Error>) -> Void
  private let mutex = NSLock()
  private var finished = false, callbackReceived = false
  private var progress: Progress?
  private var coordinator: MeshMessengerNativeProtectedCoordinator?
  @MainActor init(provider: NSItemProvider, type: String, gate: MeshMessengerAppLock,
                  context: MeshMessengerProtectedSelectionContext, expected: String, presenter: UIViewController,
                  completion: @escaping @MainActor (Result<String?, Error>) -> Void) {
    self.provider = provider; self.type = type; self.gate = gate; self.context = context
    self.expected = expected; self.presenter = presenter; self.completion = completion
  }
  @MainActor func start() {
    do { try context.validate(expected: expected); try gate.requireEpoch(expected) }
    catch { finish(.failure(error)); return }
    let value = provider.loadFileRepresentation(forTypeIdentifier: type) { [weak self] url, error in self?.receive(url, error) }
    mutex.lock(); let cancelled = finished
    if !cancelled { progress = value }; mutex.unlock()
    if cancelled { value.cancel() }
    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 120) { [weak self] in self?.cancel() }
  }
  private func requireCurrent() throws {
    mutex.lock(); let closed = finished; mutex.unlock()
    guard !closed else { throw MeshMessengerProtectedFiles.Failure.staleResource }
    try gate.requireEpoch(expected); try context.validate(expected: expected)
  }
  private func receive(_ url: URL?, _ error: Error?) {
    mutex.lock()
    guard !finished, !callbackReceived else { mutex.unlock(); return }
    callbackReceived = true; mutex.unlock()
    do {
      try requireCurrent()
      if let error { throw error }
      // An NSItemProvider temporary URL is usable only in this callback. Never
      // dispatch its read to a later task or retain the URL for a fresh epoch.
      guard !Thread.isMainThread, let url, url.isFileURL else { throw MeshMessengerProtectedFiles.Failure.unavailable }
      let image = try readImageWithinCallback(url)
      try requireCurrent()
      protectedOnMain { [weak self] in
        guard let self else { return }
        do {
          try self.requireCurrent()
          guard let presenter = self.presenter, presenter.viewIfLoaded?.window != nil,
                presenter.presentedViewController == nil, !presenter.isBeingPresented,
                !presenter.isBeingDismissed, presenter.transitionCoordinator == nil else { throw MeshMessengerProtectedFiles.Failure.unavailable }
          let editor = NativeAvatarEditor(image: image, check: { [weak self] in
            guard let self else { throw MeshMessengerProtectedFiles.Failure.staleResource }
            try self.requireCurrent()
          }) { [weak self] result in self?.finish(result) }
          self.editor = editor
          let navigation = UINavigationController(rootViewController: editor); navigation.modalPresentationStyle = .fullScreen
          presenter.present(navigation, animated: true)
        } catch { self.finish(.failure(error)) }
      }
    } catch { finish(.failure(error)) }
  }
  private func readImageWithinCallback(_ url: URL) throws -> UIImage {
    try requireCurrent()
    var original = stat()
    guard lstat(url.path, &original) == 0, original.st_mode & S_IFMT == S_IFREG,
          original.st_size > 0, original.st_size <= Self.maximum else { throw MeshMessengerProtectedFiles.Failure.storage }
    let lease = MeshMessengerProtectedScopeLease(url, port: NativeProtectedScopePort()); defer { lease.close() }
    let access = MeshMessengerNativeProtectedCoordinator()
    mutex.lock(); guard !finished else { mutex.unlock(); throw MeshMessengerProtectedFiles.Failure.staleResource }
    coordinator = access; mutex.unlock()
    defer { access.cancel(); mutex.lock(); coordinator = nil; mutex.unlock() }
    var result: UIImage?
    try access.read(url) { effective in
      try requireCurrent()
      let descriptor = open(effective.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else { throw MeshMessengerProtectedFiles.Failure.storage }
      let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true); defer { try? handle.close() }
      func unchanged() throws {
        var current = stat(), path = stat()
        guard fstat(descriptor, &current) == 0, lstat(effective.path, &path) == 0,
              path.st_mode & S_IFMT == S_IFREG, current.st_dev == path.st_dev, current.st_ino == path.st_ino,
              current.st_dev == original.st_dev, current.st_ino == original.st_ino,
              current.st_size == original.st_size, current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec,
              current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec else { throw MeshMessengerProtectedFiles.Failure.staleResource }
      }
      try unchanged()
      var bytes = Data(); defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
      while bytes.count < original.st_size {
        try requireCurrent()
        guard let chunk = try handle.read(upToCount: min(65_536, Int(original.st_size) - bytes.count)), !chunk.isEmpty else { throw MeshMessengerProtectedFiles.Failure.storage }
        bytes.append(chunk)
      }
      try requireCurrent(); try unchanged()
      guard (try handle.read(upToCount: 1) ?? Data()).isEmpty,
            let source = CGImageSourceCreateWithData(bytes as CFData, nil), CGImageSourceGetCount(source) <= 128,
            let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
            let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
            let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
            width > 0, height > 0, width <= 32_768, height <= 32_768, width * height <= 64_000_000 else { throw MeshMessengerProtectedFiles.Failure.invalidFrame }
      try requireCurrent()
      let options = [kCGImageSourceCreateThumbnailFromImageAlways: true,
        kCGImageSourceThumbnailMaxPixelSize: 2048, kCGImageSourceCreateThumbnailWithTransform: true,
        kCGImageSourceShouldCacheImmediately: true] as CFDictionary
      guard let thumbnail = CGImageSourceCreateThumbnailAtIndex(source, 0, options) else { throw MeshMessengerProtectedFiles.Failure.invalidFrame }
      try requireCurrent(); result = UIImage(cgImage: thumbnail)
    }
    guard let result else { throw MeshMessengerProtectedFiles.Failure.unavailable }; return result
  }
  func cancel() { finish(.failure(MeshMessengerProtectedFiles.Failure.staleResource)) }
  private func finish(_ result: Result<String?, Error>) {
    mutex.lock(); guard !finished else { mutex.unlock(); return }
    finished = true; let oldProgress = progress, oldCoordinator = coordinator
    progress = nil; coordinator = nil; mutex.unlock()
    oldProgress?.cancel(); oldCoordinator?.cancel()
    protectedOnMain { [self] in
      editor?.discard(); editor = nil
      let fenced = Result<String?, Error> { try gate.requireEpoch(expected); try context.validate(expected: expected); return try result.get() }
      completion(fenced)
    }
  }
}

@MainActor private final class NativeAvatarEditor: UIViewController, UIScrollViewDelegate {
  private var image: UIImage?
  private let scroll = UIScrollView(), imageView = UIImageView()
  private let check: () throws -> Void, result: (Result<String?, Error>) -> Void
  private var configuredSize = CGSize.zero, finished = false
  init(image: UIImage, check: @escaping () throws -> Void, result: @escaping (Result<String?, Error>) -> Void) {
    self.image = image; self.check = check; self.result = result; super.init(nibName: nil, bundle: nil)
  }
  @available(*, unavailable) required init?(coder: NSCoder) { fatalError("init(coder:) unavailable") }
  override func viewDidLoad() {
    super.viewDidLoad(); title = NSLocalizedString("morse_edit_photo", value: "Edit photo", comment: "Square avatar editor")
    view.backgroundColor = .black
    navigationItem.leftBarButtonItem = UIBarButtonItem(systemItem: .cancel, primaryAction: UIAction { [weak self] _ in self?.complete(.success(nil)) })
    navigationItem.rightBarButtonItem = UIBarButtonItem(title: NSLocalizedString("morse_use_photo", value: "Use photo", comment: "Confirm square avatar"), primaryAction: UIAction { [weak self] _ in self?.approve() })
    scroll.translatesAutoresizingMaskIntoConstraints = false; scroll.delegate = self
    scroll.clipsToBounds = true; scroll.contentInsetAdjustmentBehavior = .never; scroll.bounces = false
    imageView.image = image; scroll.addSubview(imageView); view.addSubview(scroll)
    let width = scroll.widthAnchor.constraint(equalTo: view.safeAreaLayoutGuide.widthAnchor, constant: -32); width.priority = .defaultHigh
    NSLayoutConstraint.activate([width, scroll.widthAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.heightAnchor, constant: -32),
      scroll.heightAnchor.constraint(equalTo: scroll.widthAnchor), scroll.centerXAnchor.constraint(equalTo: view.centerXAnchor),
      scroll.centerYAnchor.constraint(equalTo: view.safeAreaLayoutGuide.centerYAnchor)])
  }
  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    guard let image, scroll.bounds.width > 0, scroll.bounds.size != configuredSize else { return }
    configuredSize = scroll.bounds.size; scroll.zoomScale = 1
    imageView.frame = CGRect(origin: .zero, size: image.size); scroll.contentSize = image.size
    let scale = max(scroll.bounds.width / image.size.width, scroll.bounds.height / image.size.height)
    scroll.minimumZoomScale = scale; scroll.maximumZoomScale = scale * 8; scroll.zoomScale = scale
    scroll.contentOffset = CGPoint(x: max(0, (image.size.width * scale - scroll.bounds.width) / 2), y: max(0, (image.size.height * scale - scroll.bounds.height) / 2))
  }
  func viewForZooming(in scrollView: UIScrollView) -> UIView? { imageView }
  private func approve() {
    do {
      try check()
      guard let image, scroll.bounds.width > 0 else { throw MeshMessengerProtectedFiles.Failure.unavailable }
      let format = UIGraphicsImageRendererFormat(); format.scale = 1; format.opaque = true
      let factor = 160 / scroll.bounds.width
      let square = UIGraphicsImageRenderer(size: CGSize(width: 160, height: 160), format: format).image { _ in
        UIColor.black.setFill(); UIRectFill(CGRect(x: 0, y: 0, width: 160, height: 160))
        image.draw(in: CGRect(x: -scroll.contentOffset.x * factor, y: -scroll.contentOffset.y * factor,
          width: image.size.width * scroll.zoomScale * factor, height: image.size.height * scroll.zoomScale * factor))
      }
      for quality in [0.7, 0.45, 0.2] {
        try check()
        guard var bytes = square.jpegData(compressionQuality: quality) else { continue }
        let uri = "data:image/jpeg;base64," + bytes.base64EncodedString(); bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
        if uri.utf8.count <= 12_288 { try check(); complete(.success(uri)); return }
      }
      throw MeshMessengerProtectedFiles.Failure.invalidFrame
    } catch { complete(.failure(error)) }
  }
  private func complete(_ value: Result<String?, Error>) {
    guard !finished else { return }; finished = true; result(value)
  }
  func discard() {
    finished = true; image = nil; imageView.image = nil
    if let navigationController { navigationController.dismiss(animated: false) }
    else { dismiss(animated: false) }
  }
}
#endif
