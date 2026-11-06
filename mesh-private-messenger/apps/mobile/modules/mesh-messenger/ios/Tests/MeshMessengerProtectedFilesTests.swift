import Foundation
import CryptoKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

private enum CheckFailure: Error { case assertion(String), injected }
private func check(_ value: @autoclosure () throws -> Bool, _ why: String) throws {
  if try !value() { throw CheckFailure.assertion(why) }
}
private func refuses(_ body: () throws -> Void) throws {
  do { try body() }
  catch CheckFailure.assertion(let why) { throw CheckFailure.assertion(why) }
  catch { return }
  throw CheckFailure.assertion("expected refusal")
}
private final class Policy: MeshMessengerAppLockPolicyPort {
  let value = MeshMessengerAppLockPolicy.Record(install: UUID().uuidString.lowercased(), sequence: 0, policy: "disabled")
  func load() throws -> MeshMessengerAppLockPolicy.Record { value }
  func transition(previous: MeshMessengerAppLockPolicy.Record, desired: String) throws -> MeshMessengerAppLockPolicy.Record { throw CheckFailure.injected }
}
private final class Platform: MeshMessengerAppLockPlatform {
  var monotonicTime: TimeInterval { ProcessInfo.processInfo.systemUptime }
  var canAuthenticate = false
  func present(requestID: String, ownerSceneID: String, completion: @escaping (Bool) -> Void) { completion(false) }
  func cancel(requestID: String) {}
  func render(state: [String: Any], uncover: Bool) {}
  func copyText(_ text: String) {}
}
private func packet(_ fields: [Data]) -> Data {
  func u32(_ value: Int) -> Data {
    Data([UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
  }
  var result = Data()
  for field in fields { result.append(u32(field.count)); result.append(field) }
  return result
}
private final class Output: MeshMessengerProtectedOutput {
  let handle: FileHandle
  let afterWrite: () throws -> Void
  let onClose: () -> Void
  init(_ url: URL, afterWrite: @escaping () throws -> Void, onClose: @escaping () -> Void = {}) throws {
    try check(!FileManager.default.fileExists(atPath: url.path), "output must not overwrite")
    try check(FileManager.default.createFile(atPath: url.path, contents: nil), "create fixture output")
    handle = try FileHandle(forWritingTo: url); self.afterWrite = afterWrite; self.onClose = onClose
  }
  func write(_ bytes: Data) throws { try handle.write(contentsOf: bytes); try afterWrite() }
  func close() throws { try handle.close(); onClose() }
}
private final class Fixture {
  let base: URL, root: URL, documents: URL, destination: URL
  let gate: MeshMessengerAppLock
  let profile: Data
  var selection: [URL]?
  var beforeChoice: (() throws -> Void)?
  var afterOutputWrite: (() throws -> Void)?
  var pickerCalls = 0
  var outputOpens = 0
  var beforeOutputOpen: (() -> Void)?
  var afterOutputClose: (() -> Void)?
  var beforeRevoke: (() -> Void)?
  var files: MeshMessengerProtectedFiles!
  init(securityScope: MeshMessengerProtectedScopePort? = nil,
       makeCoordinator: (() -> MeshMessengerProtectedCoordinator)? = nil,
       cleanupQueue: DispatchQueue? = nil,
       profile: Data = packet([Data("Owned fixture".utf8), Data(repeating: 1, count: 32), Data(repeating: 2, count: 16), Data()])) throws {
    self.profile = profile
    base = FileManager.default.temporaryDirectory.appendingPathComponent("morse-al1-owned-" + UUID().uuidString, isDirectory: true)
    root = base.appendingPathComponent("protected", isDirectory: true)
    documents = base.appendingPathComponent("documents", isDirectory: true)
    destination = base.appendingPathComponent("destination", isDirectory: true)
    for url in [root, documents, destination] { try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true) }
    let policy = Policy()
    gate = MeshMessengerAppLock(platform: Platform(), makeStore: { policy }, cleanStaging: {}, drainNotices: {})
    try gate.bootstrap(); gate.foreground(ownerSceneID: "owned-scene", active: true)
    files = MeshMessengerProtectedFiles(gate: gate, root: root, documents: documents,
      profile: { [unowned self] expected in try self.gate.requireEpoch(expected); return self.profile },
      choose: { [unowned self] _, _ in self.pickerCalls += 1; try self.beforeChoice?(); return self.selection },
      output: { [unowned self] url in
        self.beforeOutputOpen?(); self.outputOpens += 1
        return try Output(url, afterWrite: { [unowned self] in try self.afterOutputWrite?() },
          onClose: { [unowned self] in self.afterOutputClose?() })
      }, securityScope: securityScope, makeCoordinator: makeCoordinator, cleanupQueue: cleanupQueue)
    _ = gate.onRevoke { [weak self] in
      guard let self else { return }; self.beforeRevoke?(); self.files.revoke()
    }
  }
  deinit { try? FileManager.default.removeItem(at: base) }
  func frame(_ values: [String: Any]) throws -> String {
    let bytes = try JSONSerialization.data(withJSONObject: values.merging(["version": 1]) { _, new in new }, options: [.sortedKeys])
    return String(decoding: bytes, as: UTF8.self)
  }
  func call(_ operation: String, _ values: [String: Any] = [:], bytes: Data = Data(), expected: String? = nil) throws -> Any {
    var values = values
    if ["chooseSource","chooseDestination"].contains(operation), let purpose = values["purpose"] as? String,
      ["backup-source","backup-export"].contains(purpose), values["requestId"] == nil {
      guard let raw = try files.dispatch("beginBackupChoice",frame:frame(["purpose":purpose]),bytes:Data(),expected:expected ?? gate.currentEpoch) as? String,
        let row = try JSONSerialization.jsonObject(with:Data(raw.utf8)) as? [String:Any] else { throw CheckFailure.assertion("native metadata request") }
      values["requestId"] = try handle(row,"requestId")
    }
    return try files.dispatch(operation, frame: frame(values), bytes: bytes, expected: expected ?? gate.currentEpoch)
  }
  func row(_ operation: String, _ values: [String: Any] = [:], bytes: Data = Data(), expected: String? = nil) throws -> [String: Any] {
    guard let text = try call(operation, values, bytes: bytes, expected: expected) as? String,
          let row = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
          row["version"] as? Int == 1 else { throw CheckFailure.assertion("actual canonical metadata frame") }
    return row
  }
  func handle(_ row: [String: Any], _ key: String = "handle") throws -> String {
    guard let id = row[key] as? String, UUID(uuidString: id)?.uuidString.lowercased() == id else { throw CheckFailure.assertion("native opaque handle") }
    return id
  }
  func export(_ bytes: Data, name: String = "owned.bin") throws -> String {
    selection = [destination]
    let context: [String: Any] = ["purpose": "export", "filename": name, "mimeType": "application/octet-stream", "size": bytes.count, "sourceContext": "digest/owned"]
    let choice = try handle(row("chooseDestination", context), "choiceId")
    return try handle(row("beginExport", context.merging(["choiceId": choice]) { _, new in new }))
  }
  func write(_ handle: String, _ bytes: Data) throws {
    for offset in stride(from: 0, to: bytes.count, by: 65_536) {
      _ = try row("writeExport", ["handle": handle, "offset": offset], bytes: bytes.subdata(in: offset..<min(offset + 65_536, bytes.count)))
    }
  }
  func ownedFiles() throws -> [URL] { try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) }
}

private final class CountedScope: MeshMessengerProtectedScopePort {
  private let condition = NSCondition()
  private var opened = 0, ended = 0
  let available: Bool
  init(_ available: Bool = true) { self.available = available }
  func start(_ url: URL) -> Bool {
    condition.lock(); defer { condition.unlock() }; opened += 1; return available
  }
  func stop(_ url: URL) {
    condition.lock(); ended += 1; condition.broadcast(); condition.unlock()
  }
  func snapshot() -> (starts: Int, stops: Int) {
    condition.lock(); defer { condition.unlock() }; return (opened, ended)
  }
  func waitForStops(_ count: Int) -> Bool {
    condition.lock(); defer { condition.unlock() }
    let end = Date(timeIntervalSinceNow: 2)
    while ended < count { if !condition.wait(until: end) { return false } }
    return true
  }
}

private final class OwnedCoordinator: MeshMessengerProtectedCoordinator {
  var reads = 0, writes = 0, cancels = 0
  var inRead = false, inWrite = false
  var beforeRead: ((URL, Int) throws -> Void)?
  var afterRead: ((URL, Int) throws -> Void)?
  var beforeWrite: (() throws -> Void)?
  func read(_ url: URL, body: (URL) throws -> Void) throws {
    reads += 1; let number = reads
    try beforeRead?(url, number); inRead = true
    do { try body(url) }
    catch { inRead = false; try afterRead?(url, number); throw error }
    inRead = false; try afterRead?(url, number)
  }
  func write(_ url: URL, body: (URL) throws -> Void) throws {
    writes += 1; try beforeWrite?(); inWrite = true; defer { inWrite = false }
    try body(url)
  }
  func cancel() { cancels += 1 }
}

private final class RaceValue<T> {
  private let mutex = NSLock()
  private var value: T
  init(_ value: T) { self.value = value }
  func get() -> T { mutex.lock(); defer { mutex.unlock() }; return value }
  func set(_ next: T) { mutex.lock(); value = next; mutex.unlock() }
}

// Native Foundation object seam: the adapter must invoke these exact Cocoa
// accessor methods; this object supplies no epoch or app-lock authority.
private final class FoundationCoordinatorProbe: NSFileCoordinator {
  enum Disposition { case once, twice, missing, refusal }
  var disposition: Disposition = .once
  var effective: URL?
  var failure: NSError?
  var inAccessor = false
  var reads = 0, writes = 0, cancellations = 0
  var readOptions: NSFileCoordinator.ReadingOptions?
  var writeOptions: NSFileCoordinator.WritingOptions?
  private func deliver(_ url: URL, error: NSErrorPointer, body: (URL) -> Void) {
    if disposition != .refusal && disposition != .missing {
      inAccessor = true
      body(effective ?? url)
      if disposition == .twice { body(effective ?? url) }
      inAccessor = false
    }
    error?.pointee = failure
  }
  override func coordinate(readingItemAt url: URL, options: NSFileCoordinator.ReadingOptions,
                           error: NSErrorPointer, byAccessor reader: (URL) -> Void) {
    reads += 1; readOptions = options; deliver(url, error: error, body: reader)
  }
  override func coordinate(writingItemAt url: URL, options: NSFileCoordinator.WritingOptions,
                           error: NSErrorPointer, byAccessor writer: (URL) -> Void) {
    writes += 1; writeOptions = options; deliver(url, error: error, body: writer)
  }
  override func cancel() { cancellations += 1 }
}
private final class FoundationWaitingProbe: NSFileCoordinator {
  let calls = RaceValue(0), cancellations = RaceValue(0), releasedByCancel = RaceValue(false)
  let released = DispatchSemaphore(value: 0)
  let refusal = NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)
  override func coordinate(readingItemAt url: URL, options: NSFileCoordinator.ReadingOptions,
                           error: NSErrorPointer, byAccessor reader: (URL) -> Void) {
    calls.set(calls.get() + 1)
    releasedByCancel.set(released.wait(timeout: .now() + 1) == .success)
    error?.pointee = refusal
  }
  override func cancel() { cancellations.set(cancellations.get() + 1); released.signal() }
}
private final class AccessorFailure: Error {}
private typealias NativeReacquirer = @Sendable () -> Void
private final class OwnedFilePresenter: NSObject, NSFilePresenter {
  let target: URL
  let presentedItemOperationQueue: OperationQueue
  let reads = RaceValue(0), writes = RaceValue(0)
  let beforeWrite: (() -> Void)?
  var presentedItemURL: URL? { target }
  init(_ target: URL, beforeWrite: (() -> Void)? = nil) {
    self.target = target; self.beforeWrite = beforeWrite
    presentedItemOperationQueue = OperationQueue(); presentedItemOperationQueue.maxConcurrentOperationCount = 1
    super.init()
  }
  func relinquishPresentedItem(toReader reader: @escaping @Sendable (NativeReacquirer?) -> Void) {
    reads.set(reads.get() + 1); reader(nil)
  }
  func relinquishPresentedItem(toWriter writer: @escaping @Sendable (NativeReacquirer?) -> Void) {
    writes.set(writes.get() + 1); beforeWrite?(); writer(nil)
  }
}

private final class SelectionContext: MeshMessengerProtectedSelectionContext {
  let gate: MeshMessengerAppLock
  init(_ gate: MeshMessengerAppLock) { self.gate = gate }
  func validate(expected: String) throws { try gate.requireEpoch(expected) }
}
private final class PhotoPort: MeshMessengerProtectedPhoto {
  let loads = RaceValue(0), cancellations = RaceValue(0), entered = DispatchSemaphore(value: 0)
  let completion = RaceValue<((Result<String?, Error>) -> Void)?>(nil)
  func importAvatar(expected: String, completion: @escaping (Result<String?, Error>) -> Void) -> MeshMessengerProtectedCleanup {
    loads.set(loads.get() + 1); self.completion.set(completion); entered.signal()
    return MeshMessengerProtectedCleanup { [weak self] in self?.cancelUnderlying() }
  }
  func cancelUnderlying() {
    cancellations.set(cancellations.get() + 1)
    let callback = completion.get(); completion.set(nil)
    callback?(.failure(CheckFailure.injected))
  }
}
private final class ChooserPort: MeshMessengerProtectedChooser {
  var onRevoke: (() -> Void)?
  let calls = RaceValue(0), cancellations = RaceValue(0), entered = DispatchSemaphore(value: 0)
  let completion = RaceValue<((Result<MeshMessengerProtectedSelection?, Error>) -> Void)?>(nil)
  func choose(purpose: String, multiple: Bool, expected: String,
              completion: @escaping (Result<MeshMessengerProtectedSelection?, Error>) -> Void) -> MeshMessengerProtectedCleanup {
    calls.set(calls.get() + 1); self.completion.set(completion); entered.signal()
    return MeshMessengerProtectedCleanup { [weak self] in guard let self else { return }; self.cancellations.set(self.cancellations.get() + 1) }
  }
  func revoke() { cancellations.set(cancellations.get() + 1); onRevoke?() }
}
private func actualAvatarFixture() throws -> String {
  let format = CGColorSpaceCreateDeviceRGB()
  guard let bitmap = CGContext(data: nil, width: 160, height: 160, bitsPerComponent: 8,
    bytesPerRow: 160 * 4, space: format, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { throw CheckFailure.injected }
  bitmap.setFillColor(CGColor(red: 0.2, green: 0.4, blue: 0.6, alpha: 1)); bitmap.fill(CGRect(x: 0, y: 0, width: 160, height: 160))
  guard let image = bitmap.makeImage() else { throw CheckFailure.injected }
  let bytes = NSMutableData()
  guard let destination = CGImageDestinationCreateWithData(bytes, UTType.jpeg.identifier as CFString, 1, nil) else { throw CheckFailure.injected }
  CGImageDestinationAddImage(destination, image, [kCGImageDestinationLossyCompressionQuality: 0.7] as CFDictionary)
  guard CGImageDestinationFinalize(destination) else { throw CheckFailure.injected }
  return "data:image/jpeg;base64," + (bytes as Data).base64EncodedString()
}
private final class AsyncFixture {
  let base: Fixture, chooser = ChooserPort(), photo = PhotoPort()
  var files: MeshMessengerProtectedFiles!
  var beforeRevoke: (() -> Void)?
  init(makeCoordinator: (() -> MeshMessengerProtectedCoordinator)? = nil) throws {
    base = try Fixture()
    files = MeshMessengerProtectedFiles(gate: base.gate, root: base.root, documents: base.documents,
      profile: { [base] expected in try base.gate.requireEpoch(expected); return base.profile }, nativeChooser: chooser, makeCoordinator: makeCoordinator)
    chooser.onRevoke = { [weak photo] in photo?.cancelUnderlying() }
    _ = base.gate.onRevoke { [weak self] in
      guard let self else { return }; self.beforeRevoke?(); self.files.revoke()
    }
  }
  func start(_ operation: String, _ row: [String: Any], expected: String? = nil,
             completion: @escaping (Result<Any, Error>) -> Void) throws {
    var row = row
    if ["chooseSource","chooseDestination"].contains(operation), let purpose = row["purpose"] as? String,
      ["backup-source","backup-export"].contains(purpose), row["requestId"] == nil {
      guard let raw = try files.dispatch("beginBackupChoice",frame:base.frame(["purpose":purpose]),bytes:Data(),expected:expected ?? base.gate.currentEpoch) as? String,
        let value = try JSONSerialization.jsonObject(with:Data(raw.utf8)) as? [String:Any] else { throw CheckFailure.assertion("native metadata request") }
      row["requestId"] = try base.handle(value,"requestId")
    }
    files.dispatchAsync(operation, frame: try base.frame(row), bytes: Data(), expected: expected ?? base.gate.currentEpoch, completion: completion)
  }
  func selectPhoto() throws -> String {
    let result = RaceValue<Result<Any, Error>?>(nil), done = DispatchSemaphore(value: 0)
    try start("chooseSource", ["purpose": "avatar"]) { result.set($0); done.signal() }
    try check(chooser.entered.wait(timeout: .now() + 2) == .success, "actual provider asks native selector without waiting for its UI result")
    guard let completion = chooser.completion.get() else { throw CheckFailure.assertion("native asynchronous selector callback") }
    completion(.success(MeshMessengerProtectedSelection(.photo(photo), context: SelectionContext(base.gate))))
    try check(done.wait(timeout: .now() + 2) == .success, "native selection completes without blocking UI")
    guard case .success(let any)? = result.get(), let text = any as? String,
      let row = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any], let id = row["choiceId"] as? String else {
      throw CheckFailure.assertion("actual native photo choice retained")
    }
    return id
  }
}

@main private enum ProtectedFilesTests {
  static func main() {
    let done = DispatchSemaphore(value: 0)
    DispatchQueue.global().async { run(); done.signal() }
    while done.wait(timeout: .now()) != .success { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
  }
  static func run() {
    if CommandLine.arguments.contains("--profile-framing") { runProfileFraming(); return }
    if CommandLine.arguments.contains("--backup-intents") { runBackupIntents(); return }
    if CommandLine.arguments.contains("--async-choice") { runAsyncChoice(); return }
    if CommandLine.arguments.contains("--native-coordinator") { runNativeCoordinator(); return }
    if CommandLine.arguments.contains("--headless-legacy") { runHeadlessLegacy(); return }
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("digest is actual SHA256 and has no file or picker side effect") {
      let f = try Fixture(), row = try f.row("digest", bytes: Data("hello".utf8))
      try check(row["digest"] as? String == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "known digest")
      try check(f.pickerCalls == 0 && f.outputOpens == 0 && f.ownedFiles().isEmpty, "no unintended IO")
    }
    test("preview URI belongs to protected root and old epoch cleanup cannot remove a fresh preview") {
      let f = try Fixture(), bytes = Data("owned preview fixture".utf8), old = f.gate.currentEpoch
      let row = try f.row("writePreview", ["key": "owned", "mimeType": "image/png"], bytes: bytes)
      let handle = try f.handle(row); guard let uri = row["uri"] as? String, let url = URL(string: uri) else { throw CheckFailure.assertion("preview URI") }
      try check(url.deletingLastPathComponent().standardizedFileURL == f.root.standardizedFileURL && Data(contentsOf: url) == bytes, "actual private preview")
      f.gate.foreground(ownerSceneID: "owned-scene", active: false); f.gate.foreground(ownerSceneID: "owned-scene", active: true)
      let fresh = try f.row("writePreview", ["key": "fresh", "mimeType": "image/png"], bytes: bytes)
      _ = try f.row("releasePreview", ["handle": handle], expected: old)
      guard let freshURI = fresh["uri"] as? String, let freshURL = URL(string: freshURI) else { throw CheckFailure.assertion("fresh URI") }
      try check(FileManager.default.fileExists(atPath: freshURL.path), "old cleanup preserves fresh preview")
    }
    test("native source choice claims one bounded handle and reads exact actual file ranges") {
      let f = try Fixture(), source = f.base.appendingPathComponent("source.bin"), bytes = Data((0..<1000).map { UInt8(truncatingIfNeeded: $0) })
      try bytes.write(to: source); f.selection = [source]
      let choice = try f.row("chooseSource", ["purpose": "attachment"]), choiceID = try f.handle(choice, "choiceId")
      guard let selected = (choice["files"] as? [[String: Any]])?.first else { throw CheckFailure.assertion("native source metadata") }
      let id = try f.handle(selected, "selectionId"), handle = try f.handle(f.row("claimSource", ["choiceId": choiceID, "selectionId": id, "size": bytes.count]))
      let result = try f.call("readSource", ["handle": handle, "offset": 100, "length": 40]) as? Data
      try check(result == bytes.subdata(in: 100..<140), "actual range bytes")
      try refuses { _ = try f.row("claimSource", ["choiceId": choiceID, "selectionId": id, "size": bytes.count]) }
      try Data(repeating: 4, count: bytes.count + 1).write(to: source)
      try refuses { _ = try f.call("readSource", ["handle": handle, "offset": 100, "length": 40]) }
    }
    test("picker epoch loss retains only a native choice and requires a fresh explicit operation") {
      let f = try Fixture(); f.selection = [f.destination]
      f.beforeChoice = { f.gate.foreground(ownerSceneID: "owned-scene", active: false) }
      let context: [String: Any] = ["purpose": "export", "filename": "owned.bin", "mimeType": "application/octet-stream", "size": 3, "sourceContext": "owned"]
      try refuses { _ = try f.row("chooseDestination", context) }
      try check(f.outputOpens == 0 && f.ownedFiles().isEmpty, "old picker action never stages or exports")
      f.beforeChoice = nil; f.gate.foreground(ownerSceneID: "owned-scene", active: true)
      _ = try f.handle(f.row("pendingChoice", context), "choiceId")
      f.gate.accountChanging()
      try check(try f.row("pendingChoice", context)["choiceId"] == nil, "old account choice discarded")
    }
    test("staging encrypts actual bytes and preserves existing completed exports") {
      let f = try Fixture(), bytes = Data(repeating: 0x41, count: 65_540), completed = f.destination.appendingPathComponent("completed.bin")
      try Data("existing completed export".utf8).write(to: completed)
      let handle = try f.export(bytes); try f.write(handle, bytes)
      let stages = try f.ownedFiles(); try check(stages.count == 1 && f.outputOpens == 0, "stage before destination publication")
      let sealed = try Data(contentsOf: stages[0])
      try check(sealed.range(of: Data(repeating: 0x41, count: 64)) == nil, "no plaintext run in native stage")
      try check(try Data(contentsOf: completed) == Data("existing completed export".utf8), "completed export preserved")
    }
    test("complete authenticated multi-chunk export writes the selected destination once") {
      let f = try Fixture(), bytes = Data((0..<131_073).map { UInt8(truncatingIfNeeded: $0) })
      let handle = try f.export(bytes); try f.write(handle, bytes); _ = try f.row("commitExport", ["handle": handle])
      try check(try Data(contentsOf: f.destination.appendingPathComponent("owned.bin")) == bytes, "full actual destination")
      try check(f.outputOpens == 1 && f.ownedFiles().isEmpty, "one publication and native stage cleanup")
    }
    test("last-chunk tag tamper is refused before opening or writing any destination byte") {
      let f = try Fixture(), bytes = Data(repeating: 7, count: 65_537), handle = try f.export(bytes); try f.write(handle, bytes)
      let stage = try f.ownedFiles()[0]; var changed = try Data(contentsOf: stage); changed[changed.count - 1] ^= 1; try changed.write(to: stage)
      try refuses { _ = try f.row("commitExport", ["handle": handle]) }
      try check(f.outputOpens == 0 && !FileManager.default.fileExists(atPath: f.destination.appendingPathComponent("owned.bin").path), "full tag prepass before destination open")
    }
    test("revoke after admitted output chunk blocks future chunks without deleting that partial external export") {
      let f = try Fixture(), bytes = Data(repeating: 9, count: 131_072), handle = try f.export(bytes); try f.write(handle, bytes)
      f.afterOutputWrite = { f.gate.lock() }
      try refuses { _ = try f.row("commitExport", ["handle": handle]) }
      let partial = try Data(contentsOf: f.destination.appendingPathComponent("owned.bin"))
      try check(partial == bytes.prefix(65_536), "one already-admitted chunk, no later chunk")
    }
    test("incomplete export cannot publish and stale cleanup never gains authority") {
      let f = try Fixture(), handle = try f.export(Data(repeating: 3, count: 10)), old = f.gate.currentEpoch
      _ = try f.row("writeExport", ["handle": handle, "offset": 0], bytes: Data(repeating: 3, count: 3))
      try refuses { _ = try f.row("commitExport", ["handle": handle]) }; try check(f.outputOpens == 0, "incomplete no destination")
      f.gate.lock(); _ = try f.row("abortExport", ["handle": handle], expected: old)
      try refuses { _ = try f.call("digest", bytes: Data([1]), expected: old) }
    }
    test("legacy migration derives exact filenames and stale deletion preserves originals") {
      let f = try Fixture(), account = String(repeating: "01", count: 32), url = f.documents.appendingPathComponent("read-state-" + account + ".json")
      try Data("{\"owned\":1}".utf8).write(to: url)
      try check(try f.files.readLegacy(f.profile, kind: "read-state", expected: f.gate.currentEpoch) == "{\"owned\":1}", "actual exact legacy file")
      let old = f.gate.currentEpoch; f.gate.lock()
      try refuses { try f.files.removeLegacy(f.profile, kind: "read-state", expected: old) }
      try check(FileManager.default.fileExists(atPath: url.path), "stale migration cannot delete original")
    }
    test("untrusted caller paths and malformed frames cannot trigger picker or output") {
      let f = try Fixture()
      for frame in ["{}", "{\"version\":true}", "{\"version\":1,\"uri\":\"file:///outside\"}"] {
        try refuses { _ = try f.files.dispatch("chooseSource", frame: frame, bytes: Data(), expected: f.gate.currentEpoch) }
      }
      try check(f.pickerCalls == 0 && f.outputOpens == 0, "no provider entry from invalid frame")
    }
    test("native orphan cleanup removes only owned files and refuses symlink traversal") {
      let f = try Fixture(), outside = f.base.appendingPathComponent("outside"), orphan = f.root.appendingPathComponent(UUID().uuidString.lowercased())
      try Data("outside preserved".utf8).write(to: outside); try Data("owned orphan".utf8).write(to: orphan)
      try f.files.cleanOrphans(); try check(!FileManager.default.fileExists(atPath: orphan.path), "native orphan removed")
      let link = f.root.appendingPathComponent(UUID().uuidString.lowercased()); try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
      try refuses { try f.files.cleanOrphans() }; try check(try Data(contentsOf: outside) == Data("outside preserved".utf8), "no symlink following or unrelated delete")
    }
    test("concurrent duplicate native cleanup closes a descriptor and successful security-scope lease only once") {
      let f = try Fixture(), url = f.base.appendingPathComponent("lease-source"), port = CountedScope()
      try Data("owned lease".utf8).write(to: url)
      let input = try FileHandle(forReadingFrom: url), lease = MeshMessengerProtectedScopeLease(url, port: port)
      let cleanup = MeshMessengerProtectedCleanup { try? input.close(); lease.close() }
      let workers = DispatchGroup()
      for _ in 0..<2 { workers.enter(); DispatchQueue.global().async { cleanup.run(); workers.leave() } }
      try check(workers.wait(timeout: .now() + 2) == .success, "cleanup workers reaped")
      cleanup.run()
      let actual = port.snapshot()
      try check(actual.starts == 1 && actual.stops == 1, "one successful scope start must have one stop; actual stops=\(actual.stops)")
      try refuses { _ = try input.read(upToCount: 1) }
      let unavailable = CountedScope(false), unacquired = MeshMessengerProtectedScopeLease(url, port: unavailable)
      unacquired.close(); unacquired.close()
      try check(unavailable.snapshot().starts == 1 && unavailable.snapshot().stops == 0, "failed acquisition must never stop")
    }
    test("actual source cleanup balances the injected native scope and preserves the original across late revoke") {
      let port = CountedScope(), f = try Fixture(securityScope: port), url = f.base.appendingPathComponent("source.bin")
      let bytes = Data("owned source remains".utf8); try bytes.write(to: url); f.selection = [url]
      let choice = try f.row("chooseSource", ["purpose": "attachment"]), choiceID = try f.handle(choice, "choiceId")
      guard let selected = (choice["files"] as? [[String: Any]])?.first else { throw CheckFailure.assertion("selected source") }
      let id = try f.handle(selected, "selectionId"), handle = try f.handle(f.row("claimSource", ["choiceId": choiceID, "selectionId": id, "size": bytes.count]))
      try check(port.snapshot().starts == 2 && port.snapshot().stops == 1, "source owns its second acquired scope")
      let old = f.gate.currentEpoch
      _ = try f.row("closeSource", ["handle": handle]); try check(port.waitForStops(2), "actual source descriptor cleanup completed")
      f.gate.lock(); _ = try f.row("closeSource", ["handle": handle], expected: old)
      try check(port.snapshot().stops == 2 && Data(contentsOf: url) == bytes, "late cleanup balanced and preserves original")
      try refuses { _ = try f.call("readSource", ["handle": handle, "offset": 0, "length": 1]) }
    }
    test("every actual destination open write and close stays inside its native coordinated accessor") {
      let coordination = OwnedCoordinator(), f = try Fixture(makeCoordinator: { coordination })
      var outside: [String] = []
      f.beforeOutputOpen = { if !coordination.inWrite { outside.append("open") } }
      f.afterOutputWrite = { if !coordination.inWrite { outside.append("write") } }
      f.afterOutputClose = { if !coordination.inWrite { outside.append("close") } }
      let bytes = Data(repeating: 0x62, count: 65_537), handle = try f.export(bytes)
      try f.write(handle, bytes); _ = try f.row("commitExport", ["handle": handle])
      try check(outside.isEmpty && coordination.writes == 1, "destination IO escaped native callback: \(outside)")
      try check(Data(contentsOf: f.destination.appendingPathComponent("owned.bin")) == bytes, "same real destination bytes")
    }
    test("actual selected source metadata claim and range read obey provider callback-local access") {
      let coordination = OwnedCoordinator(), f = try Fixture(makeCoordinator: { coordination })
      let selected = f.base.appendingPathComponent("selected-source"), backing = f.base.appendingPathComponent("provider-backing")
      let bytes = Data("native provider callback bytes".utf8); try bytes.write(to: backing); f.selection = [selected]
      coordination.beforeRead = { url, _ in
        try check(url == selected, "only admitted selected URL coordinated")
        try FileManager.default.moveItem(at: backing, to: selected)
      }
      coordination.afterRead = { _, count in
        try FileManager.default.moveItem(at: selected, to: backing)
        // The third access is the range read. A real read escaping its callback
        // now sees changed/truncated bytes instead of the selected snapshot.
        if count == 3 { let file = try FileHandle(forWritingTo: backing); defer { try? file.close() }; try file.truncate(atOffset: 0) }
      }
      let choice = try f.row("chooseSource", ["purpose": "attachment"]), choiceID = try f.handle(choice, "choiceId")
      guard let source = (choice["files"] as? [[String: Any]])?.first else { throw CheckFailure.assertion("native source choice") }
      let id = try f.handle(source, "selectionId"), handle = try f.handle(f.row("claimSource", ["choiceId": choiceID, "selectionId": id, "size": bytes.count]))
      let result = try f.call("readSource", ["handle": handle, "offset": 0, "length": bytes.count]) as? Data
      try check(result == bytes && coordination.reads == 3, "source bytes read before coordinated accessor return")
      try check(!FileManager.default.fileExists(atPath: selected.path), "temporary provider URL not retained for outside access")
    }
    test("coordination that returns after native revoke cannot create or write any destination") {
      let coordination = OwnedCoordinator(), f = try Fixture(makeCoordinator: { coordination })
      let bytes = Data(repeating: 3, count: 65_537), handle = try f.export(bytes), expected = f.gate.currentEpoch
      try f.write(handle, bytes)
      coordination.beforeWrite = { f.gate.lock() }
      // Even if an already-scheduled OS accessor runs after cancellation,
      // its immutable epoch must be checked again before destination creation.
      try refuses { _ = try f.row("commitExport", ["handle": handle], expected: expected) }
      try check(coordination.writes == 1 && f.outputOpens == 0 && !FileManager.default.fileExists(atPath: f.destination.appendingPathComponent("owned.bin").path), "post-wait stale accessor cannot publish")
    }
    test("a delayed old native revoke hook cannot remove a genuinely admitted fresh disabled preview") {
      let queue = DispatchQueue(label: "owned.old-revoke-preview"), f = try Fixture(cleanupQueue: queue)
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchGroup()
      let timedOut = RaceValue(false), old = f.gate.currentEpoch
      f.beforeRevoke = {
        entered.signal()
        if release.wait(timeout: .now() + 3) != .success { timedOut.set(true) }
      }
      done.enter()
      DispatchQueue.global().async { f.gate.foreground(ownerSceneID: "owned-scene", active: false); done.leave() }
      defer { release.signal(); _ = done.wait(timeout: .now() + 3) }
      try check(entered.wait(timeout: .now() + 2) == .success, "actual native revoke hook entered")
      let fresh = f.gate.currentEpoch
      try check(fresh != old && f.gate.state()["phase"] as? String == "disabled", "actual native event produced new disabled epoch")
      // A fresh disabled/headless action is allowed by this real pinned gate.
      // No synthetic unlock, manual epoch assignment or old-action refresh.
      try f.gate.requireEpoch(fresh)
      let bytes = Data("fresh owned preview".utf8)
      let row = try f.row("writePreview", ["key": "fresh-native", "mimeType": "image/png"], bytes: bytes, expected: fresh)
      guard let uri = row["uri"] as? String, let url = URL(string: uri) else { throw CheckFailure.assertion("fresh actual preview URI") }
      try check(try Data(contentsOf: url) == bytes, "fresh native preview genuinely admitted before old hook completion")
      release.signal(); try check(done.wait(timeout: .now() + 2) == .success, "old native revoke hook returned")
      queue.sync {}
      try check(!timedOut.get(), "owned hook schedule did not time out")
      try f.gate.requireEpoch(fresh)
      try check(FileManager.default.fileExists(atPath: url.path) && Data(contentsOf: url) == bytes, "old native hook removed current disabled epoch preview")
    }
    test("a delayed old native revoke hook cannot cancel genuinely current coordinated source access") {
      let queue = DispatchQueue(label: "owned.old-revoke-access"), coordination = OwnedCoordinator()
      let f = try Fixture(makeCoordinator: { coordination }, cleanupQueue: queue)
      let entered = DispatchSemaphore(value: 0), oldRelease = DispatchSemaphore(value: 0), oldDone = DispatchGroup()
      let accessEntered = DispatchSemaphore(value: 0), accessRelease = DispatchSemaphore(value: 0), accessDone = DispatchGroup()
      let timedOut = RaceValue(false), result = RaceValue<Result<Data, Error>?>(nil), old = f.gate.currentEpoch
      f.beforeRevoke = {
        entered.signal()
        if oldRelease.wait(timeout: .now() + 3) != .success { timedOut.set(true) }
      }
      oldDone.enter()
      DispatchQueue.global().async { f.gate.foreground(ownerSceneID: "owned-scene", active: false); oldDone.leave() }
      defer { oldRelease.signal(); accessRelease.signal(); _ = oldDone.wait(timeout: .now() + 3); _ = accessDone.wait(timeout: .now() + 3) }
      try check(entered.wait(timeout: .now() + 2) == .success, "old real native hook deferred")
      let fresh = f.gate.currentEpoch
      try check(fresh != old && f.gate.state()["phase"] as? String == "disabled", "real fresh disabled epoch before listener completes")
      try f.gate.requireEpoch(fresh)
      let url = f.base.appendingPathComponent("current-source"), bytes = Data("fresh source bytes".utf8)
      try bytes.write(to: url); f.selection = [url]
      let choice = try f.row("chooseSource", ["purpose": "attachment"], expected: fresh), choiceID = try f.handle(choice, "choiceId")
      guard let selected = (choice["files"] as? [[String: Any]])?.first else { throw CheckFailure.assertion("fresh current source") }
      let id = try f.handle(selected, "selectionId")
      let handle = try f.handle(f.row("claimSource", ["choiceId": choiceID, "selectionId": id, "size": bytes.count], expected: fresh))
      coordination.beforeRead = { _, number in
        if number == 3 {
          accessEntered.signal()
          if accessRelease.wait(timeout: .now() + 3) != .success { timedOut.set(true) }
        }
      }
      accessDone.enter()
      DispatchQueue.global().async {
        do {
          guard let value = try f.call("readSource", ["handle": handle, "offset": 0, "length": bytes.count], expected: fresh) as? Data else { throw CheckFailure.assertion("fresh Data response") }
          result.set(.success(value))
        } catch { result.set(.failure(error)) }
        accessDone.leave()
      }
      try check(accessEntered.wait(timeout: .now() + 2) == .success, "fresh access registered and waiting in actual native port")
      oldRelease.signal(); try check(oldDone.wait(timeout: .now() + 2) == .success, "old real hook completed with fresh access registered")
      try f.gate.requireEpoch(fresh)
      accessRelease.signal(); try check(accessDone.wait(timeout: .now() + 2) == .success, "fresh coordinated operation returned")
      queue.sync {}
      try check(!timedOut.get(), "owned native schedule had no timeout")
      switch result.get() {
      case .success(let value)?: try check(value == bytes, "fresh coordinated bytes preserved")
      case .failure(let error)?: throw CheckFailure.assertion("old native hook cancelled current access: \(error)")
      case nil: throw CheckFailure.assertion("fresh access did not report outcome")
      }
    }
    print("RESULT \(19 - failures)/19 passed")
    if failures != 0 { exit(1) }
  }

  static func runNativeCoordinator() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("native Foundation adapter uses callback URL and keeps actual reader writer IO inside its accessor") {
      let f = try Fixture(), original = f.base.appendingPathComponent("unavailable-original"), effective = f.base.appendingPathComponent("effective")
      let bytes = Data("callback-owned bytes".utf8); try bytes.write(to: effective)
      let reader = FoundationCoordinatorProbe(filePresenter: nil); reader.effective = effective
      var read = Data()
      try MeshMessengerNativeProtectedCoordinator(coordinator: reader).read(original) { url in
        try check(reader.inAccessor && url == effective, "actual native callback URL/lifetime")
        read = try Data(contentsOf: url)
      }
      try check(read == bytes && reader.reads == 1 && reader.readOptions == [], "one real Foundation reader invocation")
      let writer = FoundationCoordinatorProbe(filePresenter: nil), destination = f.base.appendingPathComponent("written")
      writer.effective = destination
      try MeshMessengerNativeProtectedCoordinator(coordinator: writer).write(original) { url in
        try check(writer.inAccessor && url == destination, "writer callback URL/lifetime")
        try check(FileManager.default.createFile(atPath: url.path, contents: nil), "create selected output in callback")
        let output = try FileHandle(forWritingTo: url); defer { try? output.close() }
        try output.write(contentsOf: bytes); try output.close()
      }
      try check(try Data(contentsOf: destination) == bytes && writer.writes == 1 && writer.writeOptions == [], "exact native write, no replace/move option")
      try check(!FileManager.default.fileExists(atPath: original.path), "original input URL was not substituted")
    }
    test("native adapter preserves original accessor error identity over Foundation error disposition") {
      let f = try Fixture(), probe = FoundationCoordinatorProbe(filePresenter: nil), own = AccessorFailure()
      probe.failure = NSError(domain: "owned-foundation-disposition", code: 31)
      do {
        try MeshMessengerNativeProtectedCoordinator(coordinator: probe).read(f.base) { _ in throw own }
        throw CheckFailure.assertion("expected original accessor failure")
      } catch {
        try check(error as AnyObject === own, "genuine callback error identity must survive")
      }
      try check(probe.reads == 1, "Foundation boundary was actually invoked")
    }
    test("native adapter returns genuine Foundation refusal without executing caller IO") {
      let f = try Fixture(), probe = FoundationCoordinatorProbe(filePresenter: nil)
      let refusal = NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)
      probe.disposition = .refusal; probe.failure = refusal
      var writes = 0
      do {
        try MeshMessengerNativeProtectedCoordinator(coordinator: probe).write(f.base) { _ in writes += 1 }
        throw CheckFailure.assertion("expected Foundation refusal")
      } catch { try check(error as NSError === refusal, "exact Foundation refusal identity") }
      try check(writes == 0 && probe.writes == 1, "no body on denied Foundation access")
    }
    test("native adapter refuses duplicate missing reused and precancelled native access without duplicate IO") {
      let f = try Fixture(), duplicate = FoundationCoordinatorProbe(filePresenter: nil); duplicate.disposition = .twice
      var writes = 0
      try refuses { try MeshMessengerNativeProtectedCoordinator(coordinator: duplicate).write(f.base) { _ in writes += 1 } }
      try check(writes == 1 && duplicate.writes == 1, "second Foundation callback cannot duplicate publication")
      let missing = FoundationCoordinatorProbe(filePresenter: nil); missing.disposition = .missing
      try refuses { try MeshMessengerNativeProtectedCoordinator(coordinator: missing).read(f.base) { _ in throw CheckFailure.assertion("missing accessor cannot run") } }
      try check(missing.reads == 1, "missing real callback observed")
      let once = FoundationCoordinatorProbe(filePresenter: nil), adapter = MeshMessengerNativeProtectedCoordinator(coordinator: once)
      try adapter.read(f.base) { _ in }
      try refuses { try adapter.read(f.base) { _ in throw CheckFailure.assertion("one native operation per coordinator") } }
      try check(once.reads == 1, "completed native instance cannot be reused")
      let cancelled = FoundationCoordinatorProbe(filePresenter: nil), cancelledAdapter = MeshMessengerNativeProtectedCoordinator(coordinator: cancelled)
      cancelledAdapter.cancel(); cancelledAdapter.cancel()
      try refuses { try cancelledAdapter.read(f.base) { _ in throw CheckFailure.assertion("precancelled operation cannot run") } }
      try check(cancelled.cancellations == 1 && cancelled.reads == 0, "native cancellation is once-only and closes admission")
    }
    test("native Foundation wait deadline cancels bounded admission without invoking accessor IO") {
      let f = try Fixture(), waiting = FoundationWaitingProbe(filePresenter: nil)
      let adapter = MeshMessengerNativeProtectedCoordinator(coordinator: waiting, timeout: 0.02)
      var reads = 0
      do { try adapter.read(f.base) { _ in reads += 1 }; throw CheckFailure.assertion("expected bounded native wait refusal") }
      catch { try check(error as NSError === waiting.refusal, "genuine Foundation cancellation disposition") }
      try check(waiting.calls.get() == 1 && waiting.releasedByCancel.get() && reads == 0, "deadline releases actual waiting boundary without plaintext IO")
      adapter.cancel(); try check(waiting.cancellations.get() == 1, "deadline and owner cleanup share once-only cancellation")
    }
    test("production default source access uses actual Foundation presenter coordination") {
      let f = try Fixture(), source = f.base.appendingPathComponent("presented-source"), bytes = Data("real Foundation source".utf8)
      try bytes.write(to: source)
      let presenter = OwnedFilePresenter(source); NSFileCoordinator.addFilePresenter(presenter)
      defer { NSFileCoordinator.removeFilePresenter(presenter); presenter.presentedItemOperationQueue.waitUntilAllOperationsAreFinished() }
      f.selection = [source]
      let selected = try f.row("chooseSource", ["purpose": "attachment"]), choice = try f.handle(selected, "choiceId")
      guard let files = selected["files"] as? [[String: Any]], let item = files.first else { throw CheckFailure.assertion("native selected source") }
      let id = try f.handle(item, "selectionId"), handle = try f.handle(f.row("claimSource", ["choiceId": choice, "selectionId": id, "size": bytes.count]))
      guard let read = try f.call("readSource", ["handle": handle, "offset": 0, "length": bytes.count]) as? Data else { throw CheckFailure.assertion("actual source Data") }
      try check(read == bytes && presenter.reads.get() >= 3, "default metadata claim and read cannot bypass actual Foundation presenter")
      _ = try f.row("closeSource", ["handle": handle])
    }
    test("production default Foundation waiting export is cancelled by revoke before output creation") {
      let f = try Fixture(), bytes = Data("must not be published".utf8)
      let handle = try f.export(bytes, name: "waiting.bin"); try f.write(handle, bytes)
      let target = f.destination.appendingPathComponent("waiting.bin")
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), finished = DispatchGroup()
      let timedOut = RaceValue(false), outcome = RaceValue<Result<Void, Error>?>(nil)
      let presenter = OwnedFilePresenter(target, beforeWrite: {
        entered.signal(); if release.wait(timeout: .now() + 3) != .success { timedOut.set(true) }
      })
      NSFileCoordinator.addFilePresenter(presenter)
      let expected = f.gate.currentEpoch
      defer {
        release.signal(); _ = finished.wait(timeout: .now() + 4)
        NSFileCoordinator.removeFilePresenter(presenter); presenter.presentedItemOperationQueue.waitUntilAllOperationsAreFinished()
      }
      finished.enter()
      DispatchQueue.global().async {
        do { _ = try f.row("commitExport", ["handle": handle], expected: expected); outcome.set(.success(())) }
        catch { outcome.set(.failure(error)) }
        finished.leave()
      }
      try check(entered.wait(timeout: .now() + 2) == .success, "actual Foundation write is waiting on owned presenter")
      f.gate.lock()
      try check(finished.wait(timeout: .now() + 2) == .success, "native cancel releases waiting operation before presenter release")
      release.signal()
      guard case .failure? = outcome.get() else { throw CheckFailure.assertion("revoked actual Foundation export cannot succeed") }
      try check(!timedOut.get() && f.outputOpens == 0 && !FileManager.default.fileExists(atPath: target.path), "no destination byte admitted across revoke")
    }
    print("RESULT \(7 - failures)/7 native-coordinator groups passed")
    if failures != 0 { exit(1) }
  }
  static func runAsyncChoice() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    test("native photo selection retains only a choice before fresh explicit import") {
      let f = try AsyncFixture(), id = try f.selectPhoto()
      try check(UUID(uuidString: id) != nil && f.photo.loads.get() == 0, "selection does not load image or private file bytes")
    }
    test("fresh explicit photo import consumes the selected provider once and preserves cancellation") {
      let f = try AsyncFixture(), id = try f.selectPhoto(), done = DispatchSemaphore(value: 0)
      let result = RaceValue<Result<Any, Error>?>(nil)
      try f.start("importAvatar", ["choiceId": id]) { result.set($0); done.signal() }
      try check(f.photo.entered.wait(timeout: .now() + 2) == .success && f.photo.loads.get() == 1, "only import asks native provider for bytes/editor")
      f.photo.completion.get()?(.success(nil))
      try check(done.wait(timeout: .now() + 2) == .success, "current native editor cancellation completes")
      guard case .success(let any)? = result.get(), let text = any as? String else { throw CheckFailure.assertion("genuine cancellation result") }
      try check(text.contains("cancelled"), "cancellation is not avatar success")
      let replay = DispatchSemaphore(value: 0), refusal = RaceValue(false)
      try f.start("importAvatar", ["choiceId": id]) { if case .failure = $0 { refusal.set(true) }; replay.signal() }
      try check(replay.wait(timeout: .now() + 2) == .success && refusal.get() && f.photo.loads.get() == 1, "a consumed native choice cannot reload")
    }
    test("late or double photo completion cannot publish through a newer native epoch") {
      let f = try AsyncFixture(), id = try f.selectPhoto(), old = f.base.gate.currentEpoch
      let done = DispatchSemaphore(value: 0), callbacks = RaceValue(0), refused = RaceValue(false)
      try f.start("importAvatar", ["choiceId": id], expected: old) {
        callbacks.set(callbacks.get() + 1); if case .failure = $0 { refused.set(true) }; done.signal()
      }
      try check(f.photo.entered.wait(timeout: .now() + 2) == .success && f.photo.loads.get() == 1, "native load began under original action")
      f.base.gate.lock(); f.photo.completion.get()?(.success(nil)); f.photo.completion.get()?(.success(nil))
      try check(done.wait(timeout: .now() + 2) == .success && refused.get() && callbacks.get() == 1, "stale completion is refused exactly once")
    }
    test("native UI callback never performs actual selected-file IO on the main thread") {
      let coordinator = OwnedCoordinator(), metadataOnWorker = RaceValue(false)
      coordinator.beforeRead = { _, _ in
        try check(!Thread.isMainThread, "native selected-file metadata IO must leave UIKit callback thread")
        metadataOnWorker.set(true)
      }
      let f = try AsyncFixture(makeCoordinator: { coordinator }), selected = f.base.base.appendingPathComponent("selected.bin")
      try Data("native-file".utf8).write(to: selected)
      let done = DispatchSemaphore(value: 0), result = RaceValue<Result<Any, Error>?>(nil)
      try f.start("chooseSource", ["purpose": "attachment"]) { result.set($0); done.signal() }
      try check(f.chooser.entered.wait(timeout: .now() + 2) == .success, "native document selector called")
      DispatchQueue.main.async {
        f.chooser.completion.get()?(.success(MeshMessengerProtectedSelection(.documents([selected]), context: SelectionContext(f.base.gate))))
      }
      try check(done.wait(timeout: .now() + 2) == .success, "document selection callback completes")
      guard case .success? = result.get() else { throw CheckFailure.assertion("actual native metadata callback was not dispatched to a worker") }
      try check(metadataOnWorker.get(), "real provider coordinated selected-file metadata off Main")
    }
    test("delayed old revoke cannot cancel a genuinely fresh asynchronous native import") {
      let f = try AsyncFixture(), choice = try f.selectPhoto(), old = f.base.gate.currentEpoch
      let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), oldDone = DispatchGroup()
      let timedOut = RaceValue(false), completion = DispatchSemaphore(value: 0), outcome = RaceValue<Result<Any, Error>?>(nil)
      f.beforeRevoke = {
        entered.signal(); if release.wait(timeout: .now() + 3) != .success { timedOut.set(true) }
      }
      oldDone.enter()
      DispatchQueue.global().async { f.base.gate.foreground(ownerSceneID: "owned-scene", active: false); oldDone.leave() }
      defer { release.signal(); _ = oldDone.wait(timeout: .now() + 3) }
      try check(entered.wait(timeout: .now() + 2) == .success, "actual old native revoke hook is deferred")
      let fresh = f.base.gate.currentEpoch
      try check(fresh != old && f.base.gate.state()["phase"] as? String == "disabled", "real fresh disabled-mode epoch before old hook completion")
      try f.base.gate.requireEpoch(fresh)
      try f.start("importAvatar", ["choiceId": choice], expected: fresh) { outcome.set($0); completion.signal() }
      try check(f.photo.entered.wait(timeout: .now() + 2) == .success, "genuinely fresh native import started")
      release.signal(); try check(oldDone.wait(timeout: .now() + 2) == .success && !timedOut.get(), "old hook returned without timeout")
      try check(f.photo.cancellations.get() == 0, "old hook must preserve the underlying current native import, not only its core completion")
      f.photo.completion.get()?(.success(nil))
      try check(completion.wait(timeout: .now() + 2) == .success, "fresh native callback completes")
      guard case .success? = outcome.get() else { throw CheckFailure.assertion("old hook cancelled fresh actual native work") }
    }
    test("actual avatar client request and response contract carries a canonical avatar field") {
      let f = try AsyncFixture(), id = try f.selectPhoto(), done = DispatchSemaphore(value: 0)
      let result = RaceValue<Result<Any, Error>?>(nil), jpeg = try actualAvatarFixture()
      // This is the actual createAvatarServices import frame, including purpose.
      try f.start("importAvatar", ["purpose": "avatar", "choiceId": id]) { result.set($0); done.signal() }
      try check(f.photo.entered.wait(timeout: .now() + 2) == .success, "the actual avatar client frame must reach the selected native photo provider")
      f.photo.completion.get()?(.success(jpeg))
      try check(done.wait(timeout: .now() + 2) == .success, "real ImageIO JPEG callback completes")
      guard case .success(let value)? = result.get(), let text = value as? String,
        let row = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw CheckFailure.assertion("actual avatar response metadata") }
      try check(row["avatar"] as? String == jpeg && row["uri"] == nil, "the actual client expects avatar, never a source URI response")
    }
    print("RESULT \(6 - failures)/6 asynchronous-choice groups passed")
    if failures != 0 { exit(1) }
  }

  static func runHeadlessLegacy() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    func provider(_ f: Fixture) -> MeshMessengerProtectedFiles {
      MeshMessengerProtectedFiles(gate: f.gate, root: f.root, documents: f.documents,
        profile: { _ in throw CheckFailure.assertion("headless file IO borrowed the unavailable UI profile reader") },
        choose: { _, _ in throw CheckFailure.assertion("headless legacy IO opened a native chooser") },
        output: { _ in throw CheckFailure.assertion("headless legacy IO opened an external destination") })
    }
    func url(_ f: Fixture) -> URL { f.documents.appendingPathComponent("read-state-" + String(repeating: "01", count: 32) + ".json") }
    test("headless legacy IO uses its native account profile and exact documents root without a UI owner") {
      let f = try Fixture(), files = provider(f), expected = f.gate.currentEpoch, target = url(f)
      try Data("owned legacy state".utf8).write(to: target)
      try files.requireNativeDocuments(f.documents)
      try refuses { try files.requireNativeDocuments(f.base) }
      let text = try files.readLegacy(f.profile, kind: "read-state", expected: expected, nativeProfile: { try f.gate.requireEpoch($0); return f.profile })
      try check(text == "owned legacy state", "actual owned file read through the native headless profile boundary")
      try files.removeLegacy(f.profile, kind: "read-state", expected: expected, nativeProfile: { try f.gate.requireEpoch($0); return f.profile })
      try check(!FileManager.default.fileExists(atPath: target.path) && f.pickerCalls == 0, "only the exact owned legacy file was removed")
    }
    test("a foreign headless account profile cannot read or remove an owned legacy file") {
      let f = try Fixture(), files = provider(f), target = url(f), expected = f.gate.currentEpoch
      try Data("preserved".utf8).write(to: target)
      let foreign = packet([Data("Foreign".utf8), Data(repeating: 3, count: 32), Data(repeating: 2, count: 16), Data()])
      try refuses { _ = try files.readLegacy(f.profile, kind: "read-state", expected: expected, nativeProfile: { _ in foreign }) }
      try refuses { try files.removeLegacy(f.profile, kind: "read-state", expected: expected, nativeProfile: { _ in foreign }) }
      try check(try Data(contentsOf: target) == Data("preserved".utf8), "foreign native profile refusal preserves all owned bytes")
    }
    test("account revocation during the native headless profile callback refuses before legacy removal") {
      let f = try Fixture(), files = provider(f), target = url(f), expected = f.gate.currentEpoch
      try Data("preserved".utf8).write(to: target)
      try refuses { try files.removeLegacy(f.profile, kind: "read-state", expected: expected, nativeProfile: { _ in f.gate.accountChanging(); return f.profile }) }
      try check(f.gate.currentEpoch != expected && Data(contentsOf: target) == Data("preserved".utf8), "the actual gate epoch is rechecked before the native unlink boundary")
    }
    print("RESULT \(3 - failures)/3 headless-legacy groups passed")
    if failures != 0 { exit(1) }
  }

  static func runBackupIntents() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    func owner(_ f: Fixture) throws {
      f.gate.foreground(ownerSceneID: "owned-scene", active: true)
      try DispatchQueue.main.sync { try f.gate.activate(f.gate.currentEpoch, ownerSceneID: "owned-scene") }
    }
    test("actual picker inactivity rotates epoch and regenerated export contexts miss retained metadata") {
      let f = try Fixture(), old = f.gate.currentEpoch
      f.selection = [f.destination]
      let original: [String: Any] = ["purpose":"export", "filename":"owned.bin", "mimeType":"application/octet-stream", "size":1, "sourceContext":"backup-export/\(old)/1"]
      f.beforeChoice = { f.gate.foreground(ownerSceneID:"owned-scene", active:false) }
      try refuses { _ = try f.row("chooseDestination", original, expected:old) }
      let fresh = f.gate.currentEpoch
      try check(fresh != old, "real native inactivity changed the epoch")
      try owner(f)
      let kept = try f.handle(f.row("pendingChoice", original), "choiceId")
      var regenerated = original; regenerated["sourceContext"] = "backup-export/\(fresh)/2"
      try check(try f.row("pendingChoice", regenerated)["choiceId"] == nil, "recreated material cannot find the old per-epoch destination context")
      let handle = try f.handle(f.row("beginExport", original.merging(["choiceId":kept]) { _, new in new }))
      _ = try f.row("abortExport", ["handle":handle])
      try check(f.pickerCalls == 1, "only fresh explicit metadata claim, no second chooser or old private publication")
    }
    test("backup destination preflight retains only metadata and fresh claim fixes ciphertext name MIME and size") {
      let f = try Fixture(); try owner(f); f.selection = [f.destination]
      let intent: [String:Any] = ["purpose":"backup-export"]
      let choice = try f.handle(f.row("chooseDestination", intent), "choiceId")
      try check(try f.ownedFiles().isEmpty && f.outputOpens == 0, "destination choice creates no staging or external bytes")
      try check(try f.handle(f.row("pendingChoice", intent), "choiceId") == choice, "same owned metadata choice is recoverable")
      let bytes = Data(repeating: 11, count: 65_537)
      let claim: [String:Any] = ["purpose":"backup-export", "choiceId":choice, "filename":"morse-backup.morsebackup", "mimeType":"application/octet-stream", "size":bytes.count, "sourceContext":"backup-export/\(f.gate.currentEpoch)/1"]
      var bad = claim; bad["filename"] = "private-code.txt"; try refuses { _ = try f.row("beginExport", bad) }
      bad = claim; bad["size"] = 16_796_865; try refuses { _ = try f.row("beginExport", bad) }
      let handle = try f.handle(f.row("beginExport", claim)); try refuses { _ = try f.row("beginExport", claim) }
      try f.write(handle, bytes); _ = try f.row("commitExport", ["handle":handle])
      try check(try Data(contentsOf:f.destination.appendingPathComponent("morse-backup.morsebackup")) == bytes, "actual encrypted staging/coordinated copy preserves ciphertext")
      try check(f.outputOpens == 1, "one explicit current owner publishes once")
    }
    test("backup source selects one inclusive bounded file and requires an explicit once only claim") {
      let f = try Fixture(); try owner(f)
      let url = f.base.appendingPathComponent("selected.backup")
      try Data().write(to:url); let writer = try FileHandle(forWritingTo:url); try writer.truncate(atOffset:16_796_864); try writer.close()
      f.selection = [url]
      let selected = try f.row("chooseSource", ["purpose":"backup-source"])
      let choice = try f.handle(selected,"choiceId")
      guard let files = selected["files"] as? [[String:Any]], files.count == 1 else { throw CheckFailure.assertion("one backup source, never attachment multiple selection") }
      let selection = try f.handle(files[0],"selectionId")
      try check(files[0]["size"] as? Int == 16_796_864, "inclusive maximum ciphertext source extent")
      try refuses { _ = try f.row("claimSource", ["choiceId":choice,"selectionId":selection,"size":16_796_864]) }
      let claim: [String:Any] = ["purpose":"backup-source", "sourceContext":"backup-import/\(f.gate.currentEpoch)/1", "choiceId":choice,"selectionId":selection,"size":16_796_864]
      let handle = try f.handle(f.row("claimSource",claim)); try refuses { _ = try f.row("claimSource",claim) }
      guard let chunk = try f.call("readSource",["handle":handle,"offset":0,"length":65_536]) as? Data else { throw CheckFailure.assertion("bounded actual ciphertext range") }
      try check(chunk.count == 65_536, "read cap is64KiB")
      try refuses { _ = try f.call("readSource",["handle":handle,"offset":0,"length":65_537]) }
      _ = try f.row("closeSource",["handle":handle])
      let oversized = try FileHandle(forWritingTo:url); try oversized.truncate(atOffset:16_796_865); try oversized.close()
      try refuses { _ = try f.row("chooseSource",["purpose":"backup-source"]) }
    }
    test("backup native chooser cancellation and late revoke completion remain once only") {
      let f = try AsyncFixture(); try owner(f.base)
      let done = DispatchSemaphore(value:0), calls = RaceValue(0), result = RaceValue<Result<Any,Error>?>(nil)
      try f.start("chooseDestination",["purpose":"backup-export"]) { result.set($0);calls.set(calls.get()+1);done.signal() }
      try check(f.chooser.entered.wait(timeout:.now()+2) == .success,"dedicated backup purpose reaches actual native chooser")
      let callback = f.chooser.completion.get();callback?(.success(nil));callback?(.success(nil))
      try check(done.wait(timeout:.now()+2) == .success && calls.get() == 1,"cancel callback delivered once")
      guard case .success(let any)? = result.get(), let text = any as? String else { throw CheckFailure.assertion("native chooser cancellation result") }
      try check(text.contains("cancelled"),"cancellation is not backup publication")
      let revoked = DispatchSemaphore(value:0), lateCalls = RaceValue(0), refused = RaceValue(false)
      try f.start("chooseSource",["purpose":"backup-source"]) { if case .failure = $0 { refused.set(true) };lateCalls.set(lateCalls.get()+1);revoked.signal() }
      try check(f.chooser.entered.wait(timeout:.now()+2) == .success,"second explicit source intent started")
      let late = f.chooser.completion.get();f.base.gate.lock();late?(.success(nil));late?(.success(nil))
      try check(revoked.wait(timeout:.now()+2) == .success && refused.get() && lateCalls.get() == 1,"revoke invalidates old chooser callback exactly once")
    }
    test("headless backup intent refuses before chooser while fresh visible owner can continue") {
      let f = try Fixture();f.selection = [f.destination]
      f.gate.foreground(ownerSceneID:nil,active:false)
      try refuses { _ = try f.row("chooseDestination",["purpose":"backup-export"]) }
      try check(f.pickerCalls == 0,"no headless picker")
      try owner(f);_ = try f.row("chooseDestination",["purpose":"backup-export"])
      try check(f.pickerCalls == 1,"fresh explicit native owner may select")
    }
    test("explicit backup cancellation clears only its exact metadata and stale cleanup preserves continuation") {
      let f = try Fixture(); try owner(f); f.selection = [f.destination]
      let intent: [String:Any] = ["purpose":"backup-export"]
      let choice = try f.handle(f.row("chooseDestination",intent),"choiceId"), old = f.gate.currentEpoch
      f.gate.foreground(ownerSceneID:"owned-scene",active:false); try owner(f)
      try refuses { _ = try f.row("discardBackupChoice",["purpose":"backup-export","choiceId":choice],expected:old) }
      try check(try f.handle(f.row("pendingChoice",intent),"choiceId") == choice,"scope loss retains only owned metadata for explicit fresh continuation")
      try refuses { _ = try f.row("discardBackupChoice",["purpose":"backup-source","choiceId":choice]) }
      _ = try f.row("discardBackupChoice",["purpose":"backup-export","choiceId":choice])
      _ = try f.row("discardBackupChoice",["purpose":"backup-export","choiceId":choice])
      try check(try f.row("pendingChoice",intent)["choiceId"] == nil && f.ownedFiles().isEmpty && f.outputOpens == 0,"explicit cancellation is idempotent and does not stage or publish")
    }
    test("explicit cancel targets the owned pending chooser and late completion cannot poison its successor") {
      let f = try AsyncFixture(); try owner(f.base)
      let entered = DispatchSemaphore(value:0), calls = RaceValue(0), refused = RaceValue(false)
      func request() throws -> String {
        guard let raw = try f.files.dispatch("beginBackupChoice",frame:f.base.frame(["purpose":"backup-export"]),bytes:Data(),expected:f.base.gate.currentEpoch) as? String,
          let row = try JSONSerialization.jsonObject(with:Data(raw.utf8)) as? [String:Any] else { throw CheckFailure.assertion("native-issued metadata request") }
        return try f.base.handle(row,"requestId")
      }
      let first = try request()
      try f.start("chooseDestination",["purpose":"backup-export","requestId":first]) { if case .failure = $0 { refused.set(true) };calls.set(calls.get()+1);entered.signal() }
      try check(f.chooser.entered.wait(timeout:.now()+2) == .success,"real native chooser was pending before explicit cancel")
      let late = f.chooser.completion.get()
      defer { f.base.gate.lock() }
      _ = try f.files.dispatch("discardBackupChoice",frame:f.base.frame(["purpose":"backup-export","requestId":first]),bytes:Data(),expected:f.base.gate.currentEpoch)
      try check(entered.wait(timeout:.now()+2) == .success && refused.get() && calls.get() == 1,"explicit cancel completes only the cancelled request")
      let second = try request(), done = DispatchSemaphore(value:0), nextCalls = RaceValue(0)
      try f.start("chooseDestination",["purpose":"backup-export","requestId":second]) { _ in nextCalls.set(nextCalls.get()+1);done.signal() }
      try check(f.chooser.entered.wait(timeout:.now()+2) == .success,"new explicit request remains usable")
      let current = f.chooser.completion.get()
      late?(.success(MeshMessengerProtectedSelection(.documents([f.base.destination]),context:SelectionContext(f.base.gate))))
      late?(.success(nil))
      guard let pending = try f.files.dispatch("pendingChoice",frame:f.base.frame(["purpose":"backup-export"]),bytes:Data(),expected:f.base.gate.currentEpoch) as? String else { throw CheckFailure.assertion("pending metadata response") }
      try check(!pending.contains("choiceId") && nextCalls.get() == 0,"late cancelled completion neither stores a selection nor cancels new chooser")
      current?(.success(nil));try check(done.wait(timeout:.now()+2) == .success && nextCalls.get() == 1,"fresh native chooser can complete normally")
    }
    test("native chooser cancellation releases bounded request capacity without renewing old choices") {
      let f = try AsyncFixture(); try owner(f.base)
      for _ in 0..<5 {
        let done = DispatchSemaphore(value:0), result = RaceValue<Result<Any,Error>?>(nil)
        try f.start("chooseDestination",["purpose":"backup-export"]) { result.set($0);done.signal() }
        try check(f.chooser.entered.wait(timeout:.now()+2) == .success,"each explicit chooser reaches native provider")
        f.chooser.completion.get()?(.success(nil))
        try check(done.wait(timeout:.now()+2) == .success,"cancelled chooser completes")
        guard case .success(let any)? = result.get(), let text = any as? String, text.contains("cancelled") else { throw CheckFailure.assertion("native Cancel must not consume request capacity until expiry") }
      }
      try check(f.chooser.calls.get() == 5,"ordinary repeated Cancel remains usable within the same owner epoch")
    }
    print("RESULT \(8-failures)/8 backup-intent groups passed")
    if failures != 0 { exit(1) }
  }

  // Synthetic profile frame emitted by actual src/codec.ts vectors and accepted
  // by parseProfileSummary. This tests native framing, not directory custody.
  static func runProfileFraming() {
    var failures = 0
    func test(_ name: String, _ body: () throws -> Void) {
      do { try body(); print("PASS \(name)") } catch { failures += 1; print("FAIL \(name): \(error)") }
    }
    func owner(_ f: Fixture) throws {
      try DispatchQueue.main.sync { try f.gate.activate(f.gate.currentEpoch, ownerSceneID: "owned-scene") }
    }
    let canonical = Data(base64Encoded: "AAAADU93bmVkIGZpeHR1cmUAAAAgAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAQAgICAgICAgICAgICAgICAgAAAAA=")!
    func maximum() -> Data { packet([Data(repeating: 65, count: 64), Data(repeating: 1, count: 32), Data(repeating: 2, count: 16), Data(repeating: 7, count: 36_006)]) }
    test("actual codec four vector profile binds preferences and backup intent without picker IO") {
      let f = try Fixture(profile: canonical); try owner(f); let expected = f.gate.currentEpoch
      try check(f.profile == packet([Data("Owned fixture".utf8), Data(repeating: 1, count: 32), Data(repeating: 2, count: 16), Data()]), "actual codec vector bytes")
      let target = f.documents.appendingPathComponent("read-state-" + String(repeating: "01", count: 32) + ".json")
      try Data("owned-read-status".utf8).write(to: target)
      try check(f.files.readLegacy(canonical, kind: "read-state", expected: expected) == "owned-read-status", "canonical profile reads its exact own preference")
      _ = try f.handle(f.row("beginBackupChoice", ["purpose": "backup-export"]), "requestId")
      try check(f.pickerCalls == 0 && f.outputOpens == 0, "binding performs no chooser or output IO")
    }
    test("exact 36134 byte codec frame remains admitted by native identity binding") {
      let value = maximum(), digest = SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined()
      try check(value.count == 36_134 && digest == "68551975240a1d1a1904d1b71c628717f70cd68d4d26f42c3911390d8ea771fa", "actual codec maximum byte oracle")
      let f = try Fixture(profile: value); try owner(f); let expected = f.gate.currentEpoch
      try check(f.files.readLegacy(value, kind: "read-state", expected: expected) == nil, "valid maximum missing preference is absence")
      _ = try f.handle(f.row("beginBackupChoice", ["purpose": "backup-source"]), "requestId")
    }
    test("count prefixed truncated trailing oversized and wrong identity length profiles refuse before IO") {
      let malformed = [Data([0,0,0,4]) + canonical, Data(canonical.dropLast()), canonical + Data([0]), maximum() + Data([0]),
        packet([Data("Owned fixture".utf8), Data(repeating: 1, count: 31), Data(repeating: 2, count: 16), Data()]),
        packet([Data("Owned fixture".utf8), Data(repeating: 1, count: 32), Data(repeating: 2, count: 15), Data()]),
        packet([Data(repeating: 65, count: 65), Data(repeating: 1, count: 32), Data(repeating: 2, count: 16), Data()]),
        packet([Data("Owned fixture".utf8), Data(repeating: 1, count: 32), Data(repeating: 2, count: 16), Data(repeating: 7, count: 36_007)])]
      for value in malformed {
        let f = try Fixture(profile: value); try owner(f); let expected = f.gate.currentEpoch
        try refuses { _ = try f.files.readLegacy(value, kind: "read-state", expected: expected) }
        try refuses { _ = try f.row("beginBackupChoice", ["purpose": "backup-export"]) }
        try check(f.pickerCalls == 0 && f.outputOpens == 0 && f.ownedFiles().isEmpty, "malformed profiles have no IO side effect")
      }
    }
    print("RESULT \(3 - failures)/3 profile-framing groups passed")
    if failures != 0 { exit(1) }
  }

}
