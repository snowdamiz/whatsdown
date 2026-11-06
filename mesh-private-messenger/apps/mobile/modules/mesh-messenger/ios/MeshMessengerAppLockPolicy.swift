import Foundation
import Security
import LocalAuthentication
import Darwin

protocol MeshMessengerAppLockPolicyStorage {
  func readMarker() throws -> Data?
  func createMarker(_ data: Data) throws
  func readRecord() throws -> Data?
  func createRecord(_ data: Data) throws
  func updateRecord(_ data: Data) throws
}

final class MeshMessengerAppLockPolicy {
  struct Record: Equatable {
    let install: String
    let sequence: Int64
    let policy: String
  }
  enum Failure: Error, Equatable { case policyUnreadable, policyChanged, backgroundRequired }
  // All instances use the same process-local writer. Revocation and covering
  // belong to the controller and must never wait on this persistence lock.
  private static let writer = NSLock()
  private static let maximumSequence: Int64 = 9_007_199_254_740_990
  private static let policies: Set<String> = ["disabled", "enable_pending", "enabled", "disable_pending"]
  private let storage: MeshMessengerAppLockPolicyStorage
  private let makeInstall: () -> String

  convenience init() throws {
    guard !Thread.isMainThread else { throw Failure.backgroundRequired }
    guard let bundle = Bundle.main.bundleIdentifier, !bundle.isEmpty else { throw Failure.policyUnreadable }
    let root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    try self.init(storage: MeshMessengerAppLockKeychainStorage(service: bundle + ".app-lock.v1", directory: root.appendingPathComponent("morse-app-lock-v1", isDirectory: true)))
  }

  init(storage: MeshMessengerAppLockPolicyStorage, makeInstall: @escaping () -> String = { UUID().uuidString.lowercased() }) {
    self.storage = storage
    self.makeInstall = makeInstall
  }

  func load() throws -> Record {
    guard !Thread.isMainThread else { throw Failure.backgroundRequired }
    Self.writer.lock(); defer { Self.writer.unlock() }
    return try loadLocked()
  }

  func transition(previous: Record, desired: String) throws -> Record {
    guard !Thread.isMainThread else { throw Failure.backgroundRequired }
    Self.writer.lock(); defer { Self.writer.unlock() }
    let actual = try loadLocked()
    guard actual == previous else { throw Failure.policyChanged }
    guard previous.sequence < Self.maximumSequence, Self.permits(previous.policy, desired) else { throw Failure.policyUnreadable }
    let next = Record(install: previous.install, sequence: previous.sequence + 1, policy: desired)
    try storage.updateRecord(Self.encode(next))
    return try verify(next)
  }

  private static func permits(_ previous: String, _ desired: String) -> Bool {
    // Every policy change first records a pending state. Authentication and
    // notification draining are the controller's obligations before completion.
    if desired == "enable_pending" { return previous == "disabled" || previous == "enable_pending" || previous == "disable_pending" }
    if desired == "disable_pending" { return previous == "enabled" || previous == "enable_pending" || previous == "disable_pending" }
    return (previous == "enable_pending" && desired == "enabled") || (previous == "disable_pending" && desired == "disabled")
  }

  private func loadLocked() throws -> Record {
    // A read error is never absence. Do not create anything until BOTH reads
    // succeeded, so unavailable Keychain/marker storage cannot reset policy.
    let mark = try storage.readMarker()
    let bytes = try storage.readRecord()
    if let bytes {
      let record = try Self.decode(bytes)
      if let mark {
        guard mark == Self.marker(record.install) else { throw Failure.policyUnreadable }
      } else {
        // The surviving authenticated Keychain record remains authoritative.
        try storage.createMarker(Self.marker(record.install))
        guard try storage.readMarker() == Self.marker(record.install) else { throw Failure.policyUnreadable }
      }
      return record
    }
    guard mark == nil else { throw Failure.policyUnreadable }
    let install = makeInstall()
    guard Self.validInstall(install) else { throw Failure.policyUnreadable }
    let initial = Record(install: install, sequence: 0, policy: "disabled")
    // Never remove this marker when creation or readback fails. A subsequent
    // missing record is an interrupted initialization, not a fresh install.
    try storage.createMarker(Self.marker(install))
    guard try storage.readMarker() == Self.marker(install) else { throw Failure.policyUnreadable }
    try storage.createRecord(Self.encode(initial))
    return try verify(initial)
  }

  private func verify(_ expected: Record) throws -> Record {
    guard let bytes = try storage.readRecord(), try Self.decode(bytes) == expected,
          try storage.readMarker() == Self.marker(expected.install) else { throw Failure.policyUnreadable }
    return expected
  }

  private static func validInstall(_ value: String) -> Bool {
    value.count == 36 && UUID(uuidString: value)?.uuidString.lowercased() == value
  }
  private static func marker(_ install: String) -> Data { Data("AL1:\(install)\n".utf8) }
  private static func encode(_ record: Record) -> Data {
    Data("{\"version\":1,\"install\":\"\(record.install)\",\"sequence\":\(record.sequence),\"policy\":\"\(record.policy)\"}".utf8)
  }
  private static func decode(_ bytes: Data) throws -> Record {
    guard (1...4096).contains(bytes.count),
          let object = try? JSONSerialization.jsonObject(with: bytes), let row = object as? [String: Any],
          Set(row.keys) == ["version", "install", "sequence", "policy"],
          let version = row["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
          let install = row["install"] as? String, validInstall(install),
          let sequence = row["sequence"] as? NSNumber, CFGetTypeID(sequence) != CFBooleanGetTypeID(),
          let policy = row["policy"] as? String, policies.contains(policy) else { throw Failure.policyUnreadable }
    let record = Record(install: install, sequence: sequence.int64Value, policy: policy)
    // Native policy has one canonical encoding. Exact equality rejects duplicate
    // fields, fractional/exponent numbers, unknown fields and trailing bytes.
    guard (0...maximumSequence).contains(record.sequence), encode(record) == bytes else { throw Failure.policyUnreadable }
    return record
  }
}

/// A distinct installation policy item. No account, wallet or Mesh key aliases.
private final class MeshMessengerAppLockKeychainStorage: MeshMessengerAppLockPolicyStorage {
  private let service: String
  private let marker: MeshMessengerAppLockPolicyMarker
  init(service: String, directory: URL) throws {
    guard !Thread.isMainThread, !service.isEmpty else { throw MeshMessengerAppLockPolicy.Failure.backgroundRequired }
    self.service = service
    self.marker = try MeshMessengerAppLockPolicyMarker(directory: directory)
  }
  private var query: [String: Any] {
    let context = LAContext()
    context.interactionNotAllowed = true
    return [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
     kSecAttrAccount as String: "policy", kSecAttrSynchronizable as String: false,
     kSecUseAuthenticationContext as String: context]
  }
  func readMarker() throws -> Data? { try marker.read() }
  func createMarker(_ data: Data) throws { try marker.create(data) }
  func readRecord() throws -> Data? {
    var search = query
    // A wrongly synchronized or duplicate item is an invalid policy, not
    // positive absence that permits creating a new disabled installation.
    search[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
    search[kSecReturnData as String] = true
    search[kSecReturnAttributes as String] = true
    search[kSecMatchLimit as String] = kSecMatchLimitAll
    var output: CFTypeRef?
    let status = SecItemCopyMatching(search as CFDictionary, &output)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let rows = output as? [[String: Any]], rows.count == 1,
          let bytes = rows[0][kSecValueData as String] as? Data, (1...4096).contains(bytes.count),
          let synchronized = rows[0][kSecAttrSynchronizable as String] as? NSNumber, synchronized == 0,
          rows[0][kSecAttrAccessible as String] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String else {
      throw MeshMessengerAppLockPolicy.Failure.policyUnreadable
    }
    return bytes
  }
  func createRecord(_ data: Data) throws {
    var item = query
    item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    item[kSecValueData as String] = data
    guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
  }
  func updateRecord(_ data: Data) throws {
    let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
    // Missing must remain missing. Never implement update failure as an upsert.
    guard SecItemUpdate(query as CFDictionary, attributes as CFDictionary) == errSecSuccess else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
  }
}

/// Marker-first initialization survives a crash independently of Keychain.
/// The marker is nonsecret, backup-excluded and bound to the policy's install ID.
final class MeshMessengerAppLockPolicyMarker {
  private let directory: URL
  private let descriptor: Int32
  private let name = "policy-initialized.v1"
  init(directory: URL) throws {
    guard !Thread.isMainThread, directory.isFileURL else { throw MeshMessengerAppLockPolicy.Failure.backgroundRequired }
    self.directory = directory
    let made = Darwin.mkdir(directory.path, mode_t(0o700))
    guard made == 0 || errno == EEXIST else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    let fd = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    do {
      guard Darwin.fchmod(fd, mode_t(0o700)) == 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      var values = URLResourceValues(); values.isExcludedFromBackup = true
      var owned = directory; try owned.setResourceValues(values)
      guard try owned.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      #if os(iOS)
      try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: directory.path)
      #endif
      guard Darwin.fsync(fd) == 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      if made == 0 {
        let parent = Darwin.open(directory.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
        defer { Darwin.close(parent) }
        guard Darwin.fsync(parent) == 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      }
    } catch { Darwin.close(fd); throw error }
    descriptor = fd
  }
  deinit { Darwin.close(descriptor) }
  func read() throws -> Data? {
    let fd = Darwin.openat(descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 && errno == ENOENT { return nil }
    guard fd >= 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    defer { Darwin.close(fd) }
    var info = stat()
    guard Darwin.fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
          info.st_nlink == 1, info.st_uid == geteuid(), (1...128).contains(info.st_size),
          (info.st_mode & 0o777) == 0o600 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    var bytes = [UInt8](repeating: 0, count: Int(info.st_size)); var offset = 0
    while offset < bytes.count {
      let remaining = bytes.count - offset
      let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), remaining) }
      if count < 0 && errno == EINTR { continue }
      guard count > 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      offset += count
    }
    var extra: UInt8 = 0
    guard Darwin.read(fd, &extra, 1) == 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    return Data(bytes)
  }
  func create(_ bytes: Data) throws {
    guard (1...128).contains(bytes.count) else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    let fd = Darwin.openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
    guard fd >= 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
    defer { Darwin.close(fd) }
    var offset = 0
    while offset < bytes.count {
      let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
      if count < 0 && errno == EINTR { continue }
      guard count > 0 else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
      offset += count
    }
    // Never unlink on failure: even a partial marker records an interrupted
    // bootstrap and must not turn back into positively absent state.
    guard Darwin.fsync(fd) == 0, Darwin.fsync(descriptor) == 0, try read() == bytes else { throw MeshMessengerAppLockPolicy.Failure.policyUnreadable }
  }
}
