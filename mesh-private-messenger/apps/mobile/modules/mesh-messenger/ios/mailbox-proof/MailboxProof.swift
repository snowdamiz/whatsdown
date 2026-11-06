import UIKit
import Foundation

@main
final class MailboxProofApp: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    window = UIWindow(frame: UIScreen.main.bounds)
    window?.rootViewController = UIViewController()
    window?.makeKeyAndVisible()
    DispatchQueue.global().async {
      let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
      do {
        try self.prove(directory)
        try Data("{\"result\":\"passed\",\"exports\":3,\"signed_sessions\":3}".utf8).write(to: directory.appendingPathComponent("result.json"))
      } catch {
        let detail = (error as? MeshLibraryFailure).flatMap { String(data: $0.payload, encoding: .utf8) } ?? String(describing: error)
        let result = try? JSONSerialization.data(withJSONObject: ["result": "failed", "error": detail])
        try? result?.write(to: directory.appendingPathComponent("result.json"))
      }
    }
    return true
  }
  enum Failure: Error { case invalid(String) }
  nonisolated private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure.invalid(message) }
  }
  nonisolated private func vector(_ value: Data) -> Data {
    var count = UInt32(value.count).bigEndian
    return Data(bytes: &count, count: 4) + value
  }
  nonisolated private func packet(_ fields: [Data]) -> Data {
    var count = UInt32(fields.count).bigEndian
    return fields.reduce(Data(bytes: &count, count: 4)) { $0 + vector($1) }
  }
  nonisolated private func rejected(_ operation: () throws -> Data) throws {
    do { _ = try operation() }
    catch let failure as MeshLibraryFailure {
      try require(String(data: failure.payload, encoding: .utf8)?.contains("mailbox") == true, "unexpected rejection")
      return
    }
    throw Failure.invalid("native accepted invalid session")
  }
  nonisolated private func prove(_ directory: URL) throws {
    try MeshLibrary.initialize()
    try require(MeshMessengerRegisterAppleHostCallbacks() == 0, "host callback registration")
    let path = Data(directory.appendingPathComponent("mailbox-proof.db").path.utf8)
    _ = try MeshLibrary.initialize(path)
    _ = try MeshLibrary.create_account_export(vector(path) + vector(Data("alice".utf8)))
    let entry = try MeshLibrary.directory_entry_export(path)
    try Data(entry.map { String(format: "%02x", $0) }.joined().utf8).write(to: directory.appendingPathComponent("profile-entry.hex"))
    let ready = directory.appendingPathComponent("server-ready")
    let deadline = Date().addingTimeInterval(120)
    while !FileManager.default.fileExists(atPath: ready.path) && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
    try require(FileManager.default.fileExists(atPath: ready.path), "owned peer did not start")
    let first = try MeshLibrary.mailbox_stream_open_export(path)
    try require(first.count == 32, "ticket length")
    try require(String(data: MeshLibrary.mailbox_stream_poll_export(packet([path, first])), encoding: .utf8) == "ready", "readiness")
    try require(String(data: MeshLibrary.mailbox_stream_poll_export(packet([path, first])), encoding: .utf8) == "encrypted-wakeup", "wakeup")
    let second = try MeshLibrary.mailbox_stream_open_export(path)
    try require(first != second, "ticket reuse")
    try rejected { try MeshLibrary.mailbox_stream_poll_export(self.packet([path, first])) }
    try rejected { try MeshLibrary.mailbox_stream_poll_export(self.packet([Data("other.db".utf8), second])) }
    try rejected { try MeshLibrary.mailbox_stream_poll_export(self.packet([path, second]) + Data([1])) }
    _ = try MeshLibrary.mailbox_stream_close_export(packet([path, second]))
    try rejected { try MeshLibrary.mailbox_stream_poll_export(self.packet([path, second])) }
    let erased = try MeshLibrary.mailbox_stream_open_export(path)
    _ = try MeshLibrary.erase_account_export(path)
    try rejected { try MeshLibrary.mailbox_stream_poll_export(self.packet([path, erased])) }
  }
}
