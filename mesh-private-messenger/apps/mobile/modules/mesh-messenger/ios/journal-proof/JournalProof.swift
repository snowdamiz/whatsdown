import UIKit
import Foundation

// Owned simulator proof for account-bound journal exports and OS custody.
@main
final class JournalProofApp: UIResponder, UIApplicationDelegate {
  var window: UIWindow?
  func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    window = UIWindow(frame: UIScreen.main.bounds)
    window?.rootViewController = UIViewController()
    window?.makeKeyAndVisible()
    DispatchQueue.global().async { self.run() }
    return true
  }
  enum Failure: Error { case invalid }
  nonisolated private func vector(_ value: Data) -> Data {
    var count = UInt32(value.count).bigEndian
    return Data(bytes: &count, count: 4) + value
  }
  nonisolated private func packet(_ fields: [Data]) -> Data {
    var count = UInt32(fields.count).bigEndian
    return fields.reduce(Data(bytes: &count, count: 4)) { $0 + vector($1) }
  }
  nonisolated private func hex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    guard bytes.count % 2 == 0, bytes.count <= 1_200_000 else { throw Failure.invalid }
    var output = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
      guard let value = UInt8(String(decoding: bytes[index..<index+2], as: UTF8.self), radix: 16) else { throw Failure.invalid }
      output.append(value)
    }
    return output
  }
  nonisolated private func run() {
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    do {
      try MeshLibrary.initialize()
      guard MeshMessengerRegisterAppleHostCallbacks() == 0 else { throw Failure.invalid }
      let path = Data(directory.appendingPathComponent("journal-proof.db").path.utf8)
      _ = try MeshLibrary.initialize(path)
      let command = directory.appendingPathComponent("command.json")
      let response = directory.appendingPathComponent("response.json")
      try Data("ready".utf8).write(to: directory.appendingPathComponent("ready"), options: .atomic)
      while true {
        guard FileManager.default.fileExists(atPath: command.path) else { Thread.sleep(forTimeInterval: 0.02); continue }
        let input = try Data(contentsOf: command)
        try FileManager.default.removeItem(at: command)
        do {
          guard let fields = try JSONSerialization.jsonObject(with: input) as? [String: String], let operation = fields["operation"] else { throw Failure.invalid }
          let id = try hex(fields["id"] ?? "")
          let body = try hex(fields["body"] ?? "")
          let value: Data
          switch operation {
          case "create": value = try MeshLibrary.create_account_export(vector(path) + vector(body.isEmpty ? Data("account_a".utf8) : body))
          case "profile": value = try MeshLibrary.load_profile_export(path)
          case "discard": value = try MeshLibrary.account_discard_export(vector(path) + vector(id))
          case "read": value = try MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector(Data("read-state/index".utf8)))
          case "write": value = try MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector(Data("read-state/index".utf8)) + vector(body))
          case "bad-load": value = try MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector(Data("read-state/index".utf8)) + Data([0]))
          case "bad-write": value = try MeshLibrary.journal_save_bound_export(vector(path) + vector(id))
          case "bad-key": value = try MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector(Data("profile/v1".utf8)) + vector(body))
          case "preview": value = try MeshLibrary.journal_save_bound_export(vector(path) + vector(id) + vector(Data("preferences/notification-preview".utf8)) + vector(body))
          case "read-preview": value = try MeshLibrary.journal_load_bound_export(vector(path) + vector(id) + vector(Data("preferences/notification-preview".utf8)))
          default: throw Failure.invalid
          }
          let output = ["result": "passed", "body": value.map { String(format: "%02x", $0) }.joined()]
          try JSONSerialization.data(withJSONObject: output).write(to: response, options: .atomic)
        } catch {
          let detail = error.localizedDescription
          try JSONSerialization.data(withJSONObject: ["result": "rejected", "error": detail]).write(to: response, options: .atomic)
        }
      }
    } catch {
      try? JSONSerialization.data(withJSONObject: ["result": "failed", "error": String(describing: error)]).write(to: directory.appendingPathComponent("fatal.json"), options: .atomic)
    }
  }
}
