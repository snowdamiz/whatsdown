import UIKit
import Foundation

// Owned simulator proof for five typed account/device exports and OS custody.
@main
final class AccountProofApp: UIResponder, UIApplicationDelegate {
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
      let path = Data(directory.appendingPathComponent("account-proof.db").path.utf8)
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
          case "capabilities": value = try MeshLibrary.account_capabilities_export(vector(path) + vector(id))
          case "delete": value = try MeshLibrary.account_delete_export(vector(path) + vector(id))
          case "discard": value = try MeshLibrary.account_discard_export(vector(path) + vector(id))
          case "bad-capabilities": value = try MeshLibrary.account_capabilities_export(vector(path) + vector(id) + Data([0]))
          case "bad-delete": value = try MeshLibrary.account_delete_export(vector(path))
          case "bad-renew": value = try MeshLibrary.devices_renew_export(vector(path))
          case "bad-revoke": value = try MeshLibrary.device_revoke_export(vector(path) + vector(Data([1])) + vector(Data(repeating: 2, count: 15)))
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
