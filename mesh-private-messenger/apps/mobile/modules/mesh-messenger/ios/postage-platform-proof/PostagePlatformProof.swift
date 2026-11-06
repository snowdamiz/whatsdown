import UIKit
import Foundation

// Owned simulator proof only. File commands drive exact compiled production
// exports; the fixture coordinator supplies the local issuer's HTTP replies.
@main
final class PostagePlatformProofApp: UIResponder, UIApplicationDelegate {
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
      let path = Data(directory.appendingPathComponent("postage-platform-proof.db").path.utf8)
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
          case "create": value = try MeshLibrary.create_account_export(vector(path) + vector(body.isEmpty ? Data("native-postage".utf8) : body))
          case "register": value = try MeshLibrary.directory_register_export(path)
          case "profile": value = try MeshLibrary.load_profile_export(path)
          case "resolve": value = try MeshLibrary.directory_resolve_export(vector(path) + vector(body))
          case "fanout": value = try MeshLibrary.fanout_send_export(vector(path) + vector(id) + body)
          case "outbox": value = try MeshLibrary.outbox_list_export(path)
          case "drain": value = try MeshLibrary.outbox_drain_export(vector(path) + vector(body))
          case "postage-candidate": value = try MeshLibrary.credit_postage_candidate_export(packet([path, id]))
          case "postage-preview": value = try MeshLibrary.credit_postage_preview_export(Data([0, 0, 0, 3]) + vector(path) + body)
          case "postage-prepare": value = try MeshLibrary.credit_postage_prepare_export(Data([0, 0, 0, 4]) + vector(path) + body)
          case "postage-recover": value = try MeshLibrary.credit_postage_recover_export(packet([path, id]))
          case "postage-continue": value = try MeshLibrary.credit_postage_continue_export(packet([path, id]))
          case "postage-inventory": value = try MeshLibrary.credit_postage_inventory_export(packet([path]))
          case "retention": value = try MeshLibrary.credit_retention_export(packet([path, body]))
          case "retention-recover": value = try MeshLibrary.credit_retention_recover_export(packet([path, id]))
          case "action": value = try MeshLibrary.credit_action_continue_export(packet([path, id, body]))
          case "discover": value = try MeshLibrary.credit_discover_online_export(packet([path]))
          case "continue": value = try MeshLibrary.credit_purchase_continue_export(packet([path, id]))
          case "admit": value = try MeshLibrary.credit_admit_export(packet([path, body]))
          case "prepare": value = try MeshLibrary.credit_prepare_export(packet([path, Data([0, 0, 0, 100]), Data([2])]))
          case "quote": value = try MeshLibrary.credit_quote_export(packet([path, id, body]))
          case "handoff": value = try MeshLibrary.credit_payment_handoff_export(packet([path, id]))
          case "recover": value = try MeshLibrary.credit_recover_export(packet([path, id]))
          case "finalize": value = try MeshLibrary.credit_finalize_export(packet([path, id, body]))
          case "balance": value = try MeshLibrary.credit_balance_export(packet([path]))
          default: throw Failure.invalid
          }
          let output = ["result": "passed", "body": value.map { String(format: "%02x", $0) }.joined()]
          try JSONSerialization.data(withJSONObject: output).write(to: response, options: .atomic)
        } catch {
          let detail = (error as? MeshLibraryFailure).flatMap { String(data: $0.payload, encoding: .utf8) } ?? String(describing: error)
          try JSONSerialization.data(withJSONObject: ["result": "rejected", "error": detail]).write(to: response, options: .atomic)
        }
      }
    } catch {
      try? JSONSerialization.data(withJSONObject: ["result": "failed", "error": String(describing: error)]).write(to: directory.appendingPathComponent("fatal.json"), options: .atomic)
    }
  }
}
