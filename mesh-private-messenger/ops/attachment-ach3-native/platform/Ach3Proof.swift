import UIKit
import Foundation

// Isolated terminal-driven ACH3 native proof. Only fixture-owned accounts and content.
@main
final class Ach3ProofApp: UIResponder, UIApplicationDelegate {
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
      let path = Data(directory.appendingPathComponent("ach3.db").path.utf8)
      _ = try MeshLibrary.initialize(path)
      let second = Data(directory.appendingPathComponent("legacy.db").path.utf8)
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
          case "create": value = try MeshLibrary.create_account_export(vector(path) + vector(Data("ach3_fixture".utf8)))
          case "create-other": value = try MeshLibrary.create_account_export(vector(second) + vector(Data("legacy_fixture".utf8)))
          case "erase-other": value = try MeshLibrary.erase_account_export(second)
          case "erase": value = try MeshLibrary.erase_account_export(path)
          case "install": value = try MeshLibrary.install_fixture(packet([path,body]))
          case "install-other": value = try MeshLibrary.install_fixture(packet([second,body]))
          case "ticket": value = try MeshLibrary.fixture_ticket(packet([path]))
          case "ticket-other": value = try MeshLibrary.fixture_ticket(packet([second]))
          case "require": value = try MeshLibrary.fixture_require(packet([path,body]))
          case "require-other": value = try MeshLibrary.fixture_require(packet([second,body]))
          case "free-prepare": value = try MeshLibrary.attachment_prepare_export(vector(path) + vector(Data("free-fixture.bin".utf8)) + vector(Data("application/octet-stream".utf8)) + vector(body) + vector(Data([0,0,0,1])))
          case "free-seal": value = try MeshLibrary.attachment_seal_chunk_export(vector(path) + vector(body) + vector(id) + vector(Data(repeating: 37, count: id == Data([0,0,0,0]) ? 65536 : 1)))
          case "free-upload": value = try MeshLibrary.attachment_upload_export(packet([path,Data("free-upload.bin".utf8),Data("application/octet-stream".utf8),Data(repeating:37,count:65537),body]))
          case "free-upload-other": value = try MeshLibrary.attachment_upload_export(packet([second,Data("free-upload.bin".utf8),Data("application/octet-stream".utf8),Data(repeating:37,count:65537),body]))
          case "free-upload-one": value = try MeshLibrary.attachment_upload_export(packet([path,Data("free-upload.bin".utf8),Data("application/octet-stream".utf8),Data(repeating:37,count:1),body]))
          case "old-upload": value = try MeshLibrary.attachment_upload_export(packet([path,Data("old.bin".utf8),Data("application/octet-stream".utf8),Data([37])]))
          case "preview": value = try MeshLibrary.credit_attachment_preview_export(packet([path,body]))
          case "prepare": value = try MeshLibrary.credit_attachment_prepare_export(packet([path,id,Data("paid-fixture.bin".utf8),Data("application/octet-stream".utf8),Data([1,0,0,1]),body]))
          case "prepare-other": value = try MeshLibrary.credit_attachment_prepare_export(packet([second,id,Data("paid-fixture.bin".utf8),Data("application/octet-stream".utf8),Data([1,0,0,1]),body]))
          case "old-prepare": value = try MeshLibrary.credit_attachment_prepare_export(packet([path,id,Data("old.bin".utf8),Data("application/octet-stream".utf8),Data([1,0,0,1])]))
          case "inventory": value = try MeshLibrary.credit_attachments_export(packet([path]))
          case "inventory-other": value = try MeshLibrary.credit_attachments_export(packet([second]))
          case "reference": value = try MeshLibrary.paid_reference(packet([path,id]))
          case "paid-seal": value = try MeshLibrary.credit_attachment_part_export(packet([path,id,body,Data(repeating:37,count:body == Data([0,0,0,0]) ? 65536 : 1)]))
          case "paid-recover": value = try MeshLibrary.credit_attachment_part_recover_export(packet([path,id,body]))
          case "fetch": value = try MeshLibrary.attachment_fetch_chunk_export(packet([path,body,id]))
          case "alternate": value = try MeshLibrary.alternate_reference(packet([path,body]))
          case "legacy": value = try MeshLibrary.legacy_fixture(packet([path,body]))
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
