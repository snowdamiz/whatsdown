import UIKit
import Foundation
import CryptoKit

// Owned simulator proof only. The production Mesh core performs all HTTP;
// this harness hashes plaintext outputs to check complete-file round trips.
@main
final class AttachmentProofApp: UIResponder, UIApplicationDelegate {
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
      let path = Data(directory.appendingPathComponent("attachment-proof.db").path.utf8)
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
          case "create": value = try MeshLibrary.create_account_export(vector(path) + vector(Data("native-attachments".utf8)))
          case "upload":
            guard body.count == 4 else { throw Failure.invalid }
            let size = body.reduce(0) { ($0 << 8) | Int($1) }
            guard (1...16_777_216).contains(size) else { throw Failure.invalid }
            value = try MeshLibrary.attachment_upload_export(packet([path,Data("fixture.bin".utf8),Data("application/octet-stream".utf8),Data(repeating:37,count:size)]))
          case "read_all":
            guard id.count == 4 else { throw Failure.invalid }
            let count = id.reduce(0) { ($0 << 8) | Int($1) }
            guard (1...256).contains(count) else { throw Failure.invalid }
            var hash = SHA256()
            var total: UInt64 = 0
            for index in 0..<count {
              var encoded = UInt32(index).bigEndian
              let chunk = try MeshLibrary.attachment_fetch_chunk_export(packet([path,body,Data(bytes:&encoded,count:4)]))
              guard !chunk.isEmpty && chunk.count <= 65536 else { throw Failure.invalid }
              hash.update(data:chunk); total += UInt64(chunk.count)
            }
            var encoded = total.bigEndian
            value = Data(bytes:&encoded,count:8) + Data(hash.finalize())
          case "discard": value = try MeshLibrary.attachment_discard_export(packet([path,body]))
          case "erase": value = try MeshLibrary.erase_account_export(path)
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
