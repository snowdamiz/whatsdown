import Foundation

@main struct RequestProof {
  static func hex(_ text: String) -> Data {
    let bytes = Array(text.utf8)
    return Data(stride(from: 0, to: bytes.count, by: 2).map {
      UInt8(String(decoding: bytes[$0..<$0+2], as: UTF8.self), radix: 16)!
    })
  }
  static func main() throws {
    let lines = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8).split(separator: "\n")
    for (index, line) in lines.enumerated() {
      let parts = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
      let accepted: Bool
      do {
        try MeshMessengerCreditRequest.validate(parts[0], hex(parts[2]), hex(parts[1]))
        accepted = true
      } catch { accepted = false }
      guard accepted == (parts[3] == "1") else {
        throw NSError(domain: "Unexpected credit request decision at vector \(index): \(parts[0])", code: 1)
      }
    }
    print("Swift credit host framing: \(lines.count) vectors passed")
  }
}
