import Foundation

enum MeshMessengerBackupRequest {
  enum Failure: Error { case invalidRequest, scopedClientRequired }
  private static let maximumInputs: [String: Int] = [
    "mesh_messenger_backup_create": 42004,
    "mesh_messenger_backup_preview": 16841207,
    "mesh_messenger_backup_import": 16841239,
    "mesh_messenger_backup_list": 40239,
    "mesh_messenger_backup_remove": 40271,
    "mesh_messenger_backup_overview": 40271,
    "mesh_messenger_backup_page": 40313,
    "mesh_messenger_backup_pending_state": 40239,
    "mesh_messenger_backup_pending_resume": 44371,
    "mesh_messenger_backup_pending_discard": 40271,
    "mesh_messenger_backup_pending_repair": 40239
  ]

  // Disabled app-lock policy is compatible with a real foreground owner.
  // A legacy or windowless data port never supplies that owner provenance.
  static func requireOwner(_ symbol: String, ownerScoped: Bool) throws {
    if symbol.hasPrefix("mesh_messenger_backup_"), !ownerScoped { throw Failure.scopedClientRequired }
  }

  // Admit only the bounded canonical public path. Core independently validates
  // profile bytes, code/selection policy, custody, rows and current authority.
  static func validate(_ symbol: String, _ request: Data, expectedDatabase: Data) throws {
    guard let maximum = maximumInputs[symbol], request.count <= maximum else { throw Failure.invalidRequest }
    let prefix = Array(request.prefix(4101))
    guard prefix.count >= 5, prefix[0] == 1 else { throw Failure.invalidRequest }
    let count = prefix[1...4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard count >= 1, count <= 4096, prefix.count >= 5 + Int(count),
      expectedDatabase.count == Int(count),
      Data(prefix[5..<(5 + Int(count))]) == expectedDatabase else { throw Failure.invalidRequest }
    guard symbol.hasPrefix("mesh_messenger_backup_pending_") else { return }

    func length(at offset: Int) throws -> Int {
      guard offset >= 0, offset <= request.count - 4 else { throw Failure.invalidRequest }
      var value = UInt32(0)
      for i in 0..<4 { value = (value << 8) | UInt32(request[request.startIndex + offset + i]) }
      return Int(value)
    }
    let pathEnd = 5 + Int(count), profileCount = try length(at: pathEnd)
    guard profileCount >= 1, profileCount <= 36134, profileCount <= request.count - pathEnd - 4 else { throw Failure.invalidRequest }
    let commonEnd = pathEnd + 4 + profileCount
    switch symbol {
    case "mesh_messenger_backup_pending_state", "mesh_messenger_backup_pending_repair":
      guard request.count == commonEnd else { throw Failure.invalidRequest }
    case "mesh_messenger_backup_pending_discard":
      guard request.count == commonEnd + 32 else { throw Failure.invalidRequest }
    case "mesh_messenger_backup_pending_resume":
      let codeCount = try length(at: commonEnd + 32)
      guard codeCount >= 1, codeCount <= 4096, request.count == commonEnd + 36 + codeCount else { throw Failure.invalidRequest }
    default: throw Failure.invalidRequest
    }
  }
}
