import Foundation

// Host authority check only. Mesh owns operation schemas and credit policy.
enum MeshMessengerCreditRequest {
  static func requiresValidation(_ symbol: String) -> Bool {
    symbol.hasPrefix("mesh_messenger_credit_") || symbol.hasPrefix("mesh_messenger_postage_policy_") || ["mesh_messenger_fanout_send", "mesh_messenger_journal_load_bound", "mesh_messenger_journal_save_bound", "mesh_messenger_attachment_fetch_chunk", "mesh_messenger_attachment_upload", "mesh_messenger_attachment_discard", "mesh_messenger_directory_resolve", "mesh_messenger_outbox_drain", "mesh_messenger_push_flow_begin", "mesh_messenger_account_delete", "mesh_messenger_account_discard", "mesh_messenger_account_capabilities", "mesh_messenger_devices_renew", "mesh_messenger_device_revoke", "mesh_messenger_push_flow_intent", "mesh_messenger_push_flow_complete", "mesh_messenger_push_flow_send"].contains(symbol)
  }

  static func validate(_ symbol: String, _ request: Data, _ database: Data) throws {
    let known = ["mesh_messenger_attachment_upload": 4, "mesh_messenger_attachment_discard": 2, "mesh_messenger_directory_resolve": 2, "mesh_messenger_outbox_drain": 2, "mesh_messenger_credit_attachment_grant": 2, "mesh_messenger_credit_attachment_upload": 3, "mesh_messenger_credit_attachment_complete": 2, "mesh_messenger_credit_attachment_delete": 2, "mesh_messenger_attachment_fetch_chunk": 3, "mesh_messenger_credit_discover_online": 1, "mesh_messenger_credit_purchase_continue": 2,
      "mesh_messenger_credit_action_continue": 3, "mesh_messenger_credit_signup_policy_online": 1, "mesh_messenger_credit_postage_continue": 2,
      "mesh_messenger_postage_policy_view": 2, "mesh_messenger_postage_policy_prepare": 2, "mesh_messenger_postage_policy_publish": 4]
    let ordinary = ["mesh_messenger_fanout_send": [4096, 36134, 65, 1, 32000, 32, 16384], "mesh_messenger_journal_load_bound": [4096, 36134, 256], "mesh_messenger_journal_save_bound": [4096, 36134, 256, 262144], "mesh_messenger_push_flow_begin": [4096, 36134, 1], "mesh_messenger_account_delete": [4096, 36134], "mesh_messenger_account_discard": [4096, 36134], "mesh_messenger_account_capabilities": [4096, 36134], "mesh_messenger_devices_renew": [4096, 305260], "mesh_messenger_device_revoke": [4096, 305260, 16], "mesh_messenger_directory_resolve": [4096, 65], "mesh_messenger_outbox_drain": [4096, 1],
      "mesh_messenger_push_flow_intent": [4096, 1], "mesh_messenger_push_flow_complete": [4096, 50, 1],
      "mesh_messenger_push_flow_send": [4096, 50]][symbol]
    guard requiresValidation(symbol) else { return }
    let fanout = symbol == "mesh_messenger_fanout_send"
    let upload = symbol == "mesh_messenger_attachment_upload"
    let maximumFields = ordinary?.count ?? (upload ? 4 : symbol == "mesh_messenger_credit_attachment_prepare" ? 5 :
      ["mesh_messenger_credit_attachment_part", "mesh_messenger_credit_postage_prepare", "mesh_messenger_postage_policy_publish"].contains(symbol) ? 4 : 3)
    let invalid = NSError(domain: "MorsePayment", code: 1)
    var offset = 0
    func u32() throws -> Int {
      guard offset + 4 <= request.count else { throw invalid }
      let value = request[offset..<offset+4].reduce(0) { ($0 << 8) | Int($1) }
      offset += 4
      return value
    }
    guard request.count >= 4, request.count <= (upload ? 16_782_000 : ordinary?.reduce(0) { $0 + $1 + 4 } ?? 5_250_024),
      !database.isEmpty, database.count <= 4096 else { throw invalid }
    let count = try ordinary?.count ?? u32()
    guard (1...maximumFields).contains(count) else { throw invalid }
    if let expected = known[symbol], count != expected { throw invalid }
    for index in 0..<count {
      let size = try u32()
      let maximum = upload ? [4096, 255, 127, 16_777_216][index] : ordinary?[index] ?? 1_050_000
      guard size <= maximum, (ordinary == nil || size > 0 || (fanout && index >= 4)), size <= request.count - offset else { throw invalid }
      if index == 0 && request.subdata(in: offset..<offset+size) != database { throw invalid }
      offset += size
    }
    guard offset == request.count else { throw invalid }
  }
}
