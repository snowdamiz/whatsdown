import Foundation

public struct MeshLibraryFailure: LocalizedError {
  public let status: Int32
  public let payload: Data

  public var errorDescription: String? {
    let summary = "Mesh library call failed (status=\(status))"
    guard let message = String(data: payload, encoding: .utf8), !message.isEmpty else { return summary }
    return "\(summary): \(message)"
  }
}

public enum MeshLibrary {
  public static func initialize() throws {
    let status = mesh_library_init()
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: Data()) }
  }

  public static func shutdown() { _ = mesh_library_shutdown() }

  public static func initialize(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_initialize(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func validate_outer(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_validate_outer(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func persist_envelope(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_store_envelope(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func create_account_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_create_account(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func load_profile_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_load_profile(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func create_signup_draft_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_create_signup_draft(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func signup_draft_state_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_signup_draft_state(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_action_recovery_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_action_recovery(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_signup_policy_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_signup_policy(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_signup_policy_view_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_signup_policy_view(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func signup_draft_rename_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_signup_draft_rename(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func signup_draft_free_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_signup_draft_free(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func signup_draft_free_complete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_signup_draft_free_complete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_signup_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_signup(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_signup_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_signup_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func register_signup_policy_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_register_signup_policy(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_receipt_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_receipt(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_part_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_part(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_part_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_part_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_prune_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_prune(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_preview_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_preview(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachments_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachments(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_download_plan_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_download_plan(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func replenish_prekeys_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_replenish_prekeys(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func reconcile_prekeys_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_reconcile_prekeys(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func create_link_request_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_create_link_request(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func device_link_sas_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_device_link_sas(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func authorize_device_link_for_set_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_authorize_device_link_for_set(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func complete_device_link_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_complete_device_link(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func inspect_device_set_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_inspect_device_set(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func create_device_revocation_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_create_device_revocation(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func account_deletion_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_account_deletion(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func erase_account_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_erase_account(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func device_departure_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_device_departure(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func forget_on_proof_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_forget_on_proof(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func receive_initial_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_receive_initial(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func prepare_fanout_prekeys_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_prepare_fanout_prekeys(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func send_fanout_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_send_fanout(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_key_package_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_key_package(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_invite_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_invite(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_invitation_accept_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_invitation_accept(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_invitation_complete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_invitation_complete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_invitation_decline_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_invitation_decline(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_invitations_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_invitations(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_create_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_create(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_add_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_add(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_remove_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_remove(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_send_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_send(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_receive_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_receive(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_list_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_list(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_inspect_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_inspect(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_history_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_history(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_forget_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_forget(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func receive_message_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_receive_message(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func update_conversation_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_update_conversation(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_intent_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_intent(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_action_complete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_action_complete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_status_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_status(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func list_conversations_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_list_conversations(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func load_history_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_load_history(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func safety_number_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_safety_number(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func import_contact_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_import_contact(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func directory_entry_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_directory_entry(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func directory_lookup_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_directory_lookup(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func transparency_lookup_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_transparency_lookup(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func register_request_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_register_request(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func renew_devices_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_renew_devices(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func resolve_request_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_resolve_request(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func resolve_plan_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_resolve_plan(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func verify_transparency_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_verify_transparency(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func transparency_fork_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_transparency_fork(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_status_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_status(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_set_enabled_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_set_enabled(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_commit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_commit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_unavailable_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_unavailable(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_status_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_status(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_cancel_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_cancel(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_commit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_commit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func bounty_transfer_submit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_bounty_transfer_submit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func anchor_check_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_anchor_check(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func fork_filing_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_fork_filing(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func privacy_submission_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_privacy_submission(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func mailbox_fetch_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_mailbox_fetch(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func mailbox_synchronize_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_mailbox_synchronize(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func mailbox_stream_open_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_mailbox_stream_open(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func mailbox_stream_poll_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_mailbox_stream_poll(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func mailbox_stream_close_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_mailbox_stream_close(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func process_delivery_batch_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_process_delivery_batch(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func outbox_list_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_outbox_list(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func outbox_drain_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_outbox_drain(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func outbox_ack_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_outbox_ack(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func outbox_fail_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_outbox_fail(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func outbox_page_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_outbox_page(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func journal_load_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_journal_load(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func journal_save_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_journal_save(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func presentation_load_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_presentation_load(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func presentation_save_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_presentation_save(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_seal_chunk_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_seal_chunk(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_discover_online_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_discover_online(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_purchase_continue_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_purchase_continue(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_payment_handoff_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_payment_handoff(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_action_continue_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_action_continue(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_signup_policy_online_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_signup_policy_online(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_discovery_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_discovery(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_admit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_admit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_prepare_again_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_prepare_again(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_quote_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_quote(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_payment_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_payment(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_finalize_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_finalize(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_purchases_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_purchases(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_balance_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_balance(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_reserve_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_reserve(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_reservation_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_reservation(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_retention_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_retention(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_retention_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_retention_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_receipt_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_receipt(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_payment_url_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_payment_url(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_payment_signature_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_payment_signature(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_wallet_quote_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_wallet_quote(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_wallet_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_wallet_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_wallet_commit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_wallet_commit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_wallet_submit_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_wallet_submit(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_candidate_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_candidate(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_preview_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_preview(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_recover_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_recover(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_receipt_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_receipt(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_inventory_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_inventory(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func postage_policy_view_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_postage_policy_view(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func postage_policy_prepare_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_postage_policy_prepare(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_postage_continue_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_postage_continue(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func postage_policy_publish_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_postage_policy_publish(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func directory_register_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_directory_register(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func prekeys_synchronize_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_prekeys_synchronize(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_grant_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_grant(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_upload_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_upload(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_complete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_complete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func credit_attachment_delete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_credit_attachment_delete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_fetch_chunk_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_fetch_chunk(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_upload_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_upload(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func attachment_discard_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_discard(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func directory_resolve_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_directory_resolve(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_flow_intent_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_flow_intent(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_flow_complete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_flow_complete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_flow_send_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_flow_send(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_flow_begin_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_flow_begin(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func push_flow_validate_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_push_flow_validate(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func account_delete_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_account_delete(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func account_discard_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_account_discard(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func account_capabilities_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_account_capabilities(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func devices_renew_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_devices_renew(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func device_revoke_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_device_revoke(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func journal_load_bound_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_journal_load_bound(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func journal_save_bound_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_journal_save_bound(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func fanout_send_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_fanout_send(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func network_counter_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_network_counter(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func group_policy_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_group_policy(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_create_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_create(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_preview_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_preview(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_import_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_import(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_list_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_list(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_remove_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_remove(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_overview_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_overview(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_page_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_page(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_pending_state_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_pending_state(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_pending_resume_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_pending_resume(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_pending_discard_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_pending_discard(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func backup_pending_repair_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_backup_pending_repair(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }

  public static func view_once_consume_native_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_view_once_consume(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }
}
