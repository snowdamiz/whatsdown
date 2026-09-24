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

  public static func attachment_open_chunk_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_attachment_open_chunk(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
    }
    defer { mesh_library_free_returned_bytes(&response) }
    let payload = response.len == 0 ? Data() : Data(bytes: response.data!, count: Int(response.len))
    guard status == MESH_LIBRARY_OK else { throw MeshLibraryFailure(status: status, payload: payload) }
    return payload
  }
}
