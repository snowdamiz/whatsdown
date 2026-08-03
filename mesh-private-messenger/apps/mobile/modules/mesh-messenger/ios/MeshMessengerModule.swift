import ExpoModulesCore
import Foundation

public final class MeshMessengerModule: Module {
  private let lock = NSLock()
  private var started = false

  public func definition() -> ModuleDefinition {
    Name("MeshMessenger")

    AsyncFunction("invoke") { (symbol: String, request: Data) throws -> Data in
      self.lock.lock()
      defer { self.lock.unlock() }
      try self.startIfNeeded()
      switch symbol {
      case "mesh_messenger_initialize":
        return try MeshLibrary.initialize(request)
      case "mesh_messenger_validate_outer":
        return try MeshLibrary.validate_outer(request)
      case "mesh_messenger_store_envelope":
        return try MeshLibrary.persist_envelope(request)
      case "mesh_messenger_create_account":
        return try MeshLibrary.create_account_export(request)
      case "mesh_messenger_load_profile":
        return try MeshLibrary.load_profile_export(request)
      case "mesh_messenger_replenish_prekeys":
        return try MeshLibrary.replenish_prekeys_export(request)
      case "mesh_messenger_create_link_request":
        return try MeshLibrary.create_link_request_export(request)
      case "mesh_messenger_device_link_sas":
        return try MeshLibrary.device_link_sas_export(request)
      case "mesh_messenger_authorize_device_link":
        return try MeshLibrary.authorize_device_link_export(request)
      case "mesh_messenger_authorize_device_link_for_set":
        return try MeshLibrary.authorize_device_link_for_set_export(request)
      case "mesh_messenger_complete_device_link":
        return try MeshLibrary.complete_device_link_export(request)
      case "mesh_messenger_inspect_device_set":
        return try MeshLibrary.inspect_device_set_export(request)
      case "mesh_messenger_create_device_revocation":
        return try MeshLibrary.create_device_revocation_export(request)
      case "mesh_messenger_start_conversation":
        return try MeshLibrary.start_conversation_export(request)
      case "mesh_messenger_receive_initial":
        return try MeshLibrary.receive_initial_export(request)
      case "mesh_messenger_send_fanout":
        return try MeshLibrary.send_fanout_export(request)
      case "mesh_messenger_send_message":
        return try MeshLibrary.send_message_export(request)
      case "mesh_messenger_receive_message":
        return try MeshLibrary.receive_message_export(request)
      case "mesh_messenger_update_conversation":
        return try MeshLibrary.update_conversation_export(request)
      case "mesh_messenger_list_conversations":
        return try MeshLibrary.list_conversations_export(request)
      case "mesh_messenger_load_history":
        return try MeshLibrary.load_history_export(request)
      case "mesh_messenger_safety_number":
        return try MeshLibrary.safety_number_export(request)
      case "mesh_messenger_import_contact":
        return try MeshLibrary.import_contact_export(request)
      case "mesh_messenger_directory_entry":
        return try MeshLibrary.directory_entry_export(request)
      case "mesh_messenger_directory_lookup":
        return try MeshLibrary.directory_lookup_export(request)
      case "mesh_messenger_transparency_lookup":
        return try MeshLibrary.transparency_lookup_export(request)
      case "mesh_messenger_verify_transparency":
        return try MeshLibrary.verify_transparency_export(request)
      case "mesh_messenger_privacy_submission":
        return try MeshLibrary.privacy_submission_export(request)
      case "mesh_messenger_mailbox_fetch":
        return try MeshLibrary.mailbox_fetch_export(request)
      case "mesh_messenger_process_delivery_batch":
        return try MeshLibrary.process_delivery_batch_export(request)
      case "mesh_messenger_outbox_list":
        return try MeshLibrary.outbox_list_export(request)
      case "mesh_messenger_outbox_ack":
        return try MeshLibrary.outbox_ack_export(request)
      default:
        throw MeshLibraryFailure(
          status: MESH_LIBRARY_ERR_INVALID_ARGUMENT,
          payload: Data("unknown_export".utf8)
        )
      }
    }

    OnDestroy { [weak self] in self?.stop() }
  }

  private func startIfNeeded() throws {
    guard !started else { return }
    try MeshLibrary.initialize()
    let status = MeshMessengerRegisterAppleSecureStore()
    guard status == MESH_LIBRARY_OK else {
      throw MeshLibraryFailure(
        status: status,
        payload: Data("secure_store_registration_failed".utf8)
      )
    }
    started = true
  }

  private func stop() {
    lock.lock()
    defer { lock.unlock() }
    guard started else { return }
    MeshLibrary.shutdown()
    started = false
  }
}
