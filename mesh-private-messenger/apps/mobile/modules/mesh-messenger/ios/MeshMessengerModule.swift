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
      case "mesh_messenger_start_conversation":
        return try MeshLibrary.start_conversation_export(request)
      case "mesh_messenger_receive_initial":
        return try MeshLibrary.receive_initial_export(request)
      case "mesh_messenger_send_message":
        return try MeshLibrary.send_message_export(request)
      case "mesh_messenger_receive_message":
        return try MeshLibrary.receive_message_export(request)
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
