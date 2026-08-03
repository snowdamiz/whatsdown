import Foundation

public struct MeshLibraryFailure: Error {
  public let status: Int32
  public let payload: Data
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

  public static func start_conversation_export(_ request: Data) throws -> Data {
    var response = MeshLibraryBytes(data: nil, len: 0)
    let status = request.withUnsafeBytes { bytes in
      mesh_messenger_start_conversation(bytes.bindMemory(to: UInt8.self).baseAddress, UInt64(bytes.count), &response)
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
}
