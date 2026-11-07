import Foundation
import Darwin

// Native-only, dormant until an embedding explicitly supplies its runtime
// image. This does not enable protected mode or replace any live predicate.
private final class MeshMessengerNativeRetirementImage {
  enum Failure: Error { case unavailable, foreignImage, allocation(Int32) }
  typealias Create = @convention(c) (UnsafeMutablePointer<UnsafeRawPointer?>) -> Int32
  typealias Generate = @convention(c) (UnsafeRawPointer, UnsafeMutablePointer<UnsafeRawPointer?>) -> Int32
  typealias Retire = @convention(c) (UnsafeRawPointer) -> Int32
  typealias Release = @convention(c) (UnsafeRawPointer) -> Void

  let handle: UnsafeMutableRawPointer
  let create: Create, generate: Generate, retire: Retire
  let releaseDomain: Release, releaseGeneration: Release

  init(path: String) throws {
    guard let opened = dlopen(path, RTLD_NOW | RTLD_LOCAL) else { throw Failure.unavailable }
    // Resolve and validate every symbol before adopting the image reference.
    // A failed initializer balances dlopen and owns no domain or generation.
    do {
      var base: UnsafeMutableRawPointer?
      let expected = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
      func symbol<T>(_ name: String, _: T.Type) throws -> T {
        guard let address = dlsym(opened, name) else { throw Failure.unavailable }
        var info = Dl_info()
        guard dladdr(address, &info) != 0, let filename = info.dli_fname,
              URL(fileURLWithPath: String(cString: filename)).resolvingSymlinksInPath().path == expected,
              let imageBase = info.dli_fbase else { throw Failure.foreignImage }
        if let base, base != imageBase { throw Failure.foreignImage }
        base = imageBase
        return unsafeBitCast(address, to: T.self)
      }
      create = try symbol("mesh_authority_domain_create_v2", Create.self)
      generate = try symbol("mesh_authority_generation_v2", Generate.self)
      retire = try symbol("mesh_authority_retire_v2", Retire.self)
      releaseDomain = try symbol("mesh_authority_domain_release_v2", Release.self)
      releaseGeneration = try symbol("mesh_authority_generation_release_v2", Release.self)
      handle = opened
    } catch { dlclose(opened); throw error }
  }
  deinit { dlclose(handle) }
}

final class MeshMessengerNativeRetirementDomain {
  private let image: MeshMessengerNativeRetirementImage
  let nativeDomain: UnsafeRawPointer

  init(imagePath: String) throws {
    let image = try MeshMessengerNativeRetirementImage(path: imagePath)
    var output: UnsafeRawPointer?
    let status = image.create(&output)
    guard status == 0, let output else {
      if let output { image.releaseDomain(output) }
      throw MeshMessengerNativeRetirementImage.Failure.allocation(status)
    }
    self.image = image; nativeDomain = output
  }
  func makeNode() throws -> MeshMessengerNativeRetirementNode {
    var output: UnsafeRawPointer?
    let status = image.generate(nativeDomain, &output)
    guard status == 0, let output else {
      if let output { image.releaseGeneration(output) }
      throw MeshMessengerNativeRetirementImage.Failure.allocation(status)
    }
    return MeshMessengerNativeRetirementNode(domain: self, node: output,
      retire: image.retire, release: image.releaseGeneration)
  }
  deinit { image.releaseDomain(nativeDomain) }
}

final class MeshMessengerNativeRetirementNode {
  // The node retains its original domain/image, never an owner selected later.
  private let domain: MeshMessengerNativeRetirementDomain
  let nativeNode: UnsafeRawPointer
  private let retire: MeshMessengerNativeRetirementImage.Retire
  private let release: MeshMessengerNativeRetirementImage.Release
  fileprivate init(domain: MeshMessengerNativeRetirementDomain, node: UnsafeRawPointer,
                   retire: @escaping MeshMessengerNativeRetirementImage.Retire,
                   release: @escaping MeshMessengerNativeRetirementImage.Release) {
    self.domain = domain; nativeNode = node; self.retire = retire; self.release = release
  }
  // Fixed frozen ABI target. No lookup, dispatch, lock, callback or destruction.
  func retireOriginal() { _ = retire(nativeNode) }
  deinit {
    retireOriginal()
    release(nativeNode)
    // domain/image references are released only after the ABI release returns.
    withExtendedLifetime(domain) {}
  }
}
