import Foundation
import Darwin

@main private enum ImageLifetime {
  static func main() throws {
    let path = CommandLine.arguments[1]
    for invalid in [path + ".missing", "/usr/lib/libSystem.B.dylib"] {
      do {
        _ = try MeshMessengerNativeRetirementDomain(imagePath: invalid)
        fatalError("invalid image produced a domain")
      } catch { print("PASS failed image initialization: \(invalid)") }
    }
    // This executable has no link dependency on the accepted runtime. The
    // production domain is its sole image owner after this temporary lookup.
    var domain: MeshMessengerNativeRetirementDomain? = try .init(imagePath: path)
    weak var originalDomain = domain
    var node: MeshMessengerNativeRetirementNode? = try domain!.makeNode()
    let domainPointer = domain!.nativeDomain
    typealias Bind = @convention(c) (UnsafeRawPointer, UnsafePointer<UnsafeRawPointer?>, UInt64, UnsafeRawPointer?, UnsafeMutablePointer<UnsafeRawPointer?>) -> Int32
    let lookup = dlopen(path, RTLD_NOW | RTLD_NOLOAD)!
    let bind = unsafeBitCast(dlsym(lookup, "mesh_authority_bind_v2")!, to: Bind.self)
    dlclose(lookup)
    domain = nil
    precondition(originalDomain != nil, "node lost original domain/image")
    node!.retireOriginal(); node!.retireOriginal()
    var rawNode: UnsafeRawPointer? = node!.nativeNode, authority: UnsafeRawPointer?
    precondition(bind(domainPointer, &rawNode, 1, nil, &authority) == 10 && authority == nil)
    print("PASS retained node/domain/image after caller domain release; repeated retire refuses actual ABI bind")
    node = nil
    precondition(originalDomain == nil, "node release leaked domain")
    print("PASS node release then domain release; image release follows domain ABI teardown")
  }
}
