import ExpoModulesCore
import LocalAuthentication

/// App lock (apps/mobile/src/LockGate.tsx): the device owner's Face ID, Touch ID
/// or passcode before Morse shows anything. While the app is away its window is
/// already covered for the app switcher (MeshMessengerDataProtection).
/// The API is apps/mobile/modules/mesh-messenger/lock.ts.
public final class MorseLockModule: Module {
  public func definition() -> ModuleDefinition {
    Name("MorseLock")

    // A device without a passcode has nothing to ask for, so it can't offer the lock.
    AsyncFunction("lockAvailable") { () -> Bool in
      var error: NSError?
      return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    // Whether the owner unlocked. A device whose passcode was removed since the
    // lock was turned on opens: there is no owner check left to make.
    AsyncFunction("lockAuthenticate") { (reason: String, promise: Promise) in
      let context = LAContext()
      var error: NSError?
      guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        promise.resolve((error as? LAError)?.code == .passcodeNotSet)
        return
      }
      context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { granted, _ in
        promise.resolve(granted)
      }
    }
  }
}
