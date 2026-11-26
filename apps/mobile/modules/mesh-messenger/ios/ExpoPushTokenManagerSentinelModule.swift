import ExpoModulesCore

public final class ExpoPushTokenManagerSentinelModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoPushTokenManager")
    Events("onDevicePushToken")
  }
}
