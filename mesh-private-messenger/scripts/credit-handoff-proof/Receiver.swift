import UIKit
import CryptoKit

// Owned receiver only. Records the OS-delivered URI digest and never pays.
@main
final class Receiver: UIResponder, UIApplicationDelegate {
  func application(_ app: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    try? FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
    try? Data("true".utf8).write(to: path.appendingPathComponent("started.json"))
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
      let state: [String: Any] = ["active": app.applicationState == .active, "connected": !app.connectedScenes.isEmpty]
      try? JSONSerialization.data(withJSONObject: state).write(to: path.appendingPathComponent("lifecycle.json"), options: .atomic)
    }
    return true
  }
  func application(_ app: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
    let configuration = UISceneConfiguration(name: nil, sessionRole: session.role)
    configuration.delegateClass = ReceiverScene.self
    return configuration
  }
}
@objc(MorseHandoffReceiverScene)
final class ReceiverScene: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?
  func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
    guard let scene = scene as? UIWindowScene else { return }
    window = UIWindow(windowScene: scene)
    window?.rootViewController = UIViewController()
    window?.makeKeyAndVisible()
    for value in options.urlContexts { record(value.url) }
  }
  func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
    for value in contexts { record(value.url) }
  }
  private func record(_ url: URL) {
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let file = directory.appendingPathComponent("received.json")
    let old = (try? Data(contentsOf: file)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let digest = SHA256.hash(data: Data(url.absoluteString.utf8)).map { String(format: "%02x", $0) }.joined()
    let value: [String: Any] = ["count": (old?["count"] as? Int ?? 0) + 1, "sha256": digest, "scheme": url.scheme ?? "", "length": url.absoluteString.utf8.count]
    try? JSONSerialization.data(withJSONObject: value).write(to: file, options: .atomic)
  }
}
