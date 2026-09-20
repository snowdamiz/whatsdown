import Foundation
import UIKit

/// Keeps message data off device backups and out of the app switcher.
///
/// Both are properties of the device the app runs on rather than of the
/// messenger protocol, so they live at the native boundary.
enum MeshMessengerDataProtection {
  private static var cover: UIView?
  private static var observers: [NSObjectProtocol] = []

  /// iCloud and Finder backups must never carry the message database, its
  /// journals, or decrypted previews. Excluding a directory excludes everything
  /// beneath it; the flag is re-applied on every launch because the system
  /// clears it when a directory is recreated.
  static func excludeAppDataFromBackup() {
    let manager = FileManager.default
    let directories: [FileManager.SearchPathDirectory] = [
      .documentDirectory, .applicationSupportDirectory, .cachesDirectory,
    ]
    for directory in directories {
      guard var url = manager.urls(for: directory, in: .userDomainMask).first else { continue }
      try? manager.createDirectory(at: url, withIntermediateDirectories: true)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try? url.setResourceValues(values)
    }
  }

  /// iOS snapshots the key window as the app leaves the foreground and shows
  /// that image in the app switcher. Cover the content before the snapshot.
  static func startCoveringInactiveWindow() {
    guard observers.isEmpty else { return }
    let center = NotificationCenter.default
    observers = [
      center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { _ in
        showCover()
      },
      center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
        hideCover()
      },
    ]
  }

  static func stop() {
    observers.forEach(NotificationCenter.default.removeObserver)
    observers = []
    DispatchQueue.main.async { hideCover() }
  }

  private static func keyWindow() -> UIWindow? {
    UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
      .first { $0.isKeyWindow }
  }

  private static func showCover() {
    guard cover == nil, let window = keyWindow() else { return }
    let view = UIView(frame: window.bounds)
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    view.backgroundColor = UIColor(red: 10 / 255, green: 10 / 255, blue: 12 / 255, alpha: 1)
    window.addSubview(view)
    cover = view
  }

  private static func hideCover() {
    cover?.removeFromSuperview()
    cover = nil
  }
}
