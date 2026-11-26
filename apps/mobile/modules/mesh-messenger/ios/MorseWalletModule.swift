import ExpoModulesCore
import Foundation
import LocalAuthentication
import Security

/// The in-app wallet's host (plan §6.13): packages/wallet-core, linked in as
/// MorseWalletCore.xcframework, with the seed (BIP39 entropy) in the Keychain,
/// this device only. The seed never reaches JavaScript: the recovery phrase (for
/// display), public keys, parsed pay requests and signed transactions do. Every
/// request frame that held the seed is wiped when the call returns.
/// The API is apps/mobile/modules/mesh-messenger/wallet.ts.
public final class MorseWalletModule: Module {
  private let lock = NSLock()

  public func definition() -> ModuleDefinition {
    Name("MorseWallet")

    // A seed the locked device can't read yet still exists (the anchor check asks from
    // the background, and the ready bounty address answers it).
    AsyncFunction("walletExists") { () throws -> Bool in
      try self.locked {
        do { return try self.hasSeed() } catch let failure as WalletFailure where failure.code == "wallet_locked" { return true }
      }
    }

    AsyncFunction("walletCreate") { (words: Int) throws -> String in
      try self.locked {
        guard let count = UInt8(exactly: words) else { throw WalletFailure("bad_word_count") }
        var answer = try walletCore(op: 1, [[count]])
        defer { wipe(&answer) }
        var entropy = try vector(answer, at: 0)
        defer { wipe(&entropy) }
        var phrase = try vector(answer, at: 4 + entropy.count)
        defer { wipe(&phrase) }
        try self.storeNew(entropy)
        return String(decoding: phrase, as: UTF8.self)
      }
    }

    AsyncFunction("walletRestore") { (phrase: String) throws in
      try self.locked {
        var typed = vec32(Array(phrase.utf8))
        defer { wipe(&typed) }
        var entropy = try walletCore(op: 2, [typed])
        defer { wipe(&entropy) }
        try self.storeNew(entropy)
      }
    }

    // Behind Face ID, Touch ID or the passcode; a device with no passcode has none to ask.
    AsyncFunction("walletPhrase") { (promise: Promise) in
      let context = LAContext()
      var error: NSError?
      let reveal = {
        do {
          promise.resolve(try self.locked {
            var entropy = try self.entropy()
            defer { wipe(&entropy) }
            var seeded = vec32(entropy)
            defer { wipe(&seeded) }
            var phrase = try walletCore(op: 3, [seeded])
            defer { wipe(&phrase) }
            return String(decoding: phrase, as: UTF8.self)
          })
        } catch {
          promise.reject(error)
        }
      }
      guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        if (error as? LAError)?.code == .passcodeNotSet { reveal() } else { promise.reject(WalletFailure("authentication_failed")) }
        return
      }
      context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Show your wallet's recovery phrase") { granted, _ in
        if granted { reveal() } else { promise.reject(WalletFailure("authentication_failed")) }
      }
    }

    AsyncFunction("walletWipe") { () throws in
      try self.locked {
        for account in [WalletKeychain.entropy, WalletKeychain.bountyIndex, WalletKeychain.bountyNext] {
          try WalletKeychain.delete(account)
        }
      }
    }

    // Ops 4 (address), 5 (transfer), 6 (parse a Solana Pay URL); `body` follows the seed.
    AsyncFunction("walletCall") { (op: Int, body: Data) throws -> Data in
      try self.locked {
        let body = [UInt8](body)
        if op == 6 { return Data(try walletCore(op: 6, [body])) }
        guard op == 4 || op == 5 else { throw WalletFailure("bad_op") }
        let issued = try self.issued()
        for start in stride(from: 0, to: op == 4 ? 5 : 10, by: 5) {
          guard body.count >= start + 5 else { throw WalletFailure("bad_frame") }
          if body[start] == 2 && readU32(body, at: start + 1) >= issued { throw WalletFailure("bounty_not_issued") }
        }
        if op == 5 && body[5] != 1 { throw WalletFailure("fee_payer_not_account") }
        var entropy = try self.entropy()
        defer { wipe(&entropy) }
        var seeded = vec32(entropy)
        defer { wipe(&seeded) }
        return Data(try walletCore(op: UInt8(op), [seeded, body]))
      }
    }

    // u32 index || public key; the next index is persisted before the address is returned.
    AsyncFunction("walletNextBountyAddress") { () throws -> Data in
      try self.locked {
        let index = try self.issued()
        let key = try self.bountyKey(index)
        try WalletKeychain.write(WalletKeychain.bountyIndex, u32(index + 1), accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try? self.prepareNext(index + 1)
        return Data(u32(index) + key)
      }
    }

    AsyncFunction("walletBountyIndex") { (atLeast: Int) throws -> Int in
      try self.locked {
        guard try self.hasSeed() else { throw WalletFailure("wallet_missing") }
        guard let wanted = UInt32(exactly: atLeast) else { throw WalletFailure("bad_index") }
        let issued = try self.issued()
        guard wanted > issued else { return Int(issued) }
        try WalletKeychain.write(WalletKeychain.bountyIndex, u32(wanted), accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try? self.prepareNext(wanted)
        return Int(wanted)
      }
    }
  }

  private func locked<T>(_ body: () throws -> T) throws -> T {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }

  private func entropy() throws -> [UInt8] {
    guard let entropy = try WalletKeychain.read(WalletKeychain.entropy) else { throw WalletFailure("wallet_missing") }
    return entropy
  }

  private func hasSeed() throws -> Bool {
    guard var entropy = try WalletKeychain.read(WalletKeychain.entropy) else { return false }
    wipe(&entropy)
    return true
  }

  private func issued() throws -> UInt32 {
    guard let bytes = try WalletKeychain.read(WalletKeychain.bountyIndex) else { return 0 }
    guard bytes.count == 4 else { throw WalletFailure("wallet_store_failed") }
    return readU32(bytes, at: 0)
  }

  private func storeNew(_ entropy: [UInt8]) throws {
    guard try !hasSeed() else { throw WalletFailure("wallet_exists") }
    try WalletKeychain.write(WalletKeychain.bountyIndex, u32(0), accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    try WalletKeychain.write(WalletKeychain.entropy, entropy, accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    try? prepareNext(0)
  }

  /// The seed is readable only while the device is unlocked, but the anchor check may
  /// need a finder address in the background: the next bounty address's public key is
  /// kept ready, readable after first unlock.
  private func prepareNext(_ index: UInt32) throws {
    var entropy = try self.entropy()
    defer { wipe(&entropy) }
    try WalletKeychain.write(
      WalletKeychain.bountyNext, u32(index) + (try derive(entropy, index)),
      accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
  }

  private func bountyKey(_ index: UInt32) throws -> [UInt8] {
    if let ready = try WalletKeychain.read(WalletKeychain.bountyNext), ready.count == 36, readU32(ready, at: 0) == index {
      return Array(ready[4...])
    }
    var entropy = try self.entropy()
    defer { wipe(&entropy) }
    return try derive(entropy, index)
  }

  private func derive(_ entropy: [UInt8], _ index: UInt32) throws -> [UInt8] {
    var seeded = vec32(entropy)
    defer { wipe(&seeded) }
    return try walletCore(op: 4, [seeded, [2] + u32(index)])
  }
}

struct WalletFailure: LocalizedError {
  let code: String
  init(_ code: String) { self.code = code }
  var errorDescription: String? { code }
}

private enum WalletKeychain {
  static let entropy = "entropy/v1"
  static let bountyIndex = "bounty-index/v1"
  static let bountyNext = "bounty-next/v1"

  private static func query(_ account: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "app.morse.wallet",
      kSecAttrAccount as String: account,
    ]
  }

  static func read(_ account: String) throws -> [UInt8]? {
    var search = query(account)
    search[kSecReturnData as String] = true
    search[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(search as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    if status == errSecInteractionNotAllowed { throw WalletFailure("wallet_locked") }
    guard status == errSecSuccess, let data = item as? Data else { throw WalletFailure("wallet_store_failed") }
    return [UInt8](data)
  }

  static func write(_ account: String, _ bytes: [UInt8], accessible: CFString) throws {
    let data = Data(bytes)
    var status = SecItemUpdate(query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecItemNotFound {
      var item = query(account)
      item[kSecValueData as String] = data
      item[kSecAttrAccessible as String] = accessible
      status = SecItemAdd(item as CFDictionary, nil)
    }
    guard status == errSecSuccess else { throw WalletFailure("wallet_store_failed") }
  }

  static func delete(_ account: String) throws {
    let status = SecItemDelete(query(account) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw WalletFailure("wallet_store_failed") }
  }
}

/// One wallet-core call on the frame `1 || op || parts`; the request is wiped before
/// returning. The caller wipes an answer that holds a secret.
private func walletCore(op: UInt8, _ parts: [[UInt8]]) throws -> [UInt8] {
  // Sized up front, so no reallocation leaves a copy of the seed behind.
  var request: [UInt8] = []
  request.reserveCapacity(2 + parts.reduce(0) { $0 + $1.count })
  request += [1, op]
  for part in parts { request += part }
  defer { wipe(&request) }
  var response = MorseWalletBytes(data: nil, len: 0)
  let status = request.withUnsafeBufferPointer { morse_wallet_call($0.baseAddress, UInt64($0.count), &response) }
  defer { morse_wallet_free_bytes(&response) }
  let answer = response.data == nil ? [] : Array(UnsafeBufferPointer(start: response.data, count: Int(response.len)))
  guard status == MORSE_WALLET_OK else {
    throw WalletFailure(status == MORSE_WALLET_ERR_APPLICATION ? String(decoding: answer, as: UTF8.self) : "wallet_failed")
  }
  return answer
}

private func wipe(_ bytes: inout [UInt8]) {
  bytes.withUnsafeMutableBytes { buffer in
    guard let base = buffer.baseAddress else { return }
    _ = memset_s(base, buffer.count, 0, buffer.count)
  }
}

private func u32(_ value: UInt32) -> [UInt8] {
  [UInt8(value >> 24), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255), UInt8(value & 255)]
}

private func readU32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
  bytes[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
}

private func vec32(_ bytes: [UInt8]) -> [UInt8] { u32(UInt32(bytes.count)) + bytes }

/// The vector32 at `offset` of a wallet-core answer.
private func vector(_ bytes: [UInt8], at offset: Int) throws -> [UInt8] {
  guard bytes.count >= offset + 4 else { throw WalletFailure("bad_frame") }
  let length = Int(readU32(bytes, at: offset))
  guard bytes.count >= offset + 4 + length else { throw WalletFailure("bad_frame") }
  return Array(bytes[offset + 4..<offset + 4 + length])
}
