import ExpoApplication
import ExpoModulesCore
import ExpoNotifications
import Foundation
import UIKit

public final class MeshMessengerModule: Module, NotificationDelegate {
  private let lock = MeshMessengerDataProtection.coreLock
  private let walletQueue = DispatchQueue(label: "app.morse.wallet", qos: .userInitiated)
  private var started = false
  private var pushEnabled = false
  private var pushPromise: Promise?
  private static let pushOperations = MeshMessengerPushSerialQueue()
  private var pushRequest: Data?
  private var pushOperationID: UUID?
  private var pushFinished: (() -> Void)?
  private var pushCall: MeshMessengerNativeCall?
  private var destroyed = false
  private var removeStateObserver: (() -> Void)?, removeInboxObserver: (() -> Void)?
  private let rootOwnerModuleID = UUID()
  private let rootOwnerLifecycle = MeshMessengerRootModuleLifecycle()

  // Expo calls this public hook after registry insertion. DSL OnCreate runs
  // earlier, during ModuleHolder construction, and cannot prove membership.
  public override func didCreate() {
    super.didCreate()
    guard let context = appContext else { return }
    let registeredModule = context.moduleRegistry.get(moduleWithName: "MeshMessenger")
    guard registeredModule === self else { return }
    do { try rootOwnerLifecycle.observeRegistryMembership(self, registeredModule: registeredModule) }
    catch { return }
    let register: () -> Void = { [weak self] in
      guard let self, self.appContext === context else { return }
      // Expo registry removal can invoke OnDestroy while holding its mutex.
      // Snapshot membership before lifecycle locking to avoid inverse ordering.
      let registeredModule = context.moduleRegistry.get(moduleWithName: "MeshMessenger")
      guard registeredModule === self else { return }
      do {
        try self.rootOwnerLifecycle.register {
          try MeshMessengerDataProtection.registerModule(self, context: context,
            registeredModule: registeredModule, moduleID: self.rootOwnerModuleID)
        }
      } catch { /* Refusal supplies no owner, grant, fallback or gate mutation. */ }
    }
    if Thread.isMainThread { register() } else { DispatchQueue.main.async(execute: register) }
  }

  public func definition() -> ModuleDefinition {
    Name("MeshMessenger")

    Events("onPushRegistrationChanged", "onAppLockChanged", "onAppLockInboxOpen")

    // The Expo view factory supplies the actual context/UIView. Registration is
    // provenance only and exposes no auth, plaintext or readiness capability.
    View(MeshMessengerAppLockOwnerView.self) {
      ViewName("AppLockOwner")
      Events("onOwnerAttached")
      AsyncFunction("bindOwner") { (view: MeshMessengerAppLockOwnerView, expected: String, promise: Promise) throws in
        // UI provenance must never wait on the native core transaction lock.
        guard let context = self.appContext else { throw MeshMessengerRootBindings.Failure.unavailable }
        let registeredModule = context.moduleRegistry.get(moduleWithName: "MeshMessenger")
        guard registeredModule === self else { throw MeshMessengerRootBindings.Failure.unavailable }
        let prepared = try view.prepareOwner(expected: expected, module: self, moduleContext: context,
          registeredModule: registeredModule, moduleID: self.rootOwnerModuleID)
        let captured = try self.rootOwnerLifecycle.withRegistered {
          try view.bindOwner(prepared)
        }
        // Neither gate validation/callbacks nor Expo event dispatch hold the
        // lifecycle mutex. An empty wake cannot grant readiness or authority.
        try self.rootOwnerLifecycle.withRegistered { () }
        try view.finishOwnerBinding(captured)
        promise.resolve(try self.makeOwnerPort(captured))
      }.runOnQueue(.main)
    }

    AsyncFunction("getAppLockState") { MeshMessengerAppLock.shared.state() }
    AsyncFunction("publishEncryptedWakeup") { (promise: Promise) throws in
      try MeshMessengerDataProtection.lockedNotices().genericWakeup { result in
        switch result { case .success: promise.resolve(nil); case .failure(let error): promise.reject(error) }
      }
    }
    AsyncFunction("bindDisabledScope") { (expected: String, promise: Promise) throws in
      promise.resolve(try MeshMessengerAppLockPort(module: self, disabled: self.disabledCall(expected: expected)))
    }
    Class(MeshMessengerAppLockPort.self) {
      // No Constructor: only native owner or verified-disabled Module factories mint this object.
      Function("checkAppLockScope") { (port: MeshMessengerAppLockPort, expected: String) throws in try port.call.requireExpected(expected).check() }
      AsyncFunction("getAppLockState") { (port: MeshMessengerAppLockPort) throws -> [String: Any] in
        return try port.publicState()
      }
      AsyncFunction("authenticateAppLock") { (port: MeshMessengerAppLockPort, expected: String) throws -> [String: Any] in
        try port.authenticate(expected, desired: nil)
      }
      AsyncFunction("setAppLockEnabled") { (port: MeshMessengerAppLockPort, enabled: Bool, expected: String) throws -> [String: Any] in
        try port.authenticate(expected, desired: enabled)
      }
      AsyncFunction("cancelAppLockAuthentication") { (port: MeshMessengerAppLockPort, request: String) throws in
        let scene = try port.ownerScope().authorization(port.call.expected)
        MeshMessengerAppLock.shared.cancel(request, ownerSceneID: scene)
      }
      AsyncFunction("lockApp") { (port: MeshMessengerAppLockPort) throws in
        _ = try port.ownerScope().authorization(port.call.expected); MeshMessengerAppLock.shared.lock()
      }
      AsyncFunction("activateAppLockScope") { (port: MeshMessengerAppLockPort, expected: String) throws in
        try port.onMain { try port.call.requireExpected(expected).check(); let scene = try port.ownerScope().authorization(expected)
          try MeshMessengerAppLock.shared.activate(expected, ownerSceneID: scene) }
      }.runOnQueue(.main)
      Function("consumeAppLockInboxIntent") { (port: MeshMessengerAppLockPort, expected: String) throws -> Bool in
        try port.privateValue(expected) { try port.ownerScope().privateValue(expected) { try MeshMessengerAppLock.shared.consumeInbox(expected) } }
      }
      Function("consumeAppLockNotificationIntent") { (port: MeshMessengerAppLockPort, expected: String) throws -> String in
        try port.privateValue(expected) { let scene = try port.ownerScope().authorization(expected)
          return try MeshMessengerAppLock.shared.consumeNotice(expected, ownerSceneID: scene) }
      }
      AsyncFunction("invokeScoped") { (port: MeshMessengerAppLockPort, symbol: String, request: Data, expected: String) throws -> Data in
        try MeshMessengerBackupRequest.requireOwner(symbol, ownerScoped: port.call.scope != nil)
        return try port.privateData(expected) { try port.module().invokeCore(symbol, request) }
      }
      AsyncFunction("walletScoped") { (port: MeshMessengerAppLockPort, operation: UInt32, request: Data, expected: String) throws -> Data in
        try port.privateData(expected) { try port.module().walletInvoke(operation, request) }
      }.runOnQueue(self.walletQueue)
      AsyncFunction("primePushTokenScoped") { (port: MeshMessengerAppLockPort, request: Data, expected: String, promise: Promise) throws in
        try port.module().beginPush(request, promise: promise, call: port.call.requireExpected(expected))
      }.runOnQueue(.main)
      AsyncFunction("clearPushTokenScoped") { (port: MeshMessengerAppLockPort, request: Data, expected: String, promise: Promise) throws in
        try port.module().clearPush(request, promise: promise, call: port.call.requireExpected(expected))
      }.runOnQueue(.main)
      AsyncFunction("openCreditPaymentScoped") { (port: MeshMessengerAppLockPort, request: Data, expected: String, promise: Promise) throws in
        try port.module().creditPayment(request, promise: promise, call: port.call.requireExpected(expected))
      }.runOnQueue(self.walletQueue)
      AsyncFunction("protectedFile") { (port: MeshMessengerAppLockPort, operation: String, frame: String, bytes: Data, expected: String, promise: Promise) throws in
        try port.protectedFile(operation, frame: frame, bytes: bytes, expected: expected, promise: promise)
      }
      AsyncFunction("publishMessageNotice") { (port: MeshMessengerAppLockPort, frame: String, expected: String, promise: Promise) throws in
        try port.publishNotice(frame, expected: expected, promise: promise)
      }
      AsyncFunction("copyProtectedText") { (port: MeshMessengerAppLockPort, text: String, expected: String) throws in
        try port.privateValue(expected) { try port.ownerScope().privateValue(expected) { try MeshMessengerAppLock.shared.copyProtectedText(text, expected: expected) } }
      }.runOnQueue(.main)
      Function("readLegacyPreference") { (port: MeshMessengerAppLockPort, profile: Data, kind: String, expected: String) throws -> String? in
        try port.privateValue(expected) { try port.readLegacy(profile, kind: kind, expected: expected) }
      }
      Function("removeLegacyPreference") { (port: MeshMessengerAppLockPort, profile: Data, kind: String, expected: String) throws in
        try port.privateValue(expected) { try port.removeLegacy(profile, kind: kind, expected: expected) }
      }
      Function("forgetLegacyPreferences") { (port: MeshMessengerAppLockPort, account: String, expected: String) throws in
        try port.privateValue(expected) { try port.forgetLegacy(account, expected: expected) }
      }
    }

    OnCreate { [self] in
      NotificationCenterManager.shared.addDelegate(self)
      MeshMessengerDataProtection.connectToNativeLaunch()
      self.removeStateObserver = MeshMessengerAppLock.shared.observe { [weak self] state in
        MeshMessengerAppLockConsent.cancelInvalidatedBeforeEvent()
        self?.sendEvent("onAppLockChanged", state)
      }
      self.removeInboxObserver = MeshMessengerAppLock.shared.observeInbox { [weak self] in self?.sendEvent("onAppLockInboxOpen", [:]) }
    }

    AsyncFunction("primePushToken") { (request: Data, promise: Promise) throws in
      try self.beginPush(request, promise: promise, call: self.disabledCall())
    }.runOnQueue(.main)
    AsyncFunction("clearPushToken") { (request: Data, promise: Promise) throws in
      try self.clearPush(request, promise: promise, call: self.disabledCall())
    }.runOnQueue(.main)

    AsyncFunction("wallet") { (operation: UInt32, request: Data) throws -> Data in
      return try self.legacyData { try self.walletInvoke(operation, request) }
    }
    .runOnQueue(self.walletQueue)

    AsyncFunction("openCreditPayment") { (request: Data, promise: Promise) throws in
      try self.creditPayment(request, promise: promise, call: self.disabledCall())
    }.runOnQueue(self.walletQueue)

    AsyncFunction("invoke") { (symbol: String, request: Data) throws -> Data in
      try MeshMessengerBackupRequest.requireOwner(symbol, ownerScoped: false)
      return try self.legacyData { try self.invokeCore(symbol, request) }
    }


    OnDestroy { [weak self] in
      guard let self else { return }
      self.rootOwnerLifecycle.dispose()
      self.removeStateObserver?(); self.removeInboxObserver?()
      // Native process observers/covers survive Module reload. Retire this
      // instance's exact registrations before waiting for any core transaction.
      let ownerModuleID = self.rootOwnerModuleID
      if Thread.isMainThread { MeshMessengerDataProtection.retireModule(ownerModuleID) }
      else { DispatchQueue.main.async { MeshMessengerDataProtection.retireModule(ownerModuleID) } }
      self.lock.lock()
      self.destroyed = true
      self.lock.unlock()
      NotificationCenterManager.shared.removeDelegate(self)
      DispatchQueue.main.async {
        self.pushEnabled = false
        self.finishPushRegistration(NSError(domain: "MorseModuleDestroyed", code: 1))
      }
      self.stop()
    }
  }

  private func requireModule() throws {
    guard let context = appContext, context.moduleRegistry.get(moduleWithName: "MeshMessenger") === self else { throw MeshMessengerRootBindings.Failure.unavailable }
    try rootOwnerLifecycle.requireAlive()
    try MeshMessengerDataProtection.requirePrivateReady()
  }
  private func disabledCall(expected: String? = nil) throws -> MeshMessengerNativeCall {
    try requireModule()
    return try MeshMessengerNativeCall(disabled: expected ?? MeshMessengerAppLock.shared.currentEpoch, gate: .shared) { [weak self] in
      guard let self else { throw MeshMessengerRootBindings.Failure.unavailable }; try self.requireModule()
    }
  }
  private func legacyData(_ body: () throws -> Data) throws -> Data {
    let call = try disabledCall(); var result = try call.data(body)
    do { try requireModule(); return result }
    catch { result.resetBytes(in: result.startIndex..<result.endIndex); throw error }
  }
  private func makeOwnerPort(_ lease: MeshMessengerRootBindings.Lease) throws -> MeshMessengerAppLockPort {
    let scope = MeshMessengerNativeOwnerScope(gate: .shared, lease: lease) { [weak self] captured in
      let action = { () throws -> String in
        guard let self else { throw MeshMessengerRootBindings.Failure.unavailable }
        try self.requireModule()
        return try MeshMessengerDataProtection.validateOwnerIdentity(captured)
      }
      if Thread.isMainThread { return try action() }
      return try DispatchQueue.main.sync(execute: action)
    }
    _ = try scope.authorization(lease.epoch)
    return try MeshMessengerAppLockPort(module: self, scope: scope)
  }

  // Only the verified disabled native constructor uses this reader. It binds
  // to its actual AppContext directory and never selects a global UI owner.
  fileprivate func headlessProfile(_ call: MeshMessengerNativeCall) throws -> Data {
    guard !Thread.isMainThread, call.scope == nil else { throw MeshMessengerRootBindings.Failure.unavailable }
    try call.check(); try requireModule()
    guard let documents = appContext?.config.documentDirectory, documents.isFileURL else { throw MeshMessengerRootBindings.Failure.unavailable }
    try MeshMessengerDataProtection.protectedFiles().requireNativeDocuments(documents)
    let request = Data(documents.appendingPathComponent("morse.db").path.utf8)
    return try call.data {
      lock.lock(); defer { lock.unlock() }; try startIfNeeded()
      return try MeshLibrary.load_profile_export(request)
    }
  }
  fileprivate func readHeadlessLegacy(_ profile: Data, kind: String, call: MeshMessengerNativeCall) throws -> String? {
    try MeshMessengerDataProtection.protectedFiles().readLegacy(profile, kind: kind, expected: call.expected,
      nativeProfile: { [weak self] expected in
        guard let self else { throw MeshMessengerRootBindings.Failure.unavailable }; _ = try call.requireExpected(expected)
        return try self.headlessProfile(call)
      })
  }
  fileprivate func removeHeadlessLegacy(_ profile: Data, kind: String, call: MeshMessengerNativeCall) throws {
    try MeshMessengerDataProtection.protectedFiles().removeLegacy(profile, kind: kind, expected: call.expected,
      nativeProfile: { [weak self] expected in
        guard let self else { throw MeshMessengerRootBindings.Failure.unavailable }; _ = try call.requireExpected(expected)
        return try self.headlessProfile(call)
      })
  }
  fileprivate func forgetHeadlessLegacy(_ account: String, call: MeshMessengerNativeCall) throws {
    try MeshMessengerDataProtection.protectedFiles().forgetLegacy(account, expected: call.expected,
      nativeProfile: { [weak self] expected in
        guard let self else { throw MeshMessengerRootBindings.Failure.unavailable }; _ = try call.requireExpected(expected)
        return try self.headlessProfile(call)
      })
  }
  private func invokeCore(_ symbol: String, _ request: Data) throws -> Data {
  if symbol.hasPrefix("mesh_messenger_backup_") {
    guard let documents = appContext?.config.documentDirectory, documents.isFileURL else { throw MeshMessengerBackupRequest.Failure.invalidRequest }
    try MeshMessengerBackupRequest.validate(symbol, request,
      expectedDatabase: Data(documents.appendingPathComponent("morse.db").path.utf8))
  }
  if MeshMessengerCreditRequest.requiresValidation(symbol) {
    guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else {
      throw NSError(domain: "MorsePayment", code: 1)
    }
    try MeshMessengerCreditRequest.validate(symbol, request, Data(database.utf8))
  }
  if symbol.hasPrefix("mesh_messenger_mailbox_stream_") || ["mesh_messenger_mailbox_synchronize", "mesh_messenger_directory_register", "mesh_messenger_prekeys_synchronize"].contains(symbol) {
    guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else {
      throw NSError(domain: "MorseMailbox", code: 1)
    }
    let path = symbol.hasSuffix("_open") || symbol.hasSuffix("_synchronize") || symbol == "mesh_messenger_directory_register" ? request : try self.walletFields(request, 2)[0]
    guard path == Data(database.utf8) else { throw NSError(domain: "MorseMailbox", code: 1) }
  }
  if symbol == "mesh_messenger_transparency_fork" || symbol == "mesh_messenger_fork_filing" {
    guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path,
      request == Data(database.utf8) else { throw NSError(domain: "MorseBounty", code: 1) }
    return try MeshMessengerBountyBridge.invokeProof(symbol, request, mesh: self.bountyMesh, sdk: self.walletSDK)
  }
  if symbol.hasPrefix("mesh_messenger_bounty_transfer_") {
    guard ["mesh_messenger_bounty_transfer_status", "mesh_messenger_bounty_transfer_recover", "mesh_messenger_bounty_transfer_cancel"].contains(symbol),
      let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else { throw NSError(domain:"MorseBounty",code:1) }
    let path = symbol.hasSuffix("_status") ? request : try self.walletFields(request,2)[0]
    guard path == Data(database.utf8) else { throw NSError(domain:"MorseBounty",code:1) }
  }
  return try MeshMessengerDataProtection.accountMutation(symbol) { transition in
  self.lock.lock()
  defer { self.lock.unlock() }
  try self.startIfNeeded(accountTransition: transition, operation: symbol)
  switch symbol {
  case "mesh_messenger_backup_create":
    return try MeshLibrary.backup_create_export(request)
  case "mesh_messenger_backup_preview":
    return try MeshLibrary.backup_preview_export(request)
  case "mesh_messenger_backup_import":
    return try MeshLibrary.backup_import_export(request)
  case "mesh_messenger_backup_list":
    return try MeshLibrary.backup_list_export(request)
  case "mesh_messenger_backup_remove":
    return try MeshLibrary.backup_remove_export(request)
  case "mesh_messenger_backup_overview":
    return try MeshLibrary.backup_overview_export(request)
  case "mesh_messenger_backup_page":
    return try MeshLibrary.backup_page_export(request)
  case "mesh_messenger_backup_pending_state":
    return try MeshLibrary.backup_pending_state_export(request)
  case "mesh_messenger_backup_pending_resume":
    return try MeshLibrary.backup_pending_resume_export(request)
  case "mesh_messenger_backup_pending_discard":
    return try MeshLibrary.backup_pending_discard_export(request)
  case "mesh_messenger_backup_pending_repair":
    return try MeshLibrary.backup_pending_repair_export(request)
  case "mesh_messenger_credit_discover_online":
    return try MeshLibrary.credit_discover_online_export(request)
  case "mesh_messenger_credit_purchase_continue":
    return try MeshLibrary.credit_purchase_continue_export(request)
  case "mesh_messenger_credit_action_continue":
    return try MeshLibrary.credit_action_continue_export(request)
  case "mesh_messenger_credit_signup_policy_online":
    return try MeshLibrary.credit_signup_policy_online_export(request)
  case "mesh_messenger_create_signup_draft":
    return try MeshLibrary.create_signup_draft_export(request)
  case "mesh_messenger_signup_draft_state":
    return try MeshLibrary.signup_draft_state_export(request)
  case "mesh_messenger_signup_draft_rename":
    return try MeshLibrary.signup_draft_rename_export(request)
  case "mesh_messenger_signup_draft_free":
    return try MeshLibrary.signup_draft_free_export(request)
  case "mesh_messenger_signup_draft_free_complete":
    return try MeshLibrary.signup_draft_free_complete_export(request)
  case "mesh_messenger_credit_signup_policy":
    return try MeshLibrary.credit_signup_policy_export(request)
  case "mesh_messenger_credit_signup_policy_view":
    return try MeshLibrary.credit_signup_policy_view_export(request)
  case "mesh_messenger_credit_signup":
    return try MeshLibrary.credit_signup_export(request)
  case "mesh_messenger_credit_signup_recover":
    return try MeshLibrary.credit_signup_recover_export(request)
  case "mesh_messenger_credit_action_recovery":
    return try MeshLibrary.credit_action_recovery_export(request)
  case "mesh_messenger_credit_postage_candidate":
    return try MeshLibrary.credit_postage_candidate_export(request)
  case "mesh_messenger_credit_postage_preview":
    return try MeshLibrary.credit_postage_preview_export(request)
  case "mesh_messenger_credit_postage_prepare":
    return try MeshLibrary.credit_postage_prepare_export(request)
  case "mesh_messenger_credit_postage_recover":
    return try MeshLibrary.credit_postage_recover_export(request)
  case "mesh_messenger_credit_attachment_grant":
    return try MeshLibrary.credit_attachment_grant_export(request)
  case "mesh_messenger_credit_attachment_upload":
    return try MeshLibrary.credit_attachment_upload_export(request)
  case "mesh_messenger_credit_attachment_complete":
    return try MeshLibrary.credit_attachment_complete_export(request)
  case "mesh_messenger_credit_attachment_delete":
    return try MeshLibrary.credit_attachment_delete_export(request)
  case "mesh_messenger_attachment_upload":
    return try MeshLibrary.attachment_upload_export(request)
  case "mesh_messenger_attachment_discard":
    return try MeshLibrary.attachment_discard_export(request)
  case "mesh_messenger_directory_resolve":
    return try MeshLibrary.directory_resolve_export(request)
  case "mesh_messenger_attachment_fetch_chunk":
    return try MeshLibrary.attachment_fetch_chunk_export(request)
  case "mesh_messenger_credit_postage_continue":
    return try MeshLibrary.credit_postage_continue_export(request)
  case "mesh_messenger_postage_policy_publish":
    return try MeshLibrary.postage_policy_publish_export(request)
  case "mesh_messenger_credit_postage_receipt":
    return try MeshLibrary.credit_postage_receipt_export(request)
  case "mesh_messenger_credit_postage_inventory":
    return try MeshLibrary.credit_postage_inventory_export(request)
  case "mesh_messenger_postage_policy_view":
    return try MeshLibrary.postage_policy_view_export(request)
  case "mesh_messenger_postage_policy_prepare":
    return try MeshLibrary.postage_policy_prepare_export(request)
  case "mesh_messenger_bounty_transfer_status":
    return try MeshLibrary.bounty_transfer_status_export(request)
  case "mesh_messenger_bounty_transfer_recover":
    return try MeshLibrary.bounty_transfer_recover_export(request)
  case "mesh_messenger_bounty_transfer_cancel":
    return try MeshLibrary.bounty_transfer_cancel_export(request)
  case "mesh_messenger_credit_attachment_prepare":
    return try MeshLibrary.credit_attachment_prepare_export(request)
  case "mesh_messenger_credit_attachment_recover":
    return try MeshLibrary.credit_attachment_recover_export(request)
  case "mesh_messenger_credit_attachment_receipt":
    return try MeshLibrary.credit_attachment_receipt_export(request)
  case "mesh_messenger_credit_attachment_part":
    return try MeshLibrary.credit_attachment_part_export(request)
  case "mesh_messenger_credit_attachment_part_recover":
    return try MeshLibrary.credit_attachment_part_recover_export(request)
  case "mesh_messenger_credit_attachment_preview":
    return try MeshLibrary.credit_attachment_preview_export(request)
  case "mesh_messenger_credit_attachments":
    return try MeshLibrary.credit_attachments_export(request)
  case "mesh_messenger_attachment_download_plan":
    return try MeshLibrary.attachment_download_plan_export(request)
  case "mesh_messenger_credit_attachment_prune":
    return try MeshLibrary.credit_attachment_prune_export(request)
  case "mesh_messenger_credit_wallet_quote":
    return try MeshLibrary.credit_wallet_quote_export(request)
  case "mesh_messenger_credit_payment_url":
    return try MeshLibrary.credit_payment_url_export(request)
  case "mesh_messenger_credit_payment_signature":
    return try MeshLibrary.credit_payment_signature_export(request)
  case "mesh_messenger_credit_retention":
    return try MeshLibrary.credit_retention_export(request)
  case "mesh_messenger_credit_retention_recover":
    return try MeshLibrary.credit_retention_recover_export(request)
  case "mesh_messenger_credit_receipt":
    return try MeshLibrary.credit_receipt_export(request)
  case "mesh_messenger_credit_discovery":
    return try MeshLibrary.credit_discovery_export(request)
  case "mesh_messenger_credit_admit":
    return try MeshLibrary.credit_admit_export(request)
  case "mesh_messenger_credit_prepare":
    return try MeshLibrary.credit_prepare_export(request)
  case "mesh_messenger_credit_prepare_again":
    return try MeshLibrary.credit_prepare_again_export(request)
  case "mesh_messenger_credit_quote":
    return try MeshLibrary.credit_quote_export(request)
  case "mesh_messenger_credit_payment":
    return try MeshLibrary.credit_payment_export(request)
  case "mesh_messenger_credit_finalize":
    return try MeshLibrary.credit_finalize_export(request)
  case "mesh_messenger_credit_recover":
    return try MeshLibrary.credit_recover_export(request)
  case "mesh_messenger_credit_purchases":
    return try MeshLibrary.credit_purchases_export(request)
  case "mesh_messenger_credit_balance":
    return try MeshLibrary.credit_balance_export(request)
  case "mesh_messenger_credit_reserve":
    return try MeshLibrary.credit_reserve_export(request)
  case "mesh_messenger_credit_reservation":
    return try MeshLibrary.credit_reservation_export(request)
  case "mesh_messenger_initialize":
    return try MeshLibrary.initialize(request)
  case "mesh_messenger_validate_outer":
    return try MeshLibrary.validate_outer(request)
  case "mesh_messenger_store_envelope":
    return try MeshLibrary.persist_envelope(request)
  case "mesh_messenger_create_account":
    return try MeshLibrary.create_account_export(request)
  case "mesh_messenger_journal_load_bound":
    return try MeshLibrary.journal_load_bound_export(request)
  case "mesh_messenger_journal_save_bound":
    return try MeshLibrary.journal_save_bound_export(request)
  case "mesh_messenger_presentation_load":
    return try MeshLibrary.presentation_load_export(request)
  case "mesh_messenger_presentation_save":
    return try MeshLibrary.presentation_save_export(request)
  case "mesh_messenger_load_profile":
    return try MeshLibrary.load_profile_export(request)
  case "mesh_messenger_create_link_request":
    return try MeshLibrary.create_link_request_export(request)
  case "mesh_messenger_device_link_sas":
    return try MeshLibrary.device_link_sas_export(request)
  case "mesh_messenger_authorize_device_link_for_set":
    return try MeshLibrary.authorize_device_link_for_set_export(request)
  case "mesh_messenger_complete_device_link":
    return try MeshLibrary.complete_device_link_export(request)
  case "mesh_messenger_inspect_device_set":
    return try MeshLibrary.inspect_device_set_export(request)
  case "mesh_messenger_receive_initial":
    return try MeshLibrary.receive_initial_export(request)
  case "mesh_messenger_group_invitation_complete":
    return try MeshLibrary.group_invitation_complete_export(request)
  case "mesh_messenger_group_invitation_decline":
    return try MeshLibrary.group_invitation_decline_export(request)
  case "mesh_messenger_group_invitations":
    return try MeshLibrary.group_invitations_export(request)
  case "mesh_messenger_group_forget":
    return try MeshLibrary.group_forget_export(request)
  case "mesh_messenger_group_key_package":
    return try MeshLibrary.group_key_package_export(request)
  case "mesh_messenger_group_create":
    return try MeshLibrary.group_create_export(request)
  case "mesh_messenger_group_add":
    return try MeshLibrary.group_add_export(request)
  case "mesh_messenger_group_remove":
    return try MeshLibrary.group_remove_export(request)
  case "mesh_messenger_group_send":
    return try MeshLibrary.group_send_export(request)
  case "mesh_messenger_group_receive":
    return try MeshLibrary.group_receive_export(request)
  case "mesh_messenger_group_list":
    return try MeshLibrary.group_list_export(request)
  case "mesh_messenger_group_inspect":
    return try MeshLibrary.group_inspect_export(request)
  case "mesh_messenger_group_history":
    return try MeshLibrary.group_history_export(request)
  case "mesh_messenger_group_policy":
    return try MeshLibrary.group_policy_export(request)
  case "mesh_messenger_receive_message":
    return try MeshLibrary.receive_message_export(request)
  case "mesh_messenger_update_conversation":
    return try MeshLibrary.update_conversation_export(request)
  case "mesh_messenger_push_flow_begin":
    return try MeshLibrary.push_flow_begin_export(request)
  case "mesh_messenger_account_delete":
    return try MeshLibrary.account_delete_export(request)
  case "mesh_messenger_account_discard":
    return try MeshLibrary.account_discard_export(request)
  case "mesh_messenger_account_capabilities":
    return try MeshLibrary.account_capabilities_export(request)
  case "mesh_messenger_devices_renew":
    return try MeshLibrary.devices_renew_export(request)
  case "mesh_messenger_device_revoke":
    return try MeshLibrary.device_revoke_export(request)
  case "mesh_messenger_push_flow_complete":
    return try MeshLibrary.push_flow_complete_export(request)
  case "mesh_messenger_push_flow_send":
    return try MeshLibrary.push_flow_send_export(request)
  case "mesh_messenger_fanout_send":
    return try MeshLibrary.fanout_send_export(request)
  case "mesh_messenger_outbox_drain":
    return try MeshLibrary.outbox_drain_export(request)
  case "mesh_messenger_push_status":
    return try MeshLibrary.push_status_export(request)
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
case "mesh_messenger_bounty_status":
    return try MeshLibrary.bounty_status_export(request)
  case "mesh_messenger_network_counter":
    guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path,
      request == Data(database.utf8) else { throw NSError(domain: "MorseDatabasePath", code: 1) }
    return try MeshLibrary.network_counter_export(request)
  case "mesh_messenger_anchor_check":
    return try MeshLibrary.anchor_check_export(request)
  case "mesh_messenger_directory_register":
    return try MeshLibrary.directory_register_export(request)
  case "mesh_messenger_prekeys_synchronize":
    return try MeshLibrary.prekeys_synchronize_export(request)
  case "mesh_messenger_mailbox_synchronize":
    return try MeshLibrary.mailbox_synchronize_export(request)
  case "mesh_messenger_mailbox_stream_open":
    return try MeshLibrary.mailbox_stream_open_export(request)
  case "mesh_messenger_mailbox_stream_poll":
    return try MeshLibrary.mailbox_stream_poll_export(request)
  case "mesh_messenger_mailbox_stream_close":
    return try MeshLibrary.mailbox_stream_close_export(request)
  default:
    throw MeshLibraryFailure(
      status: MESH_LIBRARY_ERR_INVALID_ARGUMENT,
      payload: Data("unknown_export".utf8)
    )
  }
  }
  }

  public func didRegister(_ deviceToken: String) {
    guard pushEnabled else { return }
    if let request = pushRequest {
      do {
        guard let call = pushCall else { throw MeshMessengerRootBindings.Failure.unavailable }
        try call.value { try withPushAction(request, kind: 2, call: call) { try cachePushToken(deviceToken) } }
        finishPushRegistration(nil)
      } catch { finishPushRegistration(error) }
    } else {
      // OS refresh tokens belong to the installation. Mesh decides whether a
      // current account wants a binding when the UI resumes its saved intent.
      do { try cachePushToken(deviceToken); sendEvent("onPushRegistrationChanged", [:]) }
      catch { }
    }
  }

  public func didFailRegistration(_ error: any Error) {
    finishPushRegistration(error)
  }

  private func finishPushRegistration(_ error: (any Error)?) {
    let promise = pushPromise
    let finished = pushFinished
    let call = pushCall
    pushPromise = nil
    pushRequest = nil
    pushOperationID = nil
    pushFinished = nil; pushCall = nil
    if let error { promise?.reject(error) }
    else { do { try call?.check(); promise?.resolve(nil) } catch { promise?.reject(error) } }
    finished?()
  }

  private func beginPush(_ request: Data, promise: Promise, call: MeshMessengerNativeCall) throws {
    try call.check()
    Self.pushOperations.enqueue { finished in
      do {
        try call.value {
          try self.withPushAction(request, kind: 2, call: call) {
            let operationID = UUID()
            self.pushEnabled = true; self.pushPromise = promise; self.pushRequest = request
            self.pushOperationID = operationID; self.pushFinished = finished; self.pushCall = call
            UIApplication.shared.registerForRemoteNotifications()
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
              if self.pushOperationID == operationID { self.finishPushRegistration(NSError(domain: "MorsePushRegistrationTimeout", code: 1)) }
            }
          }
        }
      } catch { promise.reject(error); finished() }
    }
  }
  private func clearPush(_ request: Data, promise: Promise, call: MeshMessengerNativeCall) throws {
    try call.check()
    Self.pushOperations.enqueue { finished in
      defer { finished() }
      do {
        try call.value {
          try self.withPushAction(request, kind: 5, call: call) {
            self.pushEnabled = false; MeshMessengerClearApplePushToken(); UIApplication.shared.unregisterForRemoteNotifications()
          }
        }
        promise.resolve(nil)
      } catch { promise.reject(error) }
    }
  }
  private func withPushAction(_ request: Data, kind: UInt8, call: MeshMessengerNativeCall, work: () throws -> Void) throws {
    lock.lock()
    do {
      guard !destroyed, let path = appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else { throw NSError(domain: "MorsePushUnavailable", code: 1) }
      try MeshMessengerCreditRequest.validate("mesh_messenger_push_flow_send", request, Data(path.utf8))
      try startIfNeeded()
      guard try MeshLibrary.push_flow_validate_export(request) == Data([kind]) else { throw NSError(domain: "MorsePushAction", code: 1) }
      lock.unlock()
    } catch { lock.unlock(); throw error }
    // UIKit and actual native provenance stay outside the core transaction lock.
    try call.publication(work)
  }
  private func creditPayment(_ request: Data, promise: Promise, call: MeshMessengerNativeCall) throws {
    try call.check()
    guard call.scope != nil else { throw MeshMessengerRootBindings.Failure.unavailable }
    let fields = try walletFields(request, 2)
    guard let database = appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path,
          fields[0] == Data(database.utf8), fields[1].count == 32 else { throw NSError(domain: "MorsePayment", code: 1) }
    var result = try call.data {
      lock.lock(); defer { lock.unlock() }; try startIfNeeded()
      return try MeshLibrary.credit_payment_handoff_export(request)
    }
    defer { result.resetBytes(in: result.startIndex..<result.endIndex) }
    guard let text = String(data: result, encoding: .utf8),
      (text.hasPrefix("solana:") && text.utf8.count <= 4096 || text.range(of: "^lightning:[A-Za-z0-9]{1,7089}$", options: .regularExpression) != nil),
      !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }), let url = URL(string: text) else { throw NSError(domain: "MorsePayment", code: 2) }
    DispatchQueue.main.async {
      do {
        try call.publication {
          UIApplication.shared.open(url, options: [:]) { opened in
          do {
            try call.check()
            if opened { promise.resolve(nil) } else { promise.reject("E_EXTERNAL_WALLET", "external_wallet_unavailable") }
          } catch { promise.reject(error) }
          }
        }
      } catch { promise.reject(error) }
    }
  }

  private func walletFields(_ request: Data, _ expected: Int, _ maximum: Int = 8192) throws -> [Data] {
    var cursor = 0
    func u32() throws -> Int {
      guard cursor + 4 <= request.count else { throw NSError(domain: "MorseWallet", code: 1) }
      let value = request[cursor..<cursor+4].reduce(0) { ($0 << 8) | Int($1) }
      cursor += 4
      return value
    }
    guard request.count <= maximum, try u32() == expected else { throw NSError(domain: "MorseWallet", code: 1) }
    var fields: [Data] = []
    for _ in 0..<expected {
      let count = try u32()
      guard count <= request.count - cursor else { throw NSError(domain: "MorseWallet", code: 1) }
      fields.append(request.subdata(in: cursor..<cursor+count)); cursor += count
    }
    guard cursor == request.count else { throw NSError(domain: "MorseWallet", code: 1) }
    return fields
  }

  private func walletPacket(_ fields: [Data]) -> Data {
    let count = UInt32(fields.count)
    var journal = Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16), UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)])
    for field in fields {
      let count = UInt32(field.count)
      journal.append(contentsOf: [UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16), UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)])
      journal.append(field)
    }
    return journal
  }

  private func bountyMesh(_ symbol: String, _ request: Data) throws -> Data {
    self.lock.lock()
    defer { self.lock.unlock() }
    try self.startIfNeeded()
    switch symbol {
    case "mesh_messenger_bounty_transfer_prepare": return try MeshLibrary.bounty_transfer_prepare_export(request)
    case "mesh_messenger_bounty_transfer_commit": return try MeshLibrary.bounty_transfer_commit_export(request)
    case "mesh_messenger_bounty_transfer_submit": return try MeshLibrary.bounty_transfer_submit_export(request)
    case "mesh_messenger_bounty_transfer_status": return try MeshLibrary.bounty_transfer_status_export(request)
    case "mesh_messenger_bounty_transfer_recover": return try MeshLibrary.bounty_transfer_recover_export(request)
    case "mesh_messenger_bounty_transfer_cancel": return try MeshLibrary.bounty_transfer_cancel_export(request)
    case "mesh_messenger_bounty_status": return try MeshLibrary.bounty_status_export(request)
    case "mesh_messenger_bounty_set_enabled": return try MeshLibrary.bounty_set_enabled_export(request)
    case "mesh_messenger_bounty_commit": return try MeshLibrary.bounty_commit_export(request)
    case "mesh_messenger_bounty_unavailable": return try MeshLibrary.bounty_unavailable_export(request)
    case "mesh_messenger_transparency_fork": return try MeshLibrary.transparency_fork_export(request)
    case "mesh_messenger_fork_filing": return try MeshLibrary.fork_filing_export(request)
    default: throw NSError(domain: "MorseBounty", code: 1)
    }
  }

  private func walletMesh(_ operation: Int, _ request: Data) throws -> Data {
    self.lock.lock()
    defer { self.lock.unlock() }
    try self.startIfNeeded()
    if operation == 0 { return try MeshLibrary.credit_wallet_prepare_export(request) }
    if operation == 1 { return try MeshLibrary.credit_wallet_commit_export(request) }
    return try MeshLibrary.credit_wallet_submit_export(request)
  }

  private func walletSDK(_ operation: UInt32, _ payload: Data) throws -> Data {
    // Never hold the Mesh lock while a native confirmation is on screen.
    var output = Data(count: 1232)
    var written: UInt64 = 0
    let status = payload.withUnsafeBytes { input in
      output.withUnsafeMutableBytes { buffer in
        MeshMessengerWalletCall(operation, input.bindMemory(to: UInt8.self).baseAddress, UInt64(payload.count),
          buffer.bindMemory(to: UInt8.self).baseAddress, 1232, &written)
      }
    }
    guard status == 0, written <= 1232 else { throw NSError(domain: "MorseWallet", code: Int(status)) }
    output.count = Int(written)
    return output
  }

  private func walletResult(_ data: Data, _ id: Data) throws -> Data {
    let result = try walletFields(data, 4, 2048)
    guard result[0] == Data([1, 77, 87, 82]), result[1] == id, result[2].count == 1,
      result[2][0] <= 1, result[3].count == 64 else { throw NSError(domain: "MorseWallet", code: 1) }
    return data
  }

  private func walletInvoke(_ operation: UInt32, _ request: Data) throws -> Data {
    if operation == 7 {
      guard request.count == 1, let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else { throw NSError(domain: "MorseBounty", code: 1) }
      return try MeshMessengerBountyBridge.setEnabled(Data(database.utf8), request[0], mesh: self.bountyMesh, sdk: self.walletSDK)
    }
    if operation == 8 {
      guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path else { throw NSError(domain:"MorseBounty",code:1) }
      return try MeshMessengerBountyBridge.movement(request,database:Data(database.utf8),mesh:self.bountyMesh,sdk:self.walletSDK)
    }
    if operation == 5 || operation == 6 {
      let fields = try walletFields(request, 2)
      guard let database = self.appContext?.config.documentDirectory?.appendingPathComponent("morse.db").path,
        fields[0] == Data(database.utf8), fields[1].count == 32 else { throw NSError(domain: "MorseWallet", code: 1) }
      if operation == 5 {
        let payer = try walletSDK(2, Data())
        guard payer.count == 32 else { throw NSError(domain: "MorseWallet", code: 1) }
        let plan = try walletFields(walletMesh(0, walletPacket([fields[0], fields[1], payer])), 6, 2048)
        guard plan[0] == Data([1, 77, 87, 80]), plan[1] == fields[1], plan[2].count == 1,
          plan[2][0] <= 1, plan[3].count == 224, plan[4].count == 32,
          (plan[2][0] == 0 ? plan[5].isEmpty : plan[5].count == 64) else { throw NSError(domain: "MorseWallet", code: 1) }
        if plan[2][0] == 0 {
          let wire = try walletSDK(3, plan[3] + plan[4])
          _ = try walletResult(walletMesh(1, walletPacket([fields[0], fields[1], wire])), fields[1])
        }
      }
      return try walletResult(walletMesh(2, request), fields[1])
    }
    guard (operation == 1 || operation == 2), request.isEmpty else { throw NSError(domain: "MorseWallet", code: 1) }
    self.lock.lock()
    do { try self.startIfNeeded(); self.lock.unlock() }
    catch { self.lock.unlock(); throw error }
    return try walletSDK(operation, Data())
  }

  private func startIfNeeded(accountTransition: MeshMessengerNativeAccountTransitions.Ticket? = nil, operation: String? = nil) throws {
    guard !destroyed else { throw MeshMessengerRootBindings.Failure.unavailable }
    try rootOwnerLifecycle.requireAlive()
    // The same originally admitted epoch is checked after waiting for the core
    // lock. No caller can refresh it from a newer public state here.
    if let accountTransition {
      guard let operation else { throw MeshMessengerRootBindings.Failure.unavailable }
      try accountTransition.consume(operation)
    } else {
      try MeshMessengerDataProtection.requirePrivateReady()
      _ = try MeshMessengerAppLock.shared.capturedCallEpoch()
    }
    guard !started else { return }
    try MeshMessengerDataProtection.initializeNativeCore()
    started = true
  }

  // The Mesh runtime starts once per process and cannot start again after
  // shutting down, while React tears this module down on every reload (an
  // update being applied, a development refresh). It keeps running; the next
  // instance registers the host callbacks again.
  private func stop() {
    lock.lock()
    defer { lock.unlock() }
    started = false
  }

  private func cachePushToken(_ token: String) throws {
    guard let applicationID = Bundle.main.bundleIdentifier else {
      throw PushRegistrationConfigurationError.missingApplicationID
    }
    let applicationIDBytes = Data(applicationID.utf8)
    let tokenBytes = Data(token.utf8)
    let development = EXProvisioningProfile.main().notificationServiceEnvironment() == "development"
    let status = applicationIDBytes.withUnsafeBytes { applicationIDBuffer in
      tokenBytes.withUnsafeBytes { tokenBuffer in
        MeshMessengerCacheApplePushToken(
          applicationIDBuffer.bindMemory(to: UInt8.self).baseAddress,
          UInt64(applicationIDBuffer.count),
          tokenBuffer.bindMemory(to: UInt8.self).baseAddress,
          UInt64(tokenBuffer.count),
          development
        )
      }
    }
    guard status == MESH_LIBRARY_OK else {
      throw PushRegistrationConfigurationError.invalidMaterial
    }
  }
}

private enum PushRegistrationConfigurationError: Error {
  case missingApplicationID
  case invalidMaterial
}

// The native constructor path determines owner vs disabled data provenance.
// Neither path accepts a caller-supplied mode, view selector or scene identity.
final class MeshMessengerAppLockPort: SharedObject {
  let call: MeshMessengerNativeCall
  private weak var ownerModule: MeshMessengerModule?
  init(module: MeshMessengerModule, scope: MeshMessengerNativeOwnerScope) throws {
    ownerModule = module; call = try MeshMessengerNativeCall(scope: scope, expected: scope.expected); super.init()
  }
  init(module: MeshMessengerModule, disabled call: MeshMessengerNativeCall) throws {
    guard call.scope == nil else { throw MeshMessengerRootBindings.Failure.unavailable }
    try call.check(); ownerModule = module; self.call = call; super.init()
  }
  func module() throws -> MeshMessengerModule {
    guard let value = ownerModule else { throw MeshMessengerRootBindings.Failure.unavailable }; return value
  }
  func ownerScope() throws -> MeshMessengerNativeOwnerScope {
    try call.requireOpen()
    guard let scope = call.scope else { throw MeshMessengerRootBindings.Failure.unavailable }; return scope
  }
  func onMain<T>(_ action: () throws -> T) rethrows -> T {
    if Thread.isMainThread { return try action() }; return try DispatchQueue.main.sync(execute: action)
  }
  func publicState() throws -> [String: Any] {
    try call.requireOpen()
    if let scope = call.scope { _ = try scope.authorizationCompletion() } else { try call.check() }
    return MeshMessengerAppLock.shared.state()
  }
  func authenticate(_ expected: String, desired: Bool?) throws -> [String: Any] {
    let scope = try ownerScope(), scene = try scope.authorization(expected)
    let value = try MeshMessengerAppLock.shared.authenticate(expected, ownerSceneID: scene, desired: desired)
    _ = try scope.authorizationCompletion(); return value
  }
  func privateData(_ expected: String, body: () throws -> Data) throws -> Data {
    _ = try call.requireExpected(expected)
    return try call.data {
      if let scope = call.scope { return try MeshMessengerDataProtection.withNativeConsent(scope, body: body) }
      return try body()
    }
  }
  func privateValue<T>(_ expected: String, body: () throws -> T) throws -> T {
    _ = try call.requireExpected(expected); return try call.value(body)
  }
  func protectedFile(_ operation: String, frame: String, bytes: Data, expected: String, promise: Promise) throws {
    // A windowless data scope never borrows a UI source/destination/preview
    // handle. Its only filesystem bridge below is account-bound legacy data.
    let scope = try ownerScope()
    let cleanup = ["abortExport", "releasePreview", "closeSource", "discardPreviews"].contains(operation)
    guard expected == call.expected else { throw MeshMessengerRootBindings.Failure.stale }
    if !cleanup { try scope.check(expected) }
    try MeshMessengerDataProtection.protectedFiles().dispatchAsync(operation, frame: frame, bytes: bytes, expected: expected) { result in
      do {
        let value = try result.get()
        do { if !cleanup { try scope.check(expected) }; promise.resolve(value) }
        catch { if var data = value as? Data { data.resetBytes(in: data.startIndex..<data.endIndex) }; throw error }
      } catch { promise.reject(error) }
    }
  }
  func publishNotice(_ frame: String, expected: String, promise: Promise) throws {
    _ = try call.requireExpected(expected)
    let notices = try MeshMessengerDataProtection.lockedNotices()
    if let scope = call.scope {
      scope.publishNotice(frame, notices: notices, expected: expected) { result in
        switch result { case .success: promise.resolve(nil); case .failure(let error): promise.reject(error) }
      }
    } else {
      notices.publish(frame, expected: expected, publication: { add in
        try self.onMain { try self.call.publication(add) }
      }) { result in
        do { try result.get(); try self.call.check(); promise.resolve(nil) } catch { promise.reject(error) }
      }
    }
  }
  func readLegacy(_ profile: Data, kind: String, expected: String) throws -> String? {
    _ = try call.requireExpected(expected)
    if call.scope != nil { return try MeshMessengerDataProtection.protectedFiles().readLegacy(profile, kind: kind, expected: expected) }
    return try module().readHeadlessLegacy(profile, kind: kind, call: call)
  }
  func removeLegacy(_ profile: Data, kind: String, expected: String) throws {
    _ = try call.requireExpected(expected)
    if call.scope != nil { try MeshMessengerDataProtection.protectedFiles().removeLegacy(profile, kind: kind, expected: expected) }
    else { try module().removeHeadlessLegacy(profile, kind: kind, call: call) }
  }
  func forgetLegacy(_ account: String, expected: String) throws {
    _ = try call.requireExpected(expected)
    if call.scope != nil { try MeshMessengerDataProtection.protectedFiles().forgetLegacy(account, expected: expected) }
    else { try module().forgetHeadlessLegacy(account, call: call) }
  }
  override func sharedObjectWillRelease() {
    call.close(); super.sharedObjectWillRelease()
    // Never synchronously dispatch Main while Expo releases its native object.
    DispatchQueue.main.async { MeshMessengerAppLockConsent.cancelInvalidatedBeforeEvent() }
  }
}
