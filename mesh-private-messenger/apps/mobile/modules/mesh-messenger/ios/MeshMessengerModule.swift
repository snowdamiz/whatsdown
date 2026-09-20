import EXApplication
import ExpoModulesCore
import ExpoNotifications
import Foundation
import UIKit

public final class MeshMessengerModule: Module, NotificationDelegate {
  private let lock = NSLock()
  private var started = false
  private var pushEnabled = false
  private var pushPromise: Promise?

  public func definition() -> ModuleDefinition {
    Name("MeshMessenger")

    Events("onPushRegistrationChanged")

    OnCreate {
      NotificationCenterManager.shared.addDelegate(self)
      MeshMessengerDataProtection.excludeAppDataFromBackup()
      MeshMessengerDataProtection.startCoveringInactiveWindow()
    }

    AsyncFunction("primePushToken") { (promise: Promise) in
      self.pushPromise?.reject(
        "E_PUSH_REGISTRATION_REPLACED",
        "A newer push registration request replaced this one."
      )
      self.pushEnabled = true
      self.pushPromise = promise
      UIApplication.shared.registerForRemoteNotifications()
    }
    .runOnQueue(.main)

    AsyncFunction("clearPushToken") { () in
      self.pushEnabled = false
      self.pushPromise?.reject(
        "E_PUSH_REGISTRATION_CANCELLED",
        "Push registration was cancelled."
      )
      self.pushPromise = nil
      MeshMessengerClearApplePushToken()
      UIApplication.shared.unregisterForRemoteNotifications()
    }
    .runOnQueue(.main)

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
      case "mesh_messenger_presentation_load":
        return try MeshLibrary.presentation_load_export(request)
      case "mesh_messenger_presentation_save":
        return try MeshLibrary.presentation_save_export(request)
      case "mesh_messenger_load_profile":
        return try MeshLibrary.load_profile_export(request)
      case "mesh_messenger_replenish_prekeys":
        return try MeshLibrary.replenish_prekeys_export(request)
      case "mesh_messenger_reconcile_prekeys":
        return try MeshLibrary.reconcile_prekeys_export(request)
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
      case "mesh_messenger_create_device_revocation":
        return try MeshLibrary.create_device_revocation_export(request)
      case "mesh_messenger_receive_initial":
        return try MeshLibrary.receive_initial_export(request)
      case "mesh_messenger_prepare_fanout_prekeys":
        return try MeshLibrary.prepare_fanout_prekeys_export(request)
      case "mesh_messenger_send_fanout":
        return try MeshLibrary.send_fanout_export(request)
      case "mesh_messenger_group_invite":
        return try MeshLibrary.group_invite_export(request)
      case "mesh_messenger_group_invitation_accept":
        return try MeshLibrary.group_invitation_accept_export(request)
      case "mesh_messenger_group_invitation_complete":
        return try MeshLibrary.group_invitation_complete_export(request)
      case "mesh_messenger_group_invitation_decline":
        return try MeshLibrary.group_invitation_decline_export(request)
      case "mesh_messenger_group_invitations":
        return try MeshLibrary.group_invitations_export(request)
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
      case "mesh_messenger_receive_message":
        return try MeshLibrary.receive_message_export(request)
      case "mesh_messenger_update_conversation":
        return try MeshLibrary.update_conversation_export(request)
      case "mesh_messenger_push_intent":
        return try MeshLibrary.push_intent_export(request)
      case "mesh_messenger_push_action_complete":
        return try MeshLibrary.push_action_complete_export(request)
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
      case "mesh_messenger_directory_lookup":
        return try MeshLibrary.directory_lookup_export(request)
      case "mesh_messenger_transparency_lookup":
        return try MeshLibrary.transparency_lookup_export(request)
      case "mesh_messenger_register_request":
        return try MeshLibrary.register_request_export(request)
      case "mesh_messenger_resolve_request":
        return try MeshLibrary.resolve_request_export(request)
      case "mesh_messenger_verify_transparency":
        return try MeshLibrary.verify_transparency_export(request)
      case "mesh_messenger_privacy_submission":
        return try MeshLibrary.privacy_submission_export(request)
      case "mesh_messenger_mailbox_fetch":
        return try MeshLibrary.mailbox_fetch_export(request)
      case "mesh_messenger_process_delivery_batch":
        return try MeshLibrary.process_delivery_batch_export(request)
      case "mesh_messenger_outbox_list":
        return try MeshLibrary.outbox_list_export(request)
      case "mesh_messenger_outbox_ack":
        return try MeshLibrary.outbox_ack_export(request)
      case "mesh_messenger_attachment_prepare":
        return try MeshLibrary.attachment_prepare_export(request)
      case "mesh_messenger_attachment_seal_chunk":
        return try MeshLibrary.attachment_seal_chunk_export(request)
      case "mesh_messenger_attachment_open_chunk":
        return try MeshLibrary.attachment_open_chunk_export(request)
      default:
        throw MeshLibraryFailure(
          status: MESH_LIBRARY_ERR_INVALID_ARGUMENT,
          payload: Data("unknown_export".utf8)
        )
      }
    }

    OnDestroy { [weak self] in
      guard let self else { return }
      NotificationCenterManager.shared.removeDelegate(self)
      MeshMessengerDataProtection.stop()
      self.pushEnabled = false
      self.pushPromise?.reject("E_MODULE_DESTROYED", "MeshMessenger was destroyed.")
      self.pushPromise = nil
      MeshMessengerClearApplePushToken()
      self.stop()
    }
  }

  public func didRegister(_ deviceToken: String) {
    guard pushEnabled else { return }
    let isRefresh = pushPromise == nil
    do {
      try cachePushToken(deviceToken)
      pushPromise?.resolve(nil)
      pushPromise = nil
      if isRefresh {
        sendEvent("onPushRegistrationChanged", [:])
      }
    } catch {
      pushPromise?.reject(error)
      pushPromise = nil
    }
  }

  public func didFailRegistration(_ error: any Error) {
    pushPromise?.reject(error)
    pushPromise = nil
  }

  private func startIfNeeded() throws {
    guard !started else { return }
    try MeshLibrary.initialize()
    let status = MeshMessengerRegisterAppleHostCallbacks()
    guard status == MESH_LIBRARY_OK else {
      throw MeshLibraryFailure(
        status: status,
        payload: Data("host_callback_registration_failed".utf8)
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
