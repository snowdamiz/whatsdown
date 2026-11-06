import { type EventSubscription, requireNativeModule, requireNativeViewManager } from 'expo-modules-core';
import { Platform, type ViewProps } from 'react-native';
import type { ReactNode, Ref } from 'react';
import { bindAppLockOwnerPort, type AppLockNativeOwner, type AppLockNativePort } from '../../src/app-lock';

// A fixed build-surface discriminator, never an authentication result.
export const isLegacyDesktopBridge = false;

export {
  fanout_send_export,
  push_flow_begin_export,
  account_delete_export,
  account_discard_export,
  account_capabilities_export,
  devices_renew_export,
  device_revoke_export,
  attachment_upload_export,
  attachment_discard_export,
  directory_resolve_export,
  credit_attachment_grant_export,
  credit_attachment_upload_export,
  credit_attachment_complete_export,
  credit_attachment_delete_export,
  attachment_fetch_chunk_export,

  credit_discover_online_export,
  credit_purchase_continue_export,
  credit_action_continue_export,
  credit_signup_policy_online_export,
  bounty_transfer_status_export,
  bounty_transfer_recover_export,
  bounty_transfer_cancel_export,
  bounty_status_export,
  credit_postage_candidate_export,
  credit_postage_preview_export,
  credit_postage_prepare_export,
  credit_postage_recover_export,
  credit_postage_receipt_export,
  credit_postage_continue_export,
  credit_postage_inventory_export,
  postage_policy_view_export,
  postage_policy_prepare_export,
  postage_policy_publish_export,
  credit_attachment_preview_export,
  credit_attachments_export,
  attachment_download_plan_export,
  credit_attachment_prune_export,
  credit_attachment_part_recover_export,
  credit_attachment_part_export,
  credit_attachment_receipt_export,
  credit_attachment_recover_export,
  credit_attachment_prepare_export,
  signup_draft_free_complete_export,
  create_signup_draft_export,
  signup_draft_state_export,
  signup_draft_rename_export,
  signup_draft_free_export,
  credit_signup_policy_export,
  credit_signup_policy_view_export,
  credit_signup_export,
  credit_signup_recover_export,
  credit_action_recovery_export,
  register_signup_policy_export,
  credit_prepare_again_export,
  credit_wallet_quote_export,
  credit_payment_url_export,
  credit_payment_signature_export,
  credit_retention_export,
  credit_retention_recover_export,
  credit_receipt_export,
  credit_discovery_export,
  credit_admit_export,
  credit_prepare_export,
  credit_quote_export,
  credit_payment_export,
  credit_finalize_export,
  credit_recover_export,
  credit_purchases_export,
  credit_balance_export,
  credit_reserve_export,
  credit_reservation_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
  journal_load_bound_export,
  journal_save_bound_export,
  presentation_load_export,
  presentation_save_export,
  create_account_export,
  create_link_request_export,
  device_link_sas_export,
  directory_entry_export,
  directory_lookup_export,
  group_add_export,
  group_create_export,
  group_history_export,
  group_policy_export,
  group_inspect_export,
  group_key_package_export,
  group_invitation_complete_export,
  group_invitation_decline_export,
  group_invitations_export,
  group_forget_export,
  group_list_export,
  group_receive_export,
  group_remove_export,
  group_send_export,
  import_contact_export,
  initialize,
  authorize_device_link_for_set_export,
  complete_device_link_export,
  inspect_device_set_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  mailbox_fetch_export,
  mailbox_synchronize_export,
  directory_register_export,
  prekeys_synchronize_export,
  mailbox_stream_open_export,
  mailbox_stream_poll_export,
  mailbox_stream_close_export,
  persist_envelope,
  process_delivery_batch_export,
  push_flow_complete_export,
  push_flow_send_export,
  push_status_export,
  outbox_drain_export,
  replenish_prekeys_export,
  reconcile_prekeys_export,
  receive_initial_export,
  receive_message_export,
  safety_number_export,
  transparency_lookup_export,
  transparency_fork_export,
  anchor_check_export,
  network_counter_export,
  fork_filing_export,
  register_request_export,
  resolve_request_export,
  resolve_plan_export,
  update_conversation_export,
  validate_outer,
  verify_transparency_export,
} from './generated/libmessenger_mobile';

type PushNativeModule = {
  bindDisabledScope(expectedEpoch: string): Promise<AppLockNativeOwner>;
  activateAppLockScope(expectedEpoch: string): Promise<void>;
  openCreditPayment(request: Uint8Array): Promise<void>;
  wallet(operation: number, request: Uint8Array): Promise<Uint8Array>;
  primePushToken(request: Uint8Array): Promise<void>;
  clearPushToken(request: Uint8Array): Promise<void>;
  addListener(
    event: 'onPushRegistrationChanged',
    listener: () => void,
  ): EventSubscription;
};

const pushNative = requireNativeModule<PushNativeModule & AppLockNativePort>('MeshMessenger');
export type AppLockOwnerHandle = { bindOwner(expectedEpoch: string): Promise<AppLockNativeOwner> };
type AppLockOwnerProps = ViewProps & { children?: ReactNode; ref?: Ref<AppLockOwnerHandle>; onOwnerAttached?: () => void };
export const AppLockOwnerView = Platform.OS === 'ios'
  ? requireNativeViewManager<AppLockOwnerProps>('MeshMessenger', 'AppLockOwner') : undefined;
export const getAppLockNativePort = (): AppLockNativePort => pushNative;
export async function bindDisabledAppLockScope(expectedEpoch: string) {
  if (Platform.OS !== 'ios') {
    // Android keeps its separately prepared native module/epoch transport. It
    // creates no SDK SharedObject; AppLockSession owns the task's JS cleanup.
    pushNative.checkAppLockScope(expectedEpoch);
    return Object.freeze({ port: pushNative, release() {} });
  }
  const object = await pushNative.bindDisabledScope(expectedEpoch);
  return bindAppLockOwnerPort(object, pushNative, expectedEpoch);
}

export const activateAppLockScope = (expectedEpoch: string): Promise<void> => pushNative.activateAppLockScope(expectedEpoch);
export function onAppLockChanged(listener: (value: unknown) => void): () => void {
  const subscription = pushNative.addListener('onAppLockChanged', listener);
  return () => subscription.remove();
}

export const primePushToken = (request: Uint8Array): Promise<void> => pushNative.primePushToken(request);
export const clearPushToken = (request: Uint8Array): Promise<void> => pushNative.clearPushToken(request);

export function onPushRegistrationChanged(listener: () => void): () => void {
  const subscription = pushNative.addListener('onPushRegistrationChanged', listener);
  return () => subscription.remove();
}

export const invokeWallet = (operation: number, request: Uint8Array): Promise<Uint8Array> => pushNative.wallet(operation, request);

export const openNativeCreditPayment = (request: Uint8Array): Promise<void> => pushNative.openCreditPayment(request);
