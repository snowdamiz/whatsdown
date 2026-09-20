import { type EventSubscription, requireNativeModule } from 'expo-modules-core';

export {
  attachment_open_chunk_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
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
  group_inspect_export,
  group_key_package_export,
  group_invite_export,
  group_invitation_accept_export,
  group_invitation_complete_export,
  group_invitation_decline_export,
  group_invitations_export,
  group_list_export,
  group_receive_export,
  group_remove_export,
  group_send_export,
  import_contact_export,
  initialize,
  authorize_device_link_for_set_export,
  complete_device_link_export,
  create_device_revocation_export,
  inspect_device_set_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  mailbox_fetch_export,
  outbox_ack_export,
  outbox_list_export,
  persist_envelope,
  process_delivery_batch_export,
  privacy_submission_export,
  push_action_complete_export,
  push_intent_export,
  push_status_export,
  replenish_prekeys_export,
  reconcile_prekeys_export,
  receive_initial_export,
  receive_message_export,
  prepare_fanout_prekeys_export,
  send_fanout_export,
  safety_number_export,
  transparency_lookup_export,
  register_request_export,
  resolve_request_export,
  update_conversation_export,
  validate_outer,
  verify_transparency_export,
} from './generated/libmessenger_mobile';

type PushNativeModule = {
  primePushToken(): Promise<void>;
  clearPushToken(): Promise<void>;
  addListener(
    event: 'onPushRegistrationChanged',
    listener: () => void,
  ): EventSubscription;
};

const pushNative = requireNativeModule<PushNativeModule>('MeshMessenger');

export const primePushToken = (): Promise<void> => pushNative.primePushToken();
export const clearPushToken = (): Promise<void> => pushNative.clearPushToken();

export function onPushRegistrationChanged(listener: () => void): () => void {
  const subscription = pushNative.addListener('onPushRegistrationChanged', listener);
  return () => subscription.remove();
}
