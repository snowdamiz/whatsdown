import { requireNativeModule } from 'expo-modules-core';

type MeshNativeModule = {
  invoke(symbol: string, request: Uint8Array): Promise<Uint8Array>;
};

const native = requireNativeModule<MeshNativeModule>('MeshMessenger');

export const initialize = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_initialize', request);
export const validate_outer = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_validate_outer', request);
export const persist_envelope = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_store_envelope', request);
export const create_account_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_account', request);
export const load_profile_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_load_profile', request);
export const create_link_request_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_link_request', request);
export const device_link_sas_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_device_link_sas', request);
export const authorize_device_link_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_authorize_device_link', request);
export const authorize_device_link_for_set_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_authorize_device_link_for_set', request);
export const complete_device_link_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_complete_device_link', request);
export const inspect_device_set_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_inspect_device_set', request);
export const create_device_revocation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_create_device_revocation', request);
export const start_conversation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_start_conversation', request);
export const receive_initial_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_initial', request);
export const send_fanout_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_send_fanout', request);
export const send_message_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_send_message', request);
export const receive_message_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_message', request);
export const update_conversation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_update_conversation', request);
export const list_conversations_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_list_conversations', request);
export const load_history_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_load_history', request);
export const safety_number_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_safety_number', request);
export const import_contact_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_import_contact', request);
export const directory_entry_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_entry', request);
export const directory_lookup_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_directory_lookup', request);
export const transparency_lookup_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_transparency_lookup', request);
export const verify_transparency_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_verify_transparency', request);
export const privacy_submission_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_privacy_submission', request);
export const mailbox_fetch_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_mailbox_fetch', request);
export const process_delivery_batch_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_process_delivery_batch', request);
