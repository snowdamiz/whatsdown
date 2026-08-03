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
export const start_conversation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_start_conversation', request);
export const receive_initial_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_initial', request);
export const send_message_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_send_message', request);
export const receive_message_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_receive_message', request);
export const update_conversation_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_update_conversation', request);
export const list_conversations_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_list_conversations', request);
export const load_history_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_load_history', request);
export const safety_number_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_safety_number', request);
