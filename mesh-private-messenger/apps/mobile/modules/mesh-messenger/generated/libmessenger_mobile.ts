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
