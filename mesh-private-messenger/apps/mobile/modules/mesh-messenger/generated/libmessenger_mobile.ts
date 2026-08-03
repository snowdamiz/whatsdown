import { requireNativeModule } from 'expo-modules-core';

type MeshNativeModule = {
  invoke(symbol: string, request: Uint8Array): Promise<Uint8Array>;
};

const native = requireNativeModule<MeshNativeModule>('MeshMessenger');

export const initialize = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_initialize', request);
export const validate_outer = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_validate_outer', request);
export const persist_envelope = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_store_envelope', request);
