import { requireNativeModule } from 'expo-modules-core';

type MeshNativeModule = {
  invoke(symbol: string, request: Uint8Array): Promise<Uint8Array>;
};

const native = requireNativeModule<MeshNativeModule>('MeshMessenger');

export const public_echo = (request: Uint8Array): Promise<Uint8Array> => native.invoke('audience_public', request);
