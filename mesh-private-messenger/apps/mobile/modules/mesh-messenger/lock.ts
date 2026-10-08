import { requireNativeModule } from 'expo-modules-core';

// App lock's native side (ios/MorseLockModule.swift, android/.../MorseLockModule.kt):
// the device owner's Face ID, Touch ID, fingerprint or passcode.
export type LockNative = {
  // Whether the device has a passcode or screen lock to ask for.
  lockAvailable(): Promise<boolean>;
  // Whether the owner unlocked; true on a device that no longer has a lock.
  lockAuthenticate(reason: string): Promise<boolean>;
};

export const lockNative = requireNativeModule<LockNative>('MorseLock');
