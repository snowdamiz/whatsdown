import { invoke } from '@tauri-apps/api/core';
import type { LockNative } from './lock';

// Desktop: the Mac's owner check (src-tauri/src/owner.rs). A desktop without one
// reports none, and Settings doesn't offer the lock there.
export const lockNative: LockNative = {
  lockAvailable: () => invoke<boolean>('lock_available').catch(() => false),
  lockAuthenticate: (reason) => invoke<boolean>('lock_authenticate', { reason }).catch(() => false),
};
