import type { BackupCapability } from './backup-capability';
// Existing desktop authority only. No desktop app-lock success or mobile fallback.
import { Clipboard } from 'react-native';
import type { AppServices } from './app-lock-services';
import * as native from '../modules/mesh-messenger';
import * as service0 from './attachment-range-io';
import * as service1 from './avatar-picker';
import * as service2 from './bounty';
import * as service3 from './credit-payment-link';
import * as service4 from './credits';
import * as service5 from './network';
import * as service6 from './notification-delivery';
import * as service7 from './paid-attachments';
import * as service8 from './presentation-store';
import * as service9 from './push';
import * as service10 from './sealed-journals';
import * as service11 from './sealed-preferences';
import * as service12 from './wallet';
import * as service13 from './attachment-compose';
import * as service14 from './attachment-io';
import * as service15 from './postage';
import * as service16 from './read-state-store';
import * as service17 from './message-notifications';
export function createDesktopAppServices(): AppServices {
  const backups: BackupCapability = Object.freeze({ kind: 'unavailable' });
  return Object.freeze({ ...native, ...service0, ...service1, ...service2, ...service3, ...service4, ...service5, ...service6, ...service7, ...service8, ...service9, ...service10, ...service11, ...service12, ...service13, ...service14, ...service15, ...service16, ...service17, backups, supportsAppLock: false, appLockEnabled: false,
    copyProtectedText: async (text: string) => { Clipboard.setString(text); } }) as unknown as AppServices;
}
