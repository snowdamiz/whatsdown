import { createBackupCapability } from './backup-capability';
import { databasePath } from './storage';
import type { AppLockNativePort, AppLockSession } from './app-lock';
import { assembleAppServices } from './app-services';
import { createAttachmentRangeServices } from './attachment-range-io';
import { createAvatarServices } from './avatar-picker';
import { createCreditPaymentServices } from './credit-payment-link';
import { createNotificationServices } from './notification-delivery';
import { createPushServices } from './push';
import { createAttachmentFileServices } from './attachment-io';
export type { AppServices } from './app-services';

export function createAppServices(scope: AppLockSession, control: Pick<AppLockNativePort, 'lockApp' | 'setAppLockEnabled'>, enabled: boolean) {
  return assembleAppServices({ scope, databasePath, backups: createBackupCapability(scope),
    createPlatform(bindings) {
      const ranges = createAttachmentRangeServices(scope);
      return {
        ranges, files: createAttachmentFileServices({ ...scope, ...ranges }),
        avatar: createAvatarServices(scope), payments: createCreditPaymentServices(scope),
        notifications: createNotificationServices(scope),
        push: createPushServices({ ...scope, ...bindings, appLockEnabled: enabled }),
        legacyPreferences: scope,
      };
    },
    controls: { supportsAppLock: true, appLockEnabled: enabled,
      lockApp: () => control.lockApp(),
      setAppLockEnabled: async value => { await control.setAppLockEnabled(value, scope.epoch); },
    },
  });
}
