import type { AppLockSession } from './app-lock';
import type { BackupCapability } from './backup-capability';
import { createScopedBindings, type ScopedBindings } from '../modules/mesh-messenger/scoped';
import type { createAttachmentRangeServices } from './attachment-range-io';
import type { createAttachmentFileServices } from './attachment-io';
import type { createAvatarServices } from './avatar-picker';
import type { createCreditPaymentServices } from './credit-payment-link';
import type { createNotificationServices } from './notification-delivery';
import type { createPushServices } from './push';
import { createBountyServices } from './bounty';
import { createCreditServices } from './credits';
import { createNetworkServices } from './network';
import { createPaidAttachmentServices } from './paid-attachments';
import { createPresentationServices } from './presentation-store';
import { createJournalServices } from './sealed-journals';
import { createPreferenceServices } from './sealed-preferences';
import { createWalletServices } from './wallet';
import { createAttachmentComposeServices } from './attachment-compose';
import { createPostageServices } from './postage';
import { createReadStateServices } from './read-state-store.ts';
import { createMessageNotificationServices } from './message-notifications';

export type AppServiceScope = Pick<AppLockSession, 'invoke' | 'invokeWallet' | 'runPrivate' | 'assertCurrent' | 'onDispose' | 'copyProtectedText'>;
export type AppPlatformServices = Readonly<{
  ranges: ReturnType<typeof createAttachmentRangeServices>;
  files: ReturnType<typeof createAttachmentFileServices>;
  avatar: ReturnType<typeof createAvatarServices>;
  payments: ReturnType<typeof createCreditPaymentServices>;
  notifications: ReturnType<typeof createNotificationServices>;
  push: ReturnType<typeof createPushServices>;
  legacyPreferences: Pick<Parameters<typeof createReadStateServices>[0], 'readLegacyPreference' | 'removeLegacyPreference' | 'forgetLegacyPreferences'>;
}>;
export type AppLockControls = Readonly<{
  supportsAppLock: true;
  appLockEnabled: boolean;
  lockApp(): Promise<void>;
  setAppLockEnabled(enabled: boolean): Promise<void>;
}> | Readonly<{ supportsAppLock: false; appLockEnabled: false }>;

export function assembleAppServices({ scope, databasePath, createPlatform, backups, controls }: {
  scope: AppServiceScope;
  databasePath: string;
  createPlatform: (bindings: ScopedBindings) => AppPlatformServices;
  backups: BackupCapability;
  controls: AppLockControls;
}) {
  scope.assertCurrent();
  const bindings = createScopedBindings(scope);
  const base = Object.freeze({ ...scope, databasePath, ...bindings });
  const platform = createPlatform(bindings);
  const bounty = createBountyServices(base);
  const credits = createCreditServices(base);
  const network = createNetworkServices(base);
  const paid = createPaidAttachmentServices(base);
  const presentation = createPresentationServices(base);
  const journals = createJournalServices(base);
  const preferences = createPreferenceServices(base);
  const wallet = createWalletServices(base);
  const compose = createAttachmentComposeServices({ ...base, ...network, ...paid });
  const postage = createPostageServices({ ...base, ...network });
  const readState = createReadStateServices({ ...base, ...journals, ...preferences,
    readLegacyPreference: platform.legacyPreferences.readLegacyPreference,
    removeLegacyPreference: platform.legacyPreferences.removeLegacyPreference,
    forgetLegacyPreferences: platform.legacyPreferences.forgetLegacyPreferences,
  });
  const messages = createMessageNotificationServices({ ...base, ...network, ...presentation,
    ...platform.push, ...platform.notifications, ...readState });
  scope.assertCurrent();
  return Object.freeze({ databasePath, ...bindings, ...bounty, ...credits, ...network, ...paid, ...presentation,
    ...journals, ...preferences, ...wallet, ...compose, ...postage, ...readState, ...messages,
    ...platform.ranges, ...platform.files, ...platform.avatar, ...platform.payments, ...platform.notifications,
    ...platform.push, backups, ...controls, copyProtectedText: scope.copyProtectedText });
}
export type AppServices = ReturnType<typeof assembleAppServices>;
