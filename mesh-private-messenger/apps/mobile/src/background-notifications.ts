import * as Notifications from 'expo-notifications';
import * as TaskManager from 'expo-task-manager';
import { BACKGROUND_NOTIFICATION_TASK, backgroundWakeup } from './push-policy';
import { bindDisabledAppLockScope, getAppLockNativePort } from '../modules/mesh-messenger';
import { createAppLockSession, parseAppLockState } from './app-lock';
import { createAppServices } from './app-lock-services';
import { databasePath } from './storage';
import { utf8 } from './codec';
import { parseFilingObservation } from './filing';
import { resolveLanguage, resolveLocale, setCurrentLanguage } from './i18n';
import { deviceLocales, loadLanguageChoice } from './language-store';

TaskManager.defineTask<Notifications.NotificationTaskPayload>(BACKGROUND_NOTIFICATION_TASK, async ({ data, error }) => {
  // A wake with the app closed has no screen to set the language: alerts
  // take the saved choice, or the phone's, as the app would.
  const locales = deviceLocales();
  const language = resolveLanguage(loadLanguageChoice(), locales);
  setCurrentLanguage(language, resolveLocale(language, locales));
  if (error || !data || 'actionIdentifier' in data || !backgroundWakeup(data.data)) return;
  const native = getAppLockNativePort();
  const generic = async () => {
    // This no-argument native operation has fixed nonprivate content only.
    // It cannot initialize Mesh, decrypt, navigate privately, or grant authority.
    await native.publishEncryptedWakeup().catch(() => {});
    return Notifications.BackgroundNotificationTaskResult.Failed;
  };
  let scope: ReturnType<typeof createAppLockSession> | undefined;
  let binding: Awaited<ReturnType<typeof bindDisabledAppLockScope>> | undefined;
  try {
    const state = parseAppLockState(await native.getAppLockState());
    if (state.policy !== 'disabled' || state.phase !== 'disabled') return await generic();
    // The snapshot only selects the path. Native admission remains authoritative
    // at every actual operation, even if enable/revoke races this headless task.
    binding = await bindDisabledAppLockScope(state.epoch);
    scope = createAppLockSession(binding.port, state.epoch);
    const services = createAppServices(scope, binding.port, false);
    services.setActiveNotificationScope(null);
    if (await services.getPushStatus(databasePath) !== 'enabled') return;
    try {
      // Still running when this returns means suspended before the receipt leaves.
      await (await services.synchronizeWithNotifications(databasePath)).receipts;
      return Notifications.BackgroundNotificationTaskResult.NewData;
    } catch {
      // A wakeup contains no plaintext. Keep a generic alert if local decryption/network access fails.
      return await generic();
    } finally {
      // A headless wake may have discovered a fork even when mailbox sync failed.
      // Native returns immediately and its actor owns networking. Give it a
      // bounded background window; OS suspension is recovered by the Mesh journal.
      try {
        for (let poll = 0; poll <= 12; poll++) {
          const state = parseFilingObservation(await services.fork_filing_export(utf8(databasePath)));
          if (!state.working || poll === 12) break;
          await new Promise(resolve => setTimeout(resolve, 2_000));
        }
      } catch { /* Evidence and its retry budget remain in encrypted storage. */ }
    }
  } catch { return await generic(); }
  finally { scope?.dispose(); binding?.release(); }
});
