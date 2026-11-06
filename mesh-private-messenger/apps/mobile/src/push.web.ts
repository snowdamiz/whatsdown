import { isTauri } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission } from '@tauri-apps/plugin-notification';
import { load_profile_export } from '../modules/mesh-messenger';
import { accountProfileIdentity } from './account-lifecycle';
import { utf8 } from './codec';
import { t } from './i18n';
import type { PushStatus } from './push-action-executor';
export type { PushStatus } from './push-action-executor';
const key = (path: string, identity: string) => `${path}/notifications-enabled/${identity}`;

export async function getPushStatus(path: string, expectedProfile?: Uint8Array): Promise<PushStatus> {
  if (!isTauri()) return 'disabled';
  const expected = expectedProfile && accountProfileIdentity(expectedProfile);
  const current = accountProfileIdentity(await load_profile_export(utf8(path)));
  if (expected && current !== expected) return 'disabled';
  return localStorage.getItem(key(path, current)) === 'true' && await isPermissionGranted() ? 'enabled' : 'disabled';
}
export const recoverPushBinding = getPushStatus;
export async function disablePushBinding(path: string, expectedProfile: Uint8Array): Promise<PushStatus> {
  localStorage.removeItem(key(path, accountProfileIdentity(expectedProfile)));
  return 'disabled';
}
export async function enablePushBinding(path: string, expectedProfile: Uint8Array): Promise<PushStatus> {
  if (!isTauri()) throw new Error(t('System notifications are available in the installed Morse app.'));
  const expected = accountProfileIdentity(expectedProfile);
  if (!await isPermissionGranted() && await requestPermission() !== 'granted') {
    throw new Error(t('Allow notifications for Morse in System Settings.'));
  }
  const current = accountProfileIdentity(await load_profile_export(utf8(path)));
  if (current !== expected) throw new Error('account_state_changed');
  localStorage.setItem(key(path, expected), 'true');
  return 'enabled';
}
export const listenForGenericWakeups = (_listener: () => void) => () => {};
export const listenForPushRegistrationChanges = listenForGenericWakeups;
// The desktop notification plugin has no notification-action API.
export const listenForNotificationOpens = (_listener: (scope: string) => void) => () => {};
