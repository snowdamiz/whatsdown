import { isTauri } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission } from '@tauri-apps/plugin-notification';
import type { PushStatus } from './push-action-executor';
export type { PushStatus } from './push-action-executor';
const key = (path: string) => `${path}/notifications-enabled`;
export async function getPushStatus(path: string): Promise<PushStatus> {
  return isTauri() && localStorage.getItem(key(path)) === 'true' && await isPermissionGranted() ? 'enabled' : 'disabled';
}
export const recoverPushBinding = getPushStatus;
export async function disablePushBinding(path: string): Promise<PushStatus> {
  localStorage.removeItem(key(path));
  return 'disabled';
}
export async function enablePushBinding(path: string): Promise<PushStatus> {
  if (!isTauri()) throw new Error('System notifications are available in the installed Morse app.');
  if (!await isPermissionGranted() && await requestPermission() !== 'granted') {
    throw new Error('Allow notifications for Morse in System Settings.');
  }
  localStorage.setItem(key(path), 'true');
  return 'enabled';
}
export const listenForGenericWakeups = (_listener: () => void) => () => {};
export const listenForPushRegistrationChanges = listenForGenericWakeups;
// The desktop notification plugin has no notification-action API.
export const listenForNotificationOpens = (_listener: (scope: string) => void) => () => {};
