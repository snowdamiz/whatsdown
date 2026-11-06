import { invoke } from '@tauri-apps/api/core';
import type { DesktopOwner, DesktopEpoch } from './desktop-lock-protocol.ts';
import type { DesktopPrivateSession } from './desktop-private-session.ts';
import type { MessageNotification } from './notification-policy.ts';

type WindowAction = 'minimize' | 'toggleMaximize' | 'close' | 'startDragging';
type NotificationOperation = 'status' | 'enable' | 'disable';
export type DesktopNotificationIntent = { kind: 'none' } | { kind: 'inbox' } | { kind: 'scope'; scope: string };
const legacyKinds = ['read-state', 'notification-state', 'receipt-marks', 'read-receipts', 'notification-preview'];
const invalid = () => Error('invalid_desktop_private_reply');
function unit(value: unknown): void { if (value !== null) throw invalid(); }
function notificationIntent(value: unknown): DesktopNotificationIntent {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !('version' in value) || value.version !== 1 || !('kind' in value)) throw invalid();
  const keys = Object.keys(value);
  if ((value.kind === 'none' || value.kind === 'inbox') && keys.length === 2) return { kind: value.kind };
  if (value.kind === 'scope' && keys.length === 3 && 'scope' in value && typeof value.scope === 'string' &&
      /^(?:chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/.test(value.scope)) return { kind: 'scope', scope: value.scope };
  throw invalid();
}

export function createDesktopPlatformPort({ owner, epoch, scope }: {
  owner: DesktopOwner; epoch: DesktopEpoch;
  scope: Pick<DesktopPrivateSession, 'runPrivate' | 'assertCurrent'>;
}) {
  const headers = Object.freeze({ 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': epoch });
  const privateCall = <T>(operation: () => Promise<T>): Promise<T> => scope.runPrivate(operation);
  async function ownedBytes<T>(bytes: Uint8Array, operation: (owned: Uint8Array) => Promise<T>): Promise<T> {
    scope.assertCurrent();
    const held = bytes.slice();
    try {
      const result = await privateCall(() => operation(held));
      scope.assertCurrent();
      return result;
    } catch (error) { scope.assertCurrent(); throw error; }
    finally { held.fill(0); }
  }
  return Object.freeze({
    databasePath() {
      return privateCall(async () => {
        const path = await invoke<unknown>('database_path', {}, { headers });
        if (typeof path !== 'string' || !path || path.includes('\0') || new TextEncoder().encode(path).length > 16_384) throw invalid();
        return path;
      });
    },
    readLegacyPreference(profile: Uint8Array, kind: string) {
      return ownedBytes(profile, async body => {
        if (!legacyKinds.includes(kind)) throw Error('invalid_legacy_kind');
        const value = await invoke<unknown>('app_lock_legacy_preference', body, { headers: { ...headers, 'X-Morse-Legacy-Operation': 'read', 'X-Morse-Legacy-Kind': kind } });
        if (value !== null && typeof value !== 'string') throw invalid();
        return value;
      });
    },
    removeLegacyPreference(profile: Uint8Array, kind: string) {
      return ownedBytes(profile, async body => {
        if (!legacyKinds.includes(kind)) throw Error('invalid_legacy_kind');
        unit(await invoke<unknown>('app_lock_legacy_preference', body, { headers: { ...headers, 'X-Morse-Legacy-Operation': 'remove', 'X-Morse-Legacy-Kind': kind } }));
      });
    },
    forgetLegacyPreferences(account: string) {
      return privateCall(async () => {
        if (!/^[a-f0-9]{64}$/.test(account)) throw Error('invalid_account');
        // Native captures and removes these exact keys before its erasure
        // worker releases Core. A retired React continuation owns no cleanup.

      });
    },
    openNativeCreditPayment(request: Uint8Array) {
      return ownedBytes(request, async body => { unit(await invoke<unknown>('credit_open_payment', body, { headers })); });
    },
    publishMessageNotice(notice: MessageNotification & { version: 1 }) {
      const captured = { ...notice };
      return privateCall(async () => { unit(await invoke<unknown>('app_lock_publish_notice', captured, { headers })); });
    },
    takeNotificationIntent() {
      return privateCall(async () => notificationIntent(await invoke<unknown>('app_lock_take_notice_intent', { version: 1 }, { headers })));
    },
    notificationBinding(operation: NotificationOperation, profile: Uint8Array) {
      return ownedBytes(profile, async body => {
        const value = await invoke<unknown>('app_lock_notification_binding', body, { headers: { ...headers, 'X-Morse-Notification-Operation': operation } });
        if (value !== 'enabled' && value !== 'disabled') throw invalid();
        return value;
      });
    },
    windowAction(action: WindowAction) {
      return privateCall(async () => { unit(await invoke<unknown>('app_lock_window_action', { action }, { headers })); });
    },
  });
}
