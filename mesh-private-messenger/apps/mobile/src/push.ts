import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import * as Notifications from 'expo-notifications';
export type { PushStatus } from './push-action-executor';
import { Platform } from 'react-native';
import {
  clearPushToken,
  onPushRegistrationChanged,
  primePushToken,
  push_flow_complete_export,
  push_flow_begin_export,
  push_status_export,
  push_flow_send_export,
} from '../modules/mesh-messenger';
import { decodeUtf8, utf8, vectors } from './codec';
import { t } from './i18n';
import {
  executePushActions,
  type PushActionOperations,
  type PushStatus,
} from './push-action-executor';
import { BACKGROUND_NOTIFICATION_TASK, GENERIC_PUSH_BODY, isGenericWakeupContent, notificationScope } from './push-policy';
import { createKeyedSerialQueue } from './single-flight';
async function configureNotificationChannels(): Promise<void> {
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync('encrypted-wakeups', {
      name: t('Encrypted activity'),
      importance: Notifications.AndroidImportance.DEFAULT,
    });
    await Notifications.setNotificationChannelAsync('messages', {
      name: t('Messages and mentions'), importance: Notifications.AndroidImportance.HIGH,
      sound: 'default', lockscreenVisibility: Notifications.AndroidNotificationVisibility.PRIVATE,
    });
  }
}
async function requestNotificationPermission(): Promise<void> {
  await configureNotificationChannels();
  const permission = await Notifications.requestPermissionsAsync();
  if (!permission.granted) throw new Error(t('Notification permission was not granted'));
  await Notifications.registerTaskAsync(BACKGROUND_NOTIFICATION_TASK);
}
export function isGenericWakeup(notification: Notifications.Notification): boolean {
  const { body } = notification.request.content;
  return isGenericWakeupContent(body, notification.request.content.data);
}
Notifications.setNotificationHandler({
  handleNotification: async (notification) => {
    const message = notificationScope(notification.request.content.data) !== null;
    const show = message || (isGenericWakeup(notification) && notification.request.content.body === GENERIC_PUSH_BODY);
    return {
      shouldPlaySound: message,
      shouldSetBadge: false,
      shouldShowBanner: show,
      shouldShowList: show,
    };
  },
});


export function createPushServices(deps: Pick<ScopedClient, 'assertCurrent' | 'runPrivate' | 'clearPushToken' | 'onDispose' | 'onInboxOpen' | 'onNotificationOpen' | 'onPushRegistrationChanged' | 'primePushToken' | 'push_flow_begin_export' | 'push_flow_complete_export' | 'push_flow_send_export' | 'push_status_export'> & { appLockEnabled: boolean }) {
const { clearPushToken, onPushRegistrationChanged, primePushToken, push_flow_complete_export, push_flow_begin_export, push_status_export, push_flow_send_export } = deps;
const coordinateByDatabase = createKeyedSerialQueue<string>();
async function getPushStatus(databasePath: string, _expectedProfile?: Uint8Array): Promise<PushStatus> {
  const status = decodeUtf8(await push_status_export(utf8(databasePath)));
  if (
    status !== 'disabled' &&
    status !== 'enabled' &&
    status !== 'pending-bind' &&
    status !== 'pending-unbind'
  ) {
    throw new Error('Mesh returned an invalid push status');
  }
  return status;
}
function pushOperations(
  databasePath: string,
  intent: 0 | 1 | 2,
  expectedProfile: Uint8Array,
): PushActionOperations {
  return {
    poll: () => push_flow_begin_export(vectors(utf8(databasePath), expectedProfile, Uint8Array.of(intent))),
    complete: (action, outcome) =>
      push_flow_complete_export(
        vectors(utf8(databasePath), action, Uint8Array.of(outcome)),
      ),
    requestPermission: requestNotificationPermission,
    prime: (action) => primePushToken(vectors(utf8(databasePath), action)),
    clear: (action) => clearPushToken(vectors(utf8(databasePath), action)),
    send: (action) => push_flow_send_export(vectors(utf8(databasePath), action)),
  };
}
function runPushIntent(databasePath: string, intent: 0 | 1 | 2, expectedProfile: Uint8Array): Promise<PushStatus> {
  // Capture the rendered account before queuing. A replacement at the same
  // path cannot inherit this user's earlier enable/disable decision.
  const profile = expectedProfile.slice();
  return coordinateByDatabase(databasePath, () => executePushActions(pushOperations(databasePath, intent, profile)));
}
async function recoverPushBinding(databasePath: string, expectedProfile: Uint8Array): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 0, expectedProfile);
  if (status === 'enabled') {
    await configureNotificationChannels();
    await Notifications.registerTaskAsync(BACKGROUND_NOTIFICATION_TASK);
  }
  return status;
}
async function enablePushBinding(databasePath: string, expectedProfile: Uint8Array): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 1, expectedProfile);
  if (status !== 'enabled') throw new Error('Mesh push binding did not converge to enabled');
  return status;
}
async function disablePushBinding(databasePath: string, expectedProfile: Uint8Array): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 2, expectedProfile);
  if (status !== 'disabled') throw new Error('Mesh push binding did not converge to disabled');
  await Notifications.unregisterTaskAsync(BACKGROUND_NOTIFICATION_TASK);
  return status;
}
const listenForPushRegistrationChanges = onPushRegistrationChanged;
function listenForGenericWakeups(onWake: () => void): () => void {
  let active = true;
  const deliver = () => {
    if (!active) return;
    void deps.runPrivate(async () => { if (active) onWake(); }).catch(() => {});
  };
  const received = Notifications.addNotificationReceivedListener((notification) => {
    const trigger = notification.request.trigger;
    if (trigger && 'type' in trigger && trigger.type === 'push' && isGenericWakeup(notification)) deliver();
  });
  const response = Notifications.addNotificationResponseReceivedListener((event) => {
    if (isGenericWakeup(event.notification)) deliver();
  });
  const close = () => { if (!active) return; active = false; received.remove(); response.remove(); removeDispose(); };
  const removeDispose = deps.onDispose(close);
  return close;
}
function listenForNotificationOpens(open: (scope: string) => void, openInbox: () => void = () => {}): () => void {
  if (Platform.OS === 'ios' || Platform.OS === 'android') {
    // Mobile taps are consumed by the epoch-bound native broker.
    // A missing native broker refuses; a cached Expo response is no fallback.
    return deps.onNotificationOpen(intent => {
      if (intent.kind === 'scope') open(intent.scope);
      else openInbox();
    });
  }
  // Restrictive native responses carry no private scope and never enter Expo's
  // retained response slot. A cold tap remains pending behind the native cover.
  const closeInbox = deps.onInboxOpen(openInbox);
  if (deps.appLockEnabled) return closeInbox;
  let active = true;
  const handle = (response: Notifications.NotificationResponse | null) => {
    if (!active || !response) return;
    void deps.runPrivate(async () => {
      if (!active) return;
      const scope = notificationScope(response.notification.request.content.data);
      if (scope) {
        open(scope);
        if (active) await Notifications.clearLastNotificationResponseAsync();
      }
    }).catch(() => {});
  };
  handle(Notifications.getLastNotificationResponse());
  const subscription = Notifications.addNotificationResponseReceivedListener(handle);
  const close = () => { if (!active) return; active = false; subscription.remove(); closeInbox(); removeDispose(); };
  const removeDispose = deps.onDispose(close);
  return close;
}
return Object.freeze({
  getPushStatus: (...args: Parameters<typeof getPushStatus>) => deps.runPrivate(() => getPushStatus(...args)),
  recoverPushBinding: (databasePath: string, expectedProfile: Uint8Array) => {
    const profile = expectedProfile.slice();
    return deps.runPrivate(() => recoverPushBinding(databasePath, profile));
  },
  enablePushBinding: (databasePath: string, expectedProfile: Uint8Array) => {
    const profile = expectedProfile.slice();
    return deps.runPrivate(() => enablePushBinding(databasePath, profile));
  },
  disablePushBinding: (databasePath: string, expectedProfile: Uint8Array) => {
    const profile = expectedProfile.slice();
    return deps.runPrivate(() => disablePushBinding(databasePath, profile));
  },
  listenForPushRegistrationChanges: (...args: Parameters<typeof listenForPushRegistrationChanges>) => {
    deps.assertCurrent(); return listenForPushRegistrationChanges(...args);
  },
  listenForGenericWakeups: (...args: Parameters<typeof listenForGenericWakeups>) => {
    deps.assertCurrent(); return listenForGenericWakeups(...args);
  },
  listenForNotificationOpens: (...args: Parameters<typeof listenForNotificationOpens>) => {
    deps.assertCurrent(); return listenForNotificationOpens(...args);
  },
});
}
function desktopNotificationIntent(listener: Parameters<ScopedClient['onNotificationOpen']>[0]): () => void {
  let active = true;
  const deliver = (response: Notifications.NotificationResponse | null) => {
    if (!active || !response) return;
    const scope = notificationScope(response.notification.request.content.data);
    if (scope) listener({ kind: 'scope', scope });
    else if (isGenericWakeup(response.notification)) listener({ kind: 'inbox' });
  };
  const subscription = Notifications.addNotificationResponseReceivedListener(deliver);
  deliver(Notifications.getLastNotificationResponse());
  return () => { if (active) { active = false; subscription.remove(); } };
}
let legacyScopeServices: ReturnType<typeof createPushServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createPushServices({ assertCurrent: () => {}, runPrivate: operation => operation(), onDispose: () => () => {}, appLockEnabled: false, onInboxOpen: () => () => {}, onNotificationOpen: desktopNotificationIntent, clearPushToken, onPushRegistrationChanged, primePushToken, push_flow_complete_export, push_flow_begin_export, push_status_export, push_flow_send_export });
}
export const getPushStatus: ReturnType<typeof createPushServices>['getPushStatus'] = (...args) => desktopCompatibility().getPushStatus(...args);
export const recoverPushBinding: ReturnType<typeof createPushServices>['recoverPushBinding'] = (...args) => desktopCompatibility().recoverPushBinding(...args);
export const enablePushBinding: ReturnType<typeof createPushServices>['enablePushBinding'] = (...args) => desktopCompatibility().enablePushBinding(...args);
export const disablePushBinding: ReturnType<typeof createPushServices>['disablePushBinding'] = (...args) => desktopCompatibility().disablePushBinding(...args);
export const listenForPushRegistrationChanges: ReturnType<typeof createPushServices>['listenForPushRegistrationChanges'] = (...args) => desktopCompatibility().listenForPushRegistrationChanges(...args);

export const listenForGenericWakeups: ReturnType<typeof createPushServices>['listenForGenericWakeups'] = (...args) => desktopCompatibility().listenForGenericWakeups(...args);

export const listenForNotificationOpens: ReturnType<typeof createPushServices>['listenForNotificationOpens'] = (...args) => desktopCompatibility().listenForNotificationOpens(...args);
