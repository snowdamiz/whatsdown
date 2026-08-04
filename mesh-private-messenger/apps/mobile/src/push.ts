import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';

import {
  clearPushToken,
  onPushRegistrationChanged,
  primePushToken,
  push_action_complete_export,
  push_intent_export,
  push_status_export,
} from '../modules/mesh-messenger';
import { decodeUtf8, utf8, vectors } from './codec';
import {
  executePushActions,
  type PushActionOperations,
  type PushStatus,
} from './push-action-executor';
import { submitPushBind, submitPushUnbind } from './network';

import { isGenericWakeupContent } from './push-policy';
import { createKeyedSerialQueue } from './single-flight';

export type { PushStatus } from './push-action-executor';

const coordinateByDatabase = createKeyedSerialQueue<string>();

async function requestNotificationPermission(): Promise<void> {
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync('encrypted-wakeups', {
      name: 'Encrypted activity',
      importance: Notifications.AndroidImportance.DEFAULT,
    });
  }
  const permission = await Notifications.requestPermissionsAsync();
  if (!permission.granted) throw new Error('Notification permission was not granted');
}

export async function getPushStatus(databasePath: string): Promise<PushStatus> {
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
): PushActionOperations {
  return {
    poll: () => push_intent_export(vectors(utf8(databasePath), Uint8Array.of(intent))),
    complete: (action, outcome) =>
      push_action_complete_export(
        vectors(utf8(databasePath), action, Uint8Array.of(outcome)),
      ),
    requestPermission: requestNotificationPermission,
    prime: primePushToken,
    clear: clearPushToken,
    sendBind: submitPushBind,
    sendUnbind: submitPushUnbind,
  };
}

function runPushIntent(databasePath: string, intent: 0 | 1 | 2): Promise<PushStatus> {
  return coordinateByDatabase(databasePath, () => executePushActions(pushOperations(databasePath, intent)));
}

export const recoverPushBinding = (databasePath: string): Promise<PushStatus> =>
  runPushIntent(databasePath, 0);

export async function enablePushBinding(databasePath: string): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 1);
  if (status !== 'enabled') throw new Error('Mesh push binding did not converge to enabled');
  return status;
}

export async function disablePushBinding(databasePath: string): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 2);
  if (status !== 'disabled') throw new Error('Mesh push binding did not converge to disabled');
  return status;
}

export const listenForPushRegistrationChanges = onPushRegistrationChanged;

export function isGenericWakeup(notification: Notifications.Notification): boolean {
  const { body } = notification.request.content;
  return isGenericWakeupContent(body, notification.request.content.data);
}

Notifications.setNotificationHandler({
  handleNotification: async (notification) => {
    const show = isGenericWakeup(notification);
    return {
      shouldPlaySound: false,
      shouldSetBadge: false,
      shouldShowBanner: show,
      shouldShowList: show,
    };
  },
});

export function listenForGenericWakeups(onWake: () => void): () => void {
  const received = Notifications.addNotificationReceivedListener((notification) => {
    if (isGenericWakeup(notification)) onWake();
  });
  const response = Notifications.addNotificationResponseReceivedListener((event) => {
    if (isGenericWakeup(event.notification)) onWake();
  });
  return () => {
    received.remove();
    response.remove();
  };
}
