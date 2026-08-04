import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';

import {
  clearPushToken,
  onPushRegistrationChanged,
  primePushToken,
  push_bind_prepare_export,
  push_status_export,
  push_unbind_prepare_export,
  push_update_commit_export,
} from '../modules/mesh-messenger';
import { decodeUtf8, utf8, vectors } from './codec';
import {
  coordinatePush,
  type PushFlowOperations,
  type PushIntent,
  type PushStatus,
} from './push-coordinator';
import { submitPushBind, submitPushUnbind } from './network';

import { isGenericWakeupContent } from './push-policy';
import { createKeyedSingleFlight } from './single-flight';

const expoProjectIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const coordinateByDatabase = createKeyedSingleFlight<string, PushStatus>();

function expoProjectId(): string {
  const projectId = process.env.EXPO_PUBLIC_MESSENGER_EXPO_PROJECT_ID;
  if (!projectId || !expoProjectIdPattern.test(projectId)) {
    throw new Error('EXPO_PUBLIC_MESSENGER_EXPO_PROJECT_ID must be a lowercase UUID');
  }
  return projectId;
}

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

function pushOperations(databasePath: string, projectId?: string): PushFlowOperations {
  return {
    requestPermission: requestNotificationPermission,
    prime: primePushToken,
    clear: clearPushToken,
    prepareBind: () =>
      push_bind_prepare_export(vectors(utf8(databasePath), utf8(projectId ?? ''))),
    prepareUnbind: () => push_unbind_prepare_export(utf8(databasePath)),
    sendBind: submitPushBind,
    sendUnbind: submitPushUnbind,
    commit: async (wire) => {
      await push_update_commit_export(vectors(utf8(databasePath), wire));
    },
  };
}

function runPushIntent(databasePath: string, intent: PushIntent): Promise<PushStatus> {
  return coordinateByDatabase(databasePath, async () => {
    const status = await getPushStatus(databasePath);
    const needsProjectId =
      intent === 'enable' || (intent === 'recover' && status === 'enabled');
    await coordinatePush(
      status,
      intent,
      pushOperations(databasePath, needsProjectId ? expoProjectId() : undefined),
    );
    return getPushStatus(databasePath);
  });
}

export const recoverPushBinding = (databasePath: string): Promise<PushStatus> =>
  runPushIntent(databasePath, 'recover');

export async function enablePushBinding(databasePath: string): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 'enable');
  if (status !== 'enabled') throw new Error('Mesh push binding did not converge to enabled');
  return status;
}

export async function disablePushBinding(databasePath: string): Promise<PushStatus> {
  const status = await runPushIntent(databasePath, 'disable');
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
