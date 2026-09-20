import * as Notifications from 'expo-notifications';
import * as TaskManager from 'expo-task-manager';
import { AppState } from 'react-native';
import { BACKGROUND_NOTIFICATION_TASK, backgroundWakeup, GENERIC_PUSH_BODY } from './push-policy';
import { synchronizeWithNotifications, setActiveNotificationScope } from './message-notifications';
import { getPushStatus } from './push';
import { databasePath } from './storage';

TaskManager.defineTask<Notifications.NotificationTaskPayload>(BACKGROUND_NOTIFICATION_TASK, async ({ data, error }) => {
  if (error || !data || 'actionIdentifier' in data || !backgroundWakeup(data.data)) return;
  if (AppState.currentState !== 'active') setActiveNotificationScope(null);
  try {
    if (await getPushStatus(databasePath) !== 'enabled') return;
  } catch { return Notifications.BackgroundNotificationTaskResult.Failed; }
  try {
    // Still running when this returns means suspended before the receipt leaves.
    await (await synchronizeWithNotifications(databasePath)).receipts;
    return Notifications.BackgroundNotificationTaskResult.NewData;
  } catch {
    // A wakeup contains no plaintext. Keep a generic alert if local decryption/network access fails.
    if (await getPushStatus(databasePath) !== 'enabled') return Notifications.BackgroundNotificationTaskResult.Failed;
    await Notifications.scheduleNotificationAsync({ identifier: 'encrypted-wakeup',
      content: { body: GENERIC_PUSH_BODY, data: { kind: 'encrypted-wakeup' } },
      trigger: { channelId: 'encrypted-wakeups' } });
    return Notifications.BackgroundNotificationTaskResult.Failed;
  }
});
