import * as Notifications from 'expo-notifications';
import type { MessageNotification } from './notification-policy';

export async function showMessageNotification(notification: MessageNotification): Promise<void> {
  if (!(await Notifications.getPermissionsAsync()).granted) return;
  await Notifications.scheduleNotificationAsync({
    identifier: notification.id,
    content: { title: notification.title, body: notification.body, sound: 'default',
      data: { kind: 'message', scope: notification.scope, mention: notification.mention } },
    trigger: { channelId: 'messages' },
  });
}
