import * as Notifications from 'expo-notifications';
import { isErasureMessageNotification } from './account-lifecycle';

export async function presentedAccountNotifications(): Promise<{ id: string; message: boolean }[]> {
  const presented = await Notifications.getPresentedNotificationsAsync();
  return presented.map(({ request }) => ({
    id: request.identifier,
    message: isErasureMessageNotification(request.identifier, request.content.data),
  }));
}

export async function dismissAccountNotification(id: string): Promise<void> {
  await Notifications.dismissNotificationAsync(id);
}
