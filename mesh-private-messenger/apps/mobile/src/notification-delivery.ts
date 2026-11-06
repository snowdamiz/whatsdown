import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import * as Notifications from 'expo-notifications';
import type { MessageNotification } from './notification-policy';
export function createNotificationServices(deps: Pick<ScopedClient, 'runPrivate'> & { publishMessageNotice(notice: MessageNotification & { version: 1 }): Promise<void> }) {
  async function showMessageNotification(notification: MessageNotification): Promise<void> {
    // Native owns the final epoch/policy check and the actual OS publication.
    // Even while unlocked, an enabled policy must publish generic content only.
    await deps.publishMessageNotice({ version: 1, ...notification });
  }
  return Object.freeze({ showMessageNotification: (...args: Parameters<typeof showMessageNotification>) => deps.runPrivate(() => showMessageNotification(...args)) });
}
async function showDesktopMessageNotification(notification: MessageNotification): Promise<void> {
  if (!(await Notifications.getPermissionsAsync()).granted) return;
  await Notifications.scheduleNotificationAsync({
    identifier: notification.id,
    content: { title: notification.title, body: notification.body, sound: 'default',
      data: { kind: 'message', scope: notification.scope, mention: notification.mention } },
    trigger: { channelId: 'messages' },
  });
}
export const showMessageNotification: ReturnType<typeof createNotificationServices>['showMessageNotification'] = (...args) => {
  if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
  return showDesktopMessageNotification(...args);
};
