import * as Notifications from 'expo-notifications';

import { isGenericWakeupContent } from './push-policy';

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
