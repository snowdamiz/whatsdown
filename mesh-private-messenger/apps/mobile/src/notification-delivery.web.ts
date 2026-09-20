import { invoke, isTauri } from '@tauri-apps/api/core';
import type { MessageNotification } from './notification-policy';

export async function showMessageNotification(notification: MessageNotification): Promise<void> {
  if (!isTauri()) return;
  await invoke('plugin:notification|notify', { options: { title: notification.title, body: notification.body } });
}
