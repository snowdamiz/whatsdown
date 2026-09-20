import { hex, type GroupHistoryMessage, type HistoryMessage } from './codec.ts';
import { receivedMessageKeys, type ReadState } from './read-state.ts';
import { attachmentPreviewText } from './attachments.ts';
import { mentionSpans } from './mentions.ts';
import { receiptDue } from './receipts.ts';

export type MessageNotification = { id: string; scope: string; title: string; body: string; mention: boolean };
// How much of a message its notification shows, since a notification is read by
// whoever holds the phone, locked or not: who and what, who only, or neither.
export type NotificationPreview = 'full' | 'sender' | 'none';
export const parseNotificationPreview = (saved: unknown): NotificationPreview =>
  saved === 'sender' || saved === 'none' ? saved : 'full';
export function redactNotification(notification: MessageNotification, preview: NotificationPreview): MessageNotification {
  if (preview === 'full') return notification;
  // The body names the sender inside a group and says when it is a mention, so it goes whole.
  return { ...notification, body: 'New message', title: preview === 'none' ? 'Morse' : notification.title };
}
export type ReceiptPeer = { username: string; accountId: Uint8Array };
export type NotificationThread = {
  scope: string;
  title: string;
  // Only an accepted, unblocked direct chat is told what reached this device.
  peer?: ReceiptPeer;
  messages: (HistoryMessage | GroupHistoryMessage)[];
  senders?: Record<string, string>;
  blocked?: boolean;
};

export function planNotifications(
  threads: NotificationThread[], previous: ReadState,
  own: { accountId: string; username: string }, activeScope: string | null,
  // The open chat that sends read receipts: its read receipt also says delivered.
  readScope: string | null = null,
): { state: ReadState; notifications: MessageNotification[]; deliveries: { peer: ReceiptPeer; through: number }[] } {
  const state = { ...previous };
  const notifications: MessageNotification[] = [];
  const deliveries: { peer: ReceiptPeer; through: number }[] = [];
  for (const thread of threads) {
    const incoming = thread.messages.filter((message) => message.direction === 'received' &&
      (!('senderAccountId' in message) || hex(message.senderAccountId) !== own.accountId));
    const keys = receivedMessageKeys(incoming, own.accountId);
    const seen = new Set(previous[thread.scope]);
    state[thread.scope] = keys;
    // One cumulative receipt answers whatever arrived since the journal was written;
    // history from before then, such as before an upgrade, is left alone.
    const through = thread.peer && thread.scope !== readScope && keys.some((key) => !seen.has(key))
      ? receiptDue(thread.messages, 1) : undefined;
    if (thread.peer && through) deliveries.push({ peer: thread.peer, through });
    for (const [index, message] of incoming.entries()) {
      if (seen.has(keys[index]!) || thread.scope === activeScope || thread.blocked) continue;
      const group = 'senderAccountId' in message;
      const mention = group && mentionSpans(message.body, [own.username]).length > 0;
      const sender = group ? thread.senders?.[hex(message.senderAccountId)] ?? 'Someone' : '';
      const preview = 'disappearingSeconds' in message && message.disappearingSeconds > 0
        ? 'Disappearing message' : attachmentPreviewText(message).replace(/\s+/g, ' ').trim();
      if (!preview) continue;
      notifications.push({ id: `${thread.scope}/${keys[index]}`, scope: thread.scope,
        title: thread.title.slice(0, 100), mention,
        body: `${mention ? `${sender} mentioned you: ` : group ? `${sender}: ` : ''}${preview}`.slice(0, 240) });
    }
  }
  return { state, notifications, deliveries };
}
