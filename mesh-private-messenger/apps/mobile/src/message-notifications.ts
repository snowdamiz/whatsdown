import { list_conversations_export, load_history_export, load_profile_export } from '../modules/mesh-messenger';
import { hex, parseConversations, parseHistory, parseProfileSummary, peerRequest, utf8 } from './codec';
import { inspectGroup, listGroups, loadGroupHistory, sendFanout, synchronizeMailbox } from './network';
import { loadPresentation } from './presentation-store';
import { getPushStatus } from './push';
import { showMessageNotification } from './notification-delivery';
import { planNotifications, type NotificationThread, type ReceiptPeer } from './notification-policy';
import { loadNotificationState, loadReceiptMarks, saveNotificationState, saveReceiptMarks } from './read-state-store';
import { advanceReceiptMarks, encodeReceipt } from './receipts';
import { createKeyedSerialQueue } from './single-flight';

const serialize = createKeyedSerialQueue<string>();
let activeScope: string | null = null;
let readScope: string | null = null;
// `readReceipts` says the open chat will answer with a read receipt, which also says delivered.
export function setActiveNotificationScope(scope: string | null, readReceipts = false): void {
  activeScope = scope;
  readScope = readReceipts ? scope : null;
}

async function loadThreads(path: string): Promise<NotificationThread[]> {
  const [conversations, groups] = await Promise.all([
    list_conversations_export(utf8(path)).then(parseConversations), listGroups(path),
  ]);
  return Promise.all([
    ...conversations.map(async (chat): Promise<NotificationThread> => ({
      scope: `chat/${hex(chat.conversationId)}`, title: `@${chat.username}`, blocked: chat.blocked,
      ...(chat.blocked || chat.requestPending ? {} : { peer: { username: chat.username, accountId: chat.peerAccountId } }),
      messages: parseHistory(await load_history_export(peerRequest(path, chat.peerAccountId))),
    })),
    ...groups.map(async (group): Promise<NotificationThread> => {
      const [messages, details, presentation] = await Promise.all([
        loadGroupHistory(path, group.groupId), inspectGroup(path, group.groupId),
        loadPresentation(path, `group/${hex(group.groupId)}`),
      ]);
      return { scope: `group/${hex(group.groupId)}`, title: presentation?.name ?? 'Group message', messages,
        senders: Object.fromEntries(details.members.flatMap((member) => member.username
          ? [[hex(member.accountId), `@${member.username}`]] : [])) };
    }),
  ]);
}

// What the other side acknowledged has to outlive its receipts; see ReceiptMarks.
// Every receipt arrives through a sync, so this is the only writer.
function rememberReceipts(account: string, threads: NotificationThread[]): void {
  try {
    const previous = loadReceiptMarks(account);
    const next = Object.fromEntries(threads.flatMap((thread) => {
      if (!thread.scope.startsWith('chat/')) return [];
      const marks = advanceReceiptMarks(thread.messages, previous[thread.scope]);
      return marks[0] ? [[thread.scope, marks]] : [];
    }));
    if (JSON.stringify(next) !== JSON.stringify(previous)) saveReceiptMarks(account, next);
  } catch { /* Ticks may go backwards; messages must still arrive. */ }
}

// Receipts are a courtesy and must never fail a sync. Stop at the first failure
// rather than wait out a timeout per chat; the next receipt covers these too.
async function acknowledge(path: string, deliveries: { peer: ReceiptPeer; through: number }[]): Promise<void> {
  try {
    for (const { peer, through } of deliveries) {
      await sendFanout(path, peer.username, encodeReceipt(1, through), peer.accountId);
    }
  } catch { /* best effort */ }
}

// Foreground and headless tasks share this queue and a journal of opaque IDs.
// A failed sync can still have committed messages, so always inspect local history.
// Delivery receipts go out after the sync settles: a headless task awaits `receipts`
// before the OS suspends it; the foreground shows the new messages without waiting.
export function synchronizeWithNotifications(path: string): Promise<{ receipts: Promise<void> }> {
  return serialize(path, async () => {
    const profile = parseProfileSummary(await load_profile_export(utf8(path)));
    const own = { accountId: hex(profile.accountId), username: profile.username };
    let previous;
    try {
      previous = loadNotificationState(own.accountId);
      if (previous === null) {
        previous = planNotifications(await loadThreads(path), {}, own, null).state;
        saveNotificationState(own.accountId, previous);
      }
    } catch (error) {
      // Notification metadata must never prevent receiving messages.
      await synchronizeMailbox(path);
      throw error;
    }
    let deliveries: { peer: ReceiptPeer; through: number }[] = [];
    try {
      await synchronizeMailbox(path);
    } finally {
      const threads = await loadThreads(path);
      rememberReceipts(own.accountId, threads);
      const plan = planNotifications(threads, previous, own, activeScope, readScope);
      if (await getPushStatus(path) === 'enabled') {
        for (const notification of plan.notifications) {
          if (await getPushStatus(path) !== 'enabled') break;
          await showMessageNotification(notification);
          // Persist each success so a later failure cannot replay the whole batch.
          const key = notification.id.slice(notification.scope.length + 1);
          previous[notification.scope] = [...(previous[notification.scope] ?? []), key].slice(-256);
          saveNotificationState(own.accountId, previous);
        }
      }
      saveNotificationState(own.accountId, plan.state);
      deliveries = plan.deliveries;
    }
    // Only reached when the sync succeeded, so a dead network is not retried per chat.
    return { receipts: acknowledge(path, deliveries) };
  });
}
