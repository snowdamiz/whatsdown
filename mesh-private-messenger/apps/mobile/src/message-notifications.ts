import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { account_capabilities_export, list_conversations_export, load_history_export, load_profile_export } from '../modules/mesh-messenger';
import { hex, parseConversations, parseHistory, parseProfileSummary, peerRequest, utf8, vectors, type GroupSummary } from './codec';
import { communityId, communityThread, indexCommunities } from './communities';
import { t } from './i18n';
import { inspectGroup, listGroups, loadGroupHistory, sendFanout, synchronizeMailbox } from './network';
import { loadPresentation } from './presentation-store';
import { getPushStatus } from './push';
import { showMessageNotification } from './notification-delivery';
import { planNotifications, redactNotification, type NotificationThread, type ReceiptPeer } from './notification-policy';
import { loadNotificationPreview, loadNotificationState, loadReceiptMarks, saveNotificationState, saveReceiptMarks } from './read-state-store';
import { advanceReceiptMarks, encodeReceipt } from './receipts';
import { createKeyedSerialQueue } from './single-flight';
export function createMessageNotificationServices(deps: Pick<ScopedClient, 'account_capabilities_export' | 'assertCurrent' | 'runPrivate' | 'list_conversations_export' | 'load_history_export' | 'load_profile_export' | 'onDispose'> & { inspectGroup: typeof inspectGroup; listGroups: typeof listGroups; loadGroupHistory: typeof loadGroupHistory; sendFanout: typeof sendFanout; synchronizeMailbox: typeof synchronizeMailbox; loadPresentation: typeof loadPresentation; getPushStatus: typeof getPushStatus; showMessageNotification: typeof showMessageNotification; loadNotificationPreview: typeof loadNotificationPreview; loadNotificationState: typeof loadNotificationState; loadReceiptMarks: typeof loadReceiptMarks; saveNotificationState: typeof saveNotificationState; saveReceiptMarks: typeof saveReceiptMarks }) {
const { account_capabilities_export, list_conversations_export, load_history_export, load_profile_export, inspectGroup, listGroups, loadGroupHistory, sendFanout, synchronizeMailbox, loadPresentation, getPushStatus, showMessageNotification, loadNotificationPreview, loadNotificationState, loadReceiptMarks, saveNotificationState, saveReceiptMarks } = deps;
const serialize = createKeyedSerialQueue<string>();
let activeScope: string | null = null;
let readScope: string | null = null;
deps.onDispose(() => { activeScope = null; readScope = null; });
// `readReceipts` says the open chat will answer with a read receipt, which also says delivered.
function setActiveNotificationScope(scope: string | null, readReceipts = false): void {
  if (scope !== null) deps.assertCurrent();
  activeScope = scope;
  readScope = readReceipts ? scope : null;
}
// Revalidate captured account/device keys after asynchronous reads and before
// notification effects. Native receipt sending also receives this profile so a
// replacement between this check and network entry cannot borrow its identity.
async function requireNotificationAccount(path: string, profile: Uint8Array): Promise<void> {
  await account_capabilities_export(vectors(utf8(path), profile));
}
async function loadThreads(path: string, own: string): Promise<NotificationThread[]> {
  const [conversations, groups] = await Promise.all([
    list_conversations_export(utf8(path)).then(parseConversations), listGroups(path),
  ]);
  const [direct, grouped] = await Promise.all([
    Promise.all(conversations.map(async (chat): Promise<NotificationThread> => ({
      scope: `chat/${hex(chat.conversationId)}`, title: `@${chat.username}`, blocked: chat.blocked,
      ...(chat.blocked || chat.requestPending ? {} : { peer: { username: chat.username, accountId: chat.peerAccountId } }),
      messages: parseHistory(await load_history_export(peerRequest(path, chat.peerAccountId))),
    }))),
    groupThreads(path, groups, own),
  ]);
  return [...direct, ...grouped];
}
// A community is one thread however many parts it spans, told only what its
// owner and admins post, plus, for them, who asked to join its groups.
async function groupThreads(path: string, groups: GroupSummary[], own: string): Promise<NotificationThread[]> {
  const loaded = await Promise.all(groups.map(async (group) => {
    const [messages, details, presentation] = await Promise.all([
      loadGroupHistory(path, group.groupId), inspectGroup(path, group.groupId),
      loadPresentation(path, `group/${hex(group.groupId)}`),
    ]);
    return { id: hex(group.groupId), messages, details, presentation };
  }));
  const byId = new Map(loaded.map((group) => [group.id, group]));
  const index = indexCommunities(loaded.map((group) => group.id), (id) => byId.get(id)?.presentation);
  const parts = new Set([...index.values()].flatMap((entry) => entry.parts));
  const senders = (members: { accountId: Uint8Array; username?: string }[]) => Object.fromEntries(members.flatMap((member) =>
    member.username ? [[hex(member.accountId), `@${member.username}`]] : []));
  return [
    ...loaded.filter((group) => !parts.has(group.id)).map((group) => ({
      scope: `group/${group.id}`, title: group.presentation?.name ?? t('Group message'), messages: group.messages,
      senders: senders(group.details.members),
    })),
    ...[...index.values()].map((entry) => {
      const held = entry.parts.map((part) => byId.get(part)!);
      return {
        scope: `group/${communityId(entry.community)}`, title: held[0]!.presentation?.name ?? t('Community'),
        messages: communityThread(held.map((part) => ({ id: part.id, messages: part.messages })), entry.community, own),
        senders: senders(held.flatMap((part) => part.details.members)),
      };
    }),
  ];
}
// What the other side acknowledged has to outlive its receipts; see ReceiptMarks.
// Every receipt arrives through a sync, so this is the only writer.
async function rememberReceipts(path: string, profile: Uint8Array, threads: NotificationThread[]): Promise<void> {
  try {
    const previous = await loadReceiptMarks(profile);
    await requireNotificationAccount(path, profile);
    const next = Object.fromEntries(threads.flatMap((thread) => {
      if (!thread.scope.startsWith('chat/')) return [];
      const marks = advanceReceiptMarks(thread.messages, previous[thread.scope]);
      return marks[0] ? [[thread.scope, marks]] : [];
    }));
    if (JSON.stringify(next) !== JSON.stringify(previous)) await saveReceiptMarks(profile, next);
  } catch { /* Ticks may go backwards; messages must still arrive. */ }
}
// Receipts are a courtesy and must never fail a sync. Stop at the first failure
// rather than wait out a timeout per chat; the next receipt covers these too.
async function acknowledge(path: string, profile: Uint8Array, deliveries: { peer: ReceiptPeer; through: number }[]): Promise<void> {
  try {
    for (const { peer, through } of deliveries) {
      await requireNotificationAccount(path, profile);
      await sendFanout(path, profile, peer.username, encodeReceipt(1, through), peer.accountId);
    }
  } catch { /* best effort */ }
}
// Foreground and headless tasks share this queue and a journal of opaque IDs.
// A failed sync can still have committed messages, so always inspect local history.
// Delivery receipts go out after the sync settles: a headless task awaits `receipts`
// before the OS suspends it; the foreground shows the new messages without waiting.
function synchronizeWithNotifications(path: string): Promise<{ receipts: Promise<void> }> {
  return serialize(path, async () => {
    const expectedProfile = (await load_profile_export(utf8(path))).slice();
    await requireNotificationAccount(path, expectedProfile);
    const profile = parseProfileSummary(expectedProfile);
    const own = { accountId: hex(profile.accountId), username: profile.username };
    let previous;
    try {
      previous = await loadNotificationState(expectedProfile);
      await requireNotificationAccount(path, expectedProfile);
      if (previous === null) {
        previous = planNotifications(await loadThreads(path, own.accountId), {}, own, null).state;
        await requireNotificationAccount(path, expectedProfile);
        await saveNotificationState(expectedProfile, previous);
      }
    } catch (error) {
      // Notification metadata must never prevent receiving messages for this account.
      await requireNotificationAccount(path, expectedProfile);
      await synchronizeMailbox(path);
      throw error;
    }
    let deliveries: { peer: ReceiptPeer; through: number }[] = [];
    try {
      await synchronizeMailbox(path);
    } finally {
      await requireNotificationAccount(path, expectedProfile);
      const threads = await loadThreads(path, own.accountId);
      await requireNotificationAccount(path, expectedProfile);
      await rememberReceipts(path, expectedProfile, threads);
      await requireNotificationAccount(path, expectedProfile);
      const plan = planNotifications(threads, previous, own, activeScope, readScope);
      const enabled = await getPushStatus(path, expectedProfile) === 'enabled';
      await requireNotificationAccount(path, expectedProfile);
      if (enabled) {
        for (const notification of plan.notifications) {
          const stillEnabled = await getPushStatus(path, expectedProfile) === 'enabled';
          await requireNotificationAccount(path, expectedProfile);
          if (!stillEnabled) break;
          const preview = await loadNotificationPreview(expectedProfile);
          await requireNotificationAccount(path, expectedProfile);
          await showMessageNotification(redactNotification(notification, preview));
          await requireNotificationAccount(path, expectedProfile);
          // Persist each success so a later failure cannot replay the whole batch.
          const key = notification.id.slice(notification.scope.length + 1);
          previous[notification.scope] = [...(previous[notification.scope] ?? []), key].slice(-256);
          await saveNotificationState(expectedProfile, previous);
        }
      }
      await requireNotificationAccount(path, expectedProfile);
      await saveNotificationState(expectedProfile, plan.state);
      await requireNotificationAccount(path, expectedProfile);
      deliveries = plan.deliveries;
    }
    // Only reached when the sync succeeded, so a dead network is not retried per chat.
    return { receipts: acknowledge(path, expectedProfile, deliveries) };
  });
}
return Object.freeze({ setActiveNotificationScope,
  synchronizeWithNotifications: (...args: Parameters<typeof synchronizeWithNotifications>) => deps.runPrivate(() => synchronizeWithNotifications(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createMessageNotificationServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createMessageNotificationServices({ assertCurrent: () => {}, runPrivate: operation => operation(), onDispose: () => () => {}, account_capabilities_export, list_conversations_export, load_history_export, load_profile_export, inspectGroup, listGroups, loadGroupHistory, sendFanout, synchronizeMailbox, loadPresentation, getPushStatus, showMessageNotification, loadNotificationPreview, loadNotificationState, loadReceiptMarks, saveNotificationState, saveReceiptMarks });
}
export const setActiveNotificationScope: ReturnType<typeof createMessageNotificationServices>['setActiveNotificationScope'] = (...args) => desktopCompatibility().setActiveNotificationScope(...args);
export const synchronizeWithNotifications: ReturnType<typeof createMessageNotificationServices>['synchronizeWithNotifications'] = (...args) => desktopCompatibility().synchronizeWithNotifications(...args);
