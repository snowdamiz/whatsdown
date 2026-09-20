import assert from 'node:assert/strict';
import test from 'node:test';
import { planNotifications, type NotificationThread } from './notification-policy.ts';

const own = { accountId: '01', username: 'sam.k' };
const message = { messageId: Uint8Array.of(9), direction: 'received' as const, body: 'Hi @sam.k!', timestamp: 1,
  epoch: 1, senderAccountId: Uint8Array.of(2), senderDeviceId: Uint8Array.of(3) };
const group: NotificationThread = { scope: `group/${'a'.repeat(64)}`, title: 'Friends', messages: [message], senders: { '02': '@alex' } };

test('new group tags and normal messages produce distinct alerts after decryption', () => {
  const plan = planNotifications([group], {}, own, null);
  assert.deepEqual(plan.notifications, [{ id: `${group.scope}/09`, scope: group.scope,
    title: 'Friends', body: '@alex mentioned you: Hi @sam.k!', mention: true }]);
  const normal = { ...group, messages: [{ ...message, body: 'Hello everyone' }] };
  assert.equal(planNotifications([normal], {}, own, null).notifications[0]?.body, '@alex: Hello everyone');
  assert.equal(planNotifications([normal], {}, own, null).notifications[0]?.mention, false);
  assert.deepEqual(planNotifications([group], plan.state, own, null).notifications, []);
});

test('disappearing messages do not leave their text in the OS notification history', () => {
  const chat: NotificationThread = { scope: `chat/${'b'.repeat(32)}`, title: '@alex', messages: [{
    messageId: Uint8Array.of(4), direction: 'received', timestamp: 1, body: 'Temporary secret', disappearingSeconds: 60,
  }] };
  assert.equal(planNotifications([chat], {}, own, null).notifications[0]?.body, 'Disappearing message');
  assert.deepEqual(planNotifications([{ ...chat, blocked: true }], {}, own, null).notifications, []);
  assert.deepEqual(planNotifications([chat], {}, own, chat.scope).notifications, []);
  assert.deepEqual(planNotifications([{ ...group, messages: [{ ...message, senderAccountId: Uint8Array.of(1) }] }], {}, own, null).notifications, []);
});

test('newly arrived direct messages are answered with one cumulative delivery receipt', () => {
  const peer = { username: 'alex', accountId: Uint8Array.of(2) };
  const chat: NotificationThread = { scope: `chat/${'c'.repeat(32)}`, title: '@alex', peer, messages: [
    { messageId: Uint8Array.of(4), direction: 'received', timestamp: 10, body: 'a', disappearingSeconds: 0 },
    { messageId: Uint8Array.of(5), direction: 'received', timestamp: 20, body: 'b', disappearingSeconds: 0 },
    { messageId: Uint8Array.of(6), direction: 'sent', timestamp: 30, body: 'c', disappearingSeconds: 0 },
  ] };
  const first = planNotifications([chat], {}, own, null);
  assert.deepEqual(first.deliveries, [{ peer, through: 20 }]);
  // Nothing arrived since the journal was written, so old history is left alone.
  assert.deepEqual(planNotifications([chat], first.state, own, null).deliveries, []);
  // An open chat that sends read receipts is about to say more than "delivered".
  assert.deepEqual(planNotifications([chat], {}, own, chat.scope, chat.scope).deliveries, []);
  assert.deepEqual(planNotifications([chat], {}, own, chat.scope).deliveries, [{ peer, through: 20 }]);
  // A linked device already acknowledged them.
  const acknowledged = { ...chat, messages: chat.messages.map((item) => ({ ...item, receipt: 1 as const })) };
  assert.deepEqual(planNotifications([acknowledged], {}, own, null).deliveries, []);
  // Requests and blocked chats carry no peer; strangers learn nothing. Groups send no receipts.
  assert.deepEqual(planNotifications([{ ...chat, peer: undefined }, group], {}, own, null).deliveries, []);
});
