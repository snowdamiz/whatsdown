import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseReadState, receivedMessageKeys, unreadCount } from './read-state.ts';

test('unread counts follow incoming message identity, not clocks, outgoing messages or expired history', () => {
  const incoming = (id: number, timestamp = 100) => ({
    direction: 'received' as const, messageId: Uint8Array.of(id), timestamp, body: '', disappearingSeconds: 0,
  });
  const first = incoming(1);
  const read = receivedMessageKeys([first]);
  const messages = [first, incoming(2, 90), { ...incoming(3), direction: 'sent' as const }];
  assert.equal(unreadCount(receivedMessageKeys(messages), read), 1);
  assert.equal(unreadCount(receivedMessageKeys(messages.slice(1)), read), 1);
  assert.equal(unreadCount(receivedMessageKeys(messages), receivedMessageKeys(messages)), 0);
  assert.equal(unreadCount(receivedMessageKeys(messages)), 2);
});

test('saved read state round-trips and malformed local data cannot hide messages', () => {
  const key = `chat/${'01'.repeat(16)}`;
  const state = { [key]: ['02'.repeat(16)] };
  assert.deepEqual(parseReadState(JSON.stringify(state)), state);
  for (const value of [null, '{', 'null', '[]', JSON.stringify({ [key]: 'invalid' }), '{"__proto__":[]}']) {
    assert.deepEqual(parseReadState(value), {});
  }
});

test('group messages from another own device are read; same-millisecond incoming messages count separately', () => {
  const message = { direction: 'received' as const, epoch: 1, senderAccountId: Uint8Array.of(2),
    senderDeviceId: Uint8Array.of(3), timestamp: 100, body: 'Hello' };
  const read = receivedMessageKeys([message], '01');
  const keys = receivedMessageKeys([message, message, { ...message, senderAccountId: Uint8Array.of(1) }], '01');
  assert.equal(keys.length, 2);
  assert.equal(unreadCount(keys, read), 1);
  assert.equal(unreadCount(keys, keys), 0);
  assert.deepEqual(receivedMessageKeys([{ ...message, messageId: Uint8Array.of(9), senderAccountId: Uint8Array.of(1) }], '01'), []);
});
