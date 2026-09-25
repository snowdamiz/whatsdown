import assert from 'node:assert/strict';
import test from 'node:test';
import { hex } from './codec.ts';
import { createDevPreview } from './dev-preview.ts';
import { receivedMessageKeys, unreadCount } from './read-state.ts';
import { messageStatus } from './receipts.ts';

test('sample chats and groups have distinct identities and readable, chronological histories', () => {
  const now = Date.now();
  const preview = createDevPreview(now);
  assert.ok(preview.conversations.length >= 12);
  assert.ok(preview.groups.length >= 4);
  assert.equal(new Set(preview.conversations.map((item) => hex(item.conversationId))).size, preview.conversations.length);
  assert.equal(new Set(preview.groups.map((item) => hex(item.groupId))).size, preview.groups.length);
  for (const conversation of preview.conversations) {
    const messages = preview.histories[hex(conversation.conversationId)]!;
    assert.ok(messages.length >= 20);
    assert.equal(new Set(messages.map((message) => hex(message.messageId))).size, messages.length);
  }
  for (const group of preview.groups) {
    const details = preview.groupDetails[hex(group.groupId)]!;
    const messages = preview.groupHistories[hex(group.groupId)]!;
    assert.equal(details.members.length, group.memberCount);
    assert.ok(messages.length >= 20);
    assert.ok(messages.every((message) => details.members.some((member) =>
      hex(member.accountId) === hex(message.senderAccountId) && hex(member.deviceId) === hex(message.senderDeviceId))));
  }
  for (const messages of [...Object.values(preview.histories), ...Object.values(preview.groupHistories)]) {
    assert.deepEqual(messages.map((message) => message.timestamp), messages.map((message) => message.timestamp).sort((a, b) => a - b));
    assert.ok(messages.every((message) => message.body.trim() && message.timestamp <= now));
    assert.deepEqual(new Set(messages.map((message) => message.direction)), new Set(['sent', 'received']));
  }
});

test('sample content includes read, single-unread and multiple-unread conversations with incoming previews', () => {
  const preview = createDevPreview(1_800_000_000_000);
  const counts = (kind: 'chat' | 'group', histories: typeof preview.histories | typeof preview.groupHistories) =>
    Object.entries(histories).map(([id, messages]) => {
      const count = unreadCount(receivedMessageKeys(messages), preview.readState[`${kind}/${id}`]);
      if (count) assert.equal(messages.at(-1)?.direction, 'received', 'Unread examples should end with a message to check');
      return count;
    });
  assert.deepEqual(counts('chat', preview.histories).slice(0, 6), [2, 0, 1, 0, 12, 0]);
  assert.deepEqual(counts('group', preview.groupHistories), [3, 0, 1, 0, 8, 0]);
  for (const conversation of preview.conversations.filter((item) => item.blocked)) {
    const id = hex(conversation.conversationId);
    assert.equal(unreadCount(receivedMessageKeys(preview.histories[id]!), preview.readState[`chat/${id}`]), 0);
  }
});

test('sample chats show each delivery state a synced bubble can take', () => {
  const [messages] = Object.values(createDevPreview(1_800_000_000_000).histories);
  assert.deepEqual(new Set(messages!.flatMap((message) => messageStatus(message) ?? [])),
    new Set(['sent', 'delivered', 'read']));
  assert.ok(messages!.every((message) => message.direction === 'sent' || !message.receipt));
});

test('sample threads show reactions and quoted replies, and every sample message can take them', () => {
  const preview = createDevPreview(1_800_000_000_000);
  for (const messages of [...Object.values(preview.histories), ...Object.values(preview.groupHistories)]) {
    assert.ok(messages.every((message) => message.messageId));
    assert.ok(messages.some((message) => message.reactions?.length));
    const replies = messages.filter((message) => message.reply);
    assert.ok(replies.length);
    // A quote names a message still in the thread, as the codec's would.
    for (const { reply } of replies) {
      assert.ok(messages.some((message) => hex(message.messageId!) === reply!.target && message.body === reply!.message?.body));
    }
  }
});
