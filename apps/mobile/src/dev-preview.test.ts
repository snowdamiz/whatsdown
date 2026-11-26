import assert from 'node:assert/strict';
import test from 'node:test';
import { hex } from './codec.ts';
import { createDevPreview, type DevPreview } from './dev-preview.ts';
import { authorities, indexCommunities, joinRequests, mergeParts } from './communities.ts';
import { ownRequests, unansweredRequests } from './community-requests.ts';
import { receivedMessageKeys, unreadCount } from './read-state.ts';
import { messageStatus } from './receipts.ts';

// Everyday chats and groups, apart from the sample communities and the chats about joining them.
const plainChats = (preview: DevPreview) => preview.conversations.filter((item) =>
  !preview.histories[hex(item.conversationId)]!.some((message) => message.community));
const plainGroups = (preview: DevPreview) => preview.groups.filter((item) => !preview.presentations[`group/${hex(item.groupId)}`]?.community);

test('sample chats and groups have distinct identities and readable, chronological histories', () => {
  const now = Date.now();
  const preview = createDevPreview(now);
  assert.ok(preview.conversations.length >= 12);
  assert.ok(preview.groups.length >= 4);
  assert.equal(new Set(preview.conversations.map((item) => hex(item.conversationId))).size, preview.conversations.length);
  assert.equal(new Set(preview.groups.map((item) => hex(item.groupId))).size, preview.groups.length);
  for (const conversation of plainChats(preview)) {
    const messages = preview.histories[hex(conversation.conversationId)]!;
    assert.ok(messages.length >= 20);
    assert.equal(new Set(messages.map((message) => hex(message.messageId))).size, messages.length);
  }
  for (const group of preview.groups) {
    const details = preview.groupDetails[hex(group.groupId)]!;
    const messages = preview.groupHistories[hex(group.groupId)]!;
    assert.equal(details.members.length, group.memberCount);
    if (plainGroups(preview).includes(group)) assert.ok(messages.length >= 20);
    assert.ok(messages.every((message) => details.members.some((member) =>
      hex(member.accountId) === hex(message.senderAccountId) && hex(member.deviceId) === hex(message.senderDeviceId))));
  }
  for (const messages of [...Object.values(preview.histories), ...Object.values(preview.groupHistories)]) {
    assert.deepEqual(messages.map((message) => message.timestamp), messages.map((message) => message.timestamp).sort((a, b) => a - b));
    assert.ok(messages.every((message) => message.body.trim() && message.timestamp <= now));
  }
  for (const messages of [...plainChats(preview).map((item) => preview.histories[hex(item.conversationId)]!),
    ...preview.groups.map((item) => preview.groupHistories[hex(item.groupId)]!)]) {
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
  const groups = Object.fromEntries(plainGroups(preview).map((item) => [hex(item.groupId), preview.groupHistories[hex(item.groupId)]!]));
  assert.deepEqual(counts('group', groups), [3, 0, 1, 0, 8, 0, 2, 0]);
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
  for (const messages of [...plainChats(preview).map((item) => preview.histories[hex(item.conversationId)]!),
    ...Object.values(preview.groupHistories)]) {
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

test('sample communities: one you own across two parts, one you read, and requests to join both ways', () => {
  const self = new Uint8Array(32).fill(7);
  const now = 1_800_000_000_000;
  const preview = createDevPreview(now, self);
  const index = indexCommunities(preview.groups.map((item) => hex(item.groupId)), (id) => preview.presentations[`group/${id}`]);
  const [owned, read] = [...index.values()];
  assert.ok(owned && read);
  // Yours: two parts you are in, run with an admin, with posts sent to both.
  assert.equal(owned.community.owner, hex(self));
  assert.equal(owned.community.admins.length, 1);
  assert.equal(owned.parts.length, 2);
  const posts = mergeParts(owned.parts.map((part) => ({ id: part, messages: preview.groupHistories[part]! })), authorities(owned.community));
  assert.ok(posts.length >= 8 && posts.every((post) => post.copies.length === 2));
  assert.ok(posts.some((post) => post.reply?.message));
  assert.ok(posts.some((post) => (post.reactions ?? []).some((reaction) => reaction.senders.length >= 4)), 'Reactions add up across parts');
  const heard = owned.parts.flatMap((part) => preview.groupHistories[part]!);
  assert.equal(joinRequests(heard, owned.community, now).length, 2);
  // Someone else's: you hold one of its two parts and asked to join one of its groups.
  assert.notEqual(read.community.owner, hex(self));
  assert.deepEqual([read.parts.length, read.community.parts.length], [1, 2]);
  assert.deepEqual(joinRequests(preview.groupHistories[read.parts[0]!]!, read.community, now).map((request) => request.accountId), [hex(self)]);
  // Unread counts ride on the community's own ID.
  const unread = (entry: typeof owned) => unreadCount(receivedMessageKeys(mergeParts(entry.parts.map((part) =>
    ({ id: part, messages: preview.groupHistories[part]! })), authorities(entry.community))), preview.readState[`group/${entry.community.parts[0]}`]);
  assert.deepEqual([unread(owned), unread(read)], [1, 2]);
  // Through links: a stranger's request waits on you, and yours waits on someone else.
  const chats = Object.fromEntries(preview.conversations.map((item) => [item.username, item]));
  const asking = chats['degen_dan']!;
  assert.equal(asking.requestPending, true);
  assert.deepEqual(unansweredRequests(preview.histories[hex(asking.conversationId)]!, [], now).map((request) => request.community),
    [owned.community.parts[0]]);
  assert.deepEqual(ownRequests(preview.histories[hex(chats['nova_labs']!.conversationId)]!, now).map((request) => [request.name, request.state]),
    [['Arbitrum Guild', 'waiting']]);
});
