import assert from 'node:assert/strict';
import test from 'node:test';
import { hex, parseGroupHistory, parseHistory, utf8, vectors, writeU32 } from './codec.ts';
import { describeReactions, encodeReaction, setReaction, summarizeReactions } from './reactions.ts';

const id = new Uint8Array(16).fill(1);
const u64 = (value: number) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};
const entry = (direction: number, body: string, serial = 1) => vectors(
  Uint8Array.of(direction), new Uint8Array(16).fill(serial), u64(serial), utf8(body), writeU32(0), new Uint8Array(),
  Uint8Array.of(0),
);
const history = (...entries: Uint8Array[]) => parseHistory(vectors(writeU32(entries.length), ...entries));
const reaction = (emoji: string, revision: number, target = hex(id)) =>
  `MORSE-REACTION/1\n${JSON.stringify([target, emoji, revision])}`;

test('encrypted history folds reactions into the target and counts each person once', () => {
  const messages = history(entry(1, 'Hello'), entry(2, reaction('👍', 10), 2), entry(1, reaction('👍', 11), 3));
  assert.equal(messages.length, 1);
  assert.equal(messages[0]?.body, 'Hello');
  assert.deepEqual(messages[0]?.reactions, [{ emoji: '👍', senders: ['received', 'sent'] }]);
});

test('replacements and removals converge despite duplicate or reordered deliveries', () => {
  const target = entry(1, 'Hello');
  const old = entry(2, reaction('👍', 10), 2);
  const changed = entry(2, reaction('❤️', 20), 3);
  const mine = entry(1, reaction('😂', 30), 4);
  assert.deepEqual(history(changed, target, mine, old, changed)[0]?.reactions,
    [{ emoji: '❤️', senders: ['received'] }, { emoji: '😂', senders: ['sent'] }]);
  const removed = entry(2, reaction('', 40), 5);
  assert.deepEqual(history(target, removed, changed, old, mine)[0]?.reactions,
    [{ emoji: '😂', senders: ['sent'] }]);
});

test('group reactions use stable IDs and authenticated accounts across linked devices', () => {
  const groupId = new Uint8Array(32).fill(9);
  const record = (body: string, account: number, device: number, messageId?: Uint8Array) => {
    const fields = [Uint8Array.of(1), Uint8Array.of(2), u64(1), new Uint8Array(32).fill(account),
      new Uint8Array(16).fill(device), u64(100 + device), utf8(body), new Uint8Array()];
    if (messageId) fields.push(messageId);
    return vectors(writeU32(fields.length), ...fields);
  };
  const records = [record('Older message', 1, 1), record('Hello group', 1, 1, groupId),
    record(encodeReaction(hex(groupId), '👍', 10), 2, 1),
    record(encodeReaction(hex(groupId), '❤️', 20), 2, 2),
    record(encodeReaction(hex(groupId), '❤️', 30), 3, 1)];
  const parsed = parseGroupHistory(vectors(writeU32(records.length), ...records));
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0]?.messageId, undefined);
  assert.deepEqual(parsed[1]?.messageId, groupId);
  assert.deepEqual(parsed[1]?.reactions, [{ emoji: '❤️', senders: [hex(new Uint8Array(32).fill(2)), hex(new Uint8Array(32).fill(3))] }]);
});

test('the pill shows the most-given emojis first, at most three, over the total count', () => {
  assert.deepEqual(summarizeReactions([]), { emojis: [], total: 0 });
  assert.deepEqual(summarizeReactions([{ emoji: '👍', senders: ['a'] }]), { emojis: ['👍'], total: 1 });
  const reactions = [
    { emoji: '😂', senders: ['a'] },
    { emoji: '👍', senders: ['b', 'c'] },
    { emoji: '❤️', senders: ['d'] },
    { emoji: '🎉', senders: ['e', 'f', 'g'] },
  ];
  // Ties keep history order, so the pill does not reshuffle as people react.
  assert.deepEqual(summarizeReactions(reactions), { emojis: ['🎉', '👍', '😂'], total: 7 });
});

test('reactions are described by name for assistive technology', () => {
  assert.equal(describeReactions([]), 'No reactions');
  assert.equal(describeReactions([{ emoji: '👍', senders: ['a'] }]), '1 reaction: Thumbs up');
  assert.equal(
    describeReactions([{ emoji: '😂', senders: ['a'] }, { emoji: '👍', senders: ['b', 'c'] }]),
    '3 reactions: Thumbs up 2, Laugh 1',
  );
});

test('a person holds one reaction at a time, and choosing none takes it back', () => {
  const start = [{ emoji: '👍', senders: ['a', 'b'] }, { emoji: '❤️', senders: ['c'] }];
  assert.deepEqual(setReaction(start, 'c', '👍'), [{ emoji: '👍', senders: ['a', 'b', 'c'] }]);
  assert.deepEqual(setReaction(start, 'a', '😂'),
    [{ emoji: '👍', senders: ['b'] }, { emoji: '❤️', senders: ['c'] }, { emoji: '😂', senders: ['a'] }]);
  assert.deepEqual(setReaction(start, 'b', ''), [{ emoji: '👍', senders: ['a'] }, { emoji: '❤️', senders: ['c'] }]);
  assert.deepEqual(setReaction(undefined, 'a', '👍'), [{ emoji: '👍', senders: ['a'] }]);
  assert.deepEqual(start, [{ emoji: '👍', senders: ['a', 'b'] }, { emoji: '❤️', senders: ['c'] }]);
});
