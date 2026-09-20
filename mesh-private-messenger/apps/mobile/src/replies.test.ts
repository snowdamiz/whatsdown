import assert from 'node:assert/strict';
import test from 'node:test';
import { hex, parseGroupHistory, parseHistory, utf8, vectors, writeU32 } from './codec.ts';
import { encodeReaction } from './reactions.ts';
import { encodeReply } from './replies.ts';

const u64 = (value: number) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};
const id = (serial: number, length = 32) => new Uint8Array(length).fill(serial);
const group = (body: string, account: number, serial: number) => {
  const fields = [Uint8Array.of(1), Uint8Array.of(2), u64(1), id(account), id(account, 16), u64(100 + serial),
    utf8(body), new Uint8Array(), id(serial)];
  return vectors(writeU32(fields.length), ...fields);
};
const groupHistory = (...records: Uint8Array[]) => parseGroupHistory(vectors(writeU32(records.length), ...records));

test('a group reply quotes the message in the reader’s own history, not words from the wire', () => {
  const [original, reply] = groupHistory(
    group('Lunch at noon?', 1, 7),
    group(encodeReply(hex(id(7)), 'Works for me'), 2, 8),
  );
  assert.equal(original?.reply, undefined);
  assert.equal(reply?.body, 'Works for me');
  assert.equal(reply?.reply?.target, hex(id(7)));
  assert.equal(reply?.reply?.message?.body, 'Lunch at noon?');
  // The quoted author is the authenticated sender of the local record.
  assert.deepEqual(reply?.reply?.message?.senderAccountId, id(1));
});

test('a reply whose target expired or never arrived keeps its words and quotes nothing', () => {
  const [reply] = groupHistory(group(encodeReply(hex(id(9)), 'Still on?'), 2, 8));
  assert.equal(reply?.body, 'Still on?');
  assert.deepEqual(reply?.reply, { target: hex(id(9)) });
});

test('a quoted reply shows its own words, one level deep', () => {
  const [, , last] = groupHistory(
    group('First', 1, 1),
    group(encodeReply(hex(id(1)), 'Second'), 2, 2),
    group(encodeReply(hex(id(2)), 'Third'), 1, 3),
  );
  assert.equal(last?.reply?.message?.body, 'Second');
  assert.equal(last?.reply?.message && 'reply' in last.reply.message, false);
});

test('replies can be reacted to, and reactions are never quoted', () => {
  const [, reply] = groupHistory(
    group('First', 1, 1),
    group(encodeReply(hex(id(1)), 'Second'), 2, 2),
    group(encodeReaction(hex(id(2)), '👍', 10), 1, 3),
  );
  assert.deepEqual(reply?.reactions, [{ emoji: '👍', senders: [hex(id(1))] }]);
});

test('direct replies resolve through 16-byte message IDs', () => {
  const entry = (direction: number, body: string, serial: number) => vectors(
    Uint8Array.of(direction), id(serial, 16), u64(serial), utf8(body), writeU32(0), new Uint8Array(),
    Uint8Array.of(0),
  );
  const [, reply] = parseHistory(vectors(writeU32(2), entry(2, 'Call me', 1), entry(1, encodeReply(hex(id(1, 16)), 'In five'), 2)));
  assert.equal(reply?.body, 'In five');
  assert.equal(reply?.reply?.message?.body, 'Call me');
  assert.equal(reply?.reply?.message?.direction, 'received');
});

test('a malformed header is only text, and a bad target cannot be encoded', () => {
  const [message] = groupHistory(group('MORSE-REPLY/1\nnot-an-id\nHello', 2, 8));
  assert.equal(message?.body, 'MORSE-REPLY/1\nnot-an-id\nHello');
  assert.equal(message?.reply, undefined);
  assert.throws(() => encodeReply('XYZ', 'Hello'), /Invalid reply/);
  assert.throws(() => encodeReply(hex(id(0xab)).toUpperCase(), 'Hello'), /Invalid reply/);
});
