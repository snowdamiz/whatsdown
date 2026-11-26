import assert from 'node:assert/strict';
import test from 'node:test';
import { envelopeQueuedAt, parseGroupHistory, parseHistory, utf8, vectors, writeU32 } from './codec.ts';
import { advanceReceiptMarks, describeStatus, encodeReceipt, messageStatus, parseReceiptMarks, receiptDue } from './receipts.ts';

const u64 = (value: number) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
};
// History order is arrival order; the timestamp is the sender's clock.
// The last field is the core's delivery state: 0 left, 1 waiting, 2 refused for good.
const entry = (direction: 1 | 2, body: string, timestamp: number, delivery = 0) => vectors(
  Uint8Array.of(direction), new Uint8Array(16).fill(timestamp % 251), u64(timestamp), utf8(body), writeU32(0), new Uint8Array(),
  Uint8Array.of(delivery),
);
const sent = (body: string, timestamp: number, delivery = 0) => entry(1, body, timestamp, delivery);
const received = (body: string, timestamp: number) => entry(2, body, timestamp);
const history = (...entries: Uint8Array[]) => parseHistory(vectors(writeU32(entries.length), ...entries));
const states = (...entries: Uint8Array[]) => history(...entries).map((message) => [message.body, message.receipt]);

test('a receipt acknowledges every earlier message up to its watermark, and read implies delivered', () => {
  assert.deepEqual(
    states(sent('one', 10), sent('two', 20), sent('three', 30),
      received(encodeReceipt(1, 30), 31), received(encodeReceipt(2, 20), 32)),
    [['one', 2], ['two', 2], ['three', 1]],
  );
});

test('receipts converge when they are duplicated or arrive out of order', () => {
  const read = received(encodeReceipt(2, 20), 40);
  const delivered = received(encodeReceipt(1, 20), 41);
  assert.deepEqual(states(sent('one', 10), sent('two', 20), read, delivered, read),
    [['one', 2], ['two', 2]]);
});

test('a receipt never acknowledges a message that was sent after it arrived', () => {
  // The watermark is the peer's claim. Even a forged one cannot reach forward.
  assert.deepEqual(
    states(sent('before', 10), received(encodeReceipt(2, Number.MAX_SAFE_INTEGER), 11), sent('after', 12)),
    [['before', 2], ['after', undefined]],
  );
});

test('a message that crossed the receipt in flight stays unacknowledged', () => {
  assert.deepEqual(states(sent('seen', 10), sent('crossed', 20), received(encodeReceipt(2, 10), 21)),
    [['seen', 2], ['crossed', undefined]]);
});

test('each side acknowledges only the other side’s messages', () => {
  const messages = history(sent('mine', 10), received('theirs', 11),
    received(encodeReceipt(2, 99), 12), sent(encodeReceipt(1, 99), 13));
  assert.deepEqual(messages.map((message) => [message.body, message.receipt]), [['mine', 2], ['theirs', 1]]);
});

test('reserved receipt records never become bubbles, previews, or unread messages', () => {
  const oversized = `MORSE-RECEIPT/1\n[1,${'1'.repeat(80)}]`;
  for (const body of [encodeReceipt(1, 5), 'MORSE-RECEIPT/1\n', 'MORSE-RECEIPT/1\n[3,5]', 'MORSE-RECEIPT/1\n[1,-5]',
    'MORSE-RECEIPT/1\n[1,5,6]', 'MORSE-RECEIPT/1\n{"state":1}', oversized]) {
    assert.deepEqual(states(sent('hello', 5), received(body, 6)).map(([text]) => text), ['hello'], body);
  }
  // Only a well-formed receipt changes anything.
  assert.deepEqual(states(sent('hello', 5), received('MORSE-RECEIPT/1\n[3,5]', 6)), [['hello', undefined]]);
  assert.throws(() => encodeReceipt(3 as 1, 5));
  assert.throws(() => encodeReceipt(1, 0));
  assert.throws(() => encodeReceipt(1, 1.5));
});

test('receipts and reactions fold independently of each other', () => {
  const target = '05'.repeat(16);
  const messages = history(sent('hello', 5),
    received(`MORSE-REACTION/1\n${JSON.stringify([target, '👍', 7])}`, 6), received(encodeReceipt(2, 5), 7));
  assert.equal(messages.length, 1);
  assert.equal(messages[0]?.receipt, 2);
  assert.deepEqual(messages[0]?.reactions, [{ emoji: '👍', senders: ['received'] }]);
});

test('a receipt is due only for received messages this account has not yet acknowledged that far', () => {
  assert.equal(receiptDue(history(sent('mine', 10)), 1), undefined);
  assert.equal(receiptDue(history(received('a', 10), received('b', 20)), 1), 20);
  // A linked device's delivery receipt reaches this history as a sent record.
  const delivered = history(received('a', 10), received('b', 20), sent(encodeReceipt(1, 20), 21));
  assert.equal(receiptDue(delivered, 1), undefined);
  assert.equal(receiptDue(delivered, 2), 20);
  const read = history(received('a', 10), sent(encodeReceipt(2, 10), 11), received('b', 20));
  assert.equal(receiptDue(read, 1), 20);
  assert.equal(receiptDue(read, 2), 20);
  // Reactions and receipts from the peer are not messages to acknowledge.
  assert.equal(receiptDue(history(received(encodeReceipt(1, 5), 30)), 1), undefined);
});

test('a sent message shows what became of its own envelopes, until a receipt proves otherwise', () => {
  // One envelope waiting for a recipient who cannot take it now says nothing
  // about the messages sent after it: each has its own state.
  const [waiting, left, refused] = history(sent('waiting', 10, 1), sent('left', 20), sent('refused', 30, 2));
  assert.equal(messageStatus(waiting!), 'pending');
  assert.equal(messageStatus(left!), 'sent');
  assert.equal(messageStatus(refused!), 'failed');
  // The peer has it, so it arrived whatever one of their devices refused.
  const [acknowledged, incoming] = history(sent('acknowledged', 40, 2),
    received(encodeReceipt(1, 40), 41), received('incoming', 50));
  assert.equal(messageStatus(acknowledged!), 'delivered');
  assert.equal(messageStatus(incoming!), undefined);
});

test('turning read receipts off also hides the other side’s, as it does in other messengers', () => {
  const [message] = history(sent('hello', 10), received(encodeReceipt(2, 10), 11));
  assert.equal(messageStatus(message!), 'read');
  assert.equal(messageStatus(message!, false), 'delivered');
});

test('group messages carry a delivery state but no receipts', () => {
  const group = (delivery?: number) => {
    const fields = [Uint8Array.of(1), Uint8Array.of(1), u64(1), new Uint8Array(32).fill(1), new Uint8Array(16).fill(1),
      u64(10), utf8('hello'), new Uint8Array(), new Uint8Array(32).fill(7),
      ...(delivery === undefined ? [] : [Uint8Array.of(delivery)])];
    return parseGroupHistory(vectors(writeU32(1), vectors(writeU32(fields.length), ...fields)))[0]!;
  };
  assert.equal(messageStatus(group(1)), 'pending');
  assert.equal(messageStatus(group(2)), 'failed');
  assert.equal(messageStatus(group(0)), 'sent');
  // History stored before delivery was tracked has no such field.
  assert.equal(messageStatus(group()), 'sent');
  assert.throws(() => group(3), /delivery state/);
});

test('every state has words for people who cannot see the glyph', () => {
  assert.deepEqual((['pending', 'sent', 'delivered', 'read', 'failed'] as const).map(describeStatus),
    ['Sending', 'Sent', 'Delivered', 'Read', 'Not delivered']);
});

test('the oldest queued envelope tells when sending stalled', () => {
  // version, "MSG", envelope ID, mailbox token, suite, then the expiry 30 days after queueing.
  const envelope = new Uint8Array([1, ...utf8('MSG'), ...new Uint8Array(16), ...new Uint8Array(32), 0, 1,
    ...u64(1_800_000_000_000 + 2_592_000_000), ...writeU32(512), ...writeU32(0)]);
  assert.equal(envelopeQueuedAt(envelope), 1_800_000_000_000);
  assert.throws(() => envelopeQueuedAt(envelope.slice(0, 61)));
  assert.throws(() => envelopeQueuedAt(new Uint8Array([2, ...envelope.slice(1)])));
  assert.throws(() => envelopeQueuedAt(new Uint8Array([1, ...utf8('BAT'), ...envelope.slice(4)])));
});

test('an acknowledgement outlives the receipt that carried it, but not the messages it was for', () => {
  // Each side's disappearing timer stamps only what it sends, so the other side's
  // receipts can expire long before the messages they acknowledged.
  const marks = advanceReceiptMarks(history(sent('one', 10), sent('two', 20),
    received(encodeReceipt(2, 10), 21), received(encodeReceipt(1, 20), 22)));
  assert.deepEqual(marks, [20, 10]);
  const expired = history(sent('one', 10), sent('two', 20), sent('three', 30));
  assert.deepEqual(expired.map((message) => messageStatus(message, true, marks)), ['read', 'delivered', 'sent']);
  assert.deepEqual(expired.map((message) => messageStatus(message, false, marks)), ['delivered', 'delivered', 'sent']);
  assert.deepEqual(advanceReceiptMarks(expired, marks), [20, 10]);
  // Once the acknowledged messages are gone, nothing about them is kept.
  assert.deepEqual(advanceReceiptMarks(history(sent('three', 30)), marks), [0, 0]);
  // A forged watermark is remembered only as far as it really reached.
  assert.deepEqual(advanceReceiptMarks(history(sent('one', 10),
    received(encodeReceipt(2, Number.MAX_SAFE_INTEGER), 11), sent('later', 12))), [10, 10]);
});

test('stored receipt marks are bounded and validated before use', () => {
  const scope = `chat/${'a'.repeat(32)}`;
  assert.deepEqual(parseReceiptMarks(JSON.stringify({ [scope]: [20, 10] })), { [scope]: [20, 10] });
  for (const value of [null, 'not json', '[]', JSON.stringify({ [scope]: [20] }), JSON.stringify({ [scope]: [20, -1] }),
    JSON.stringify({ [scope]: [20, 1.5] }), JSON.stringify({ [scope]: ['20', 10] }), JSON.stringify({ 'chat/nope': [20, 10] }),
    JSON.stringify({ [`group/${'a'.repeat(64)}`]: [20, 10] })]) {
    assert.deepEqual(parseReceiptMarks(value), {}, String(value));
  }
});
