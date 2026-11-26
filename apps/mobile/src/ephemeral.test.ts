import assert from 'node:assert/strict';
import test from 'node:test';

import { attachmentPreviewText } from './attachments.ts';
import { parseGroupHistory, parseHistory, utf8, vectors, writeU32 } from './codec.ts';
import {
  describeSafetyCheck,
  parsePurge,
  purgeDelay,
  timerNotice,
  viewOnceText,
} from './ephemeral.ts';

const u64 = (value: bigint): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
};

test('history summaries say whether a view-once message is still unopened', () => {
  const entry = (kind: number) => vectors(Uint8Array.of(2), new Uint8Array(16), u64(1_800_000_000_000n),
    new Uint8Array(), writeU32(0), new Uint8Array(), Uint8Array.of(0), Uint8Array.of(kind));
  const [unopened, gone, plain] = parseHistory(vectors(writeU32(3), entry(1), entry(2), entry(0)));
  assert.equal(unopened?.viewOnce, 'unopened');
  assert.equal(gone?.viewOnce, 'gone');
  assert.equal(plain?.viewOnce, undefined);
  assert.throws(() => parseHistory(vectors(writeU32(1), entry(3))));
});

test('group summaries carry expiry, view-once state and timer notices', () => {
  const record = (kind: number, body: string, expiresAt: bigint) => vectors(writeU32(12), Uint8Array.of(1),
    Uint8Array.of(2), u64(3n), new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), u64(1_800_000_000_000n),
    utf8(body), new Uint8Array(), new Uint8Array(32).fill(3), Uint8Array.of(0), u64(expiresAt), Uint8Array.of(kind));
  const [message, notice, unopened] = parseGroupHistory(vectors(writeU32(3),
    record(0, 'brief', 1_800_000_060_000n), record(3, '3600', 0n), record(1, '', 0n)));
  assert.equal(message?.expiresAt, 1_800_000_060_000);
  assert.equal(message?.viewOnce, undefined);
  assert.equal(notice?.timerNotice, 3600);
  assert.equal('expiresAt' in notice!, false);
  assert.equal(unopened?.viewOnce, 'unopened');
  assert.throws(() => parseGroupHistory(vectors(writeU32(1), record(4, '', 0n))));
});

test('a purge hands over the next expiry and the objects to forget', () => {
  const objectId = new Uint8Array(32).fill(0xab);
  assert.deepEqual(parsePurge(vectors(writeU32(2), u64(1_800_000_000_000n), objectId)), {
    next: 1_800_000_000_000,
    objectIds: ['ab'.repeat(32)],
  });
  assert.deepEqual(parsePurge(vectors(writeU32(1), u64(0n))), { next: 0, objectIds: [] });
  assert.throws(() => parsePurge(vectors(writeU32(2), u64(0n), new Uint8Array(31))));
});

test('the purge timer wakes at the next expiry, never busier than a second nor idler than a minute', () => {
  const now = 1_800_000_000_000;
  assert.equal(purgeDelay(now + 5_000, now), 5_000);
  assert.equal(purgeDelay(now - 10, now), 1_000);
  assert.equal(purgeDelay(now + 3_600_000, now), 60_000);
  assert.equal(purgeDelay(0, now), 60_000);
});

test('timer notices name who changed the timer and what it is now', () => {
  assert.equal(timerNotice('You', 3_600), 'You set disappearing messages to 1 hour.');
  assert.equal(timerNotice('Ada', 60), 'Ada set disappearing messages to 1 minute.');
  assert.equal(timerNotice('Ada', 0), 'Ada turned off disappearing messages.');
  assert.equal(timerNotice('Ada', 172_800), 'Ada set disappearing messages to 2 days.');
});

test('view-once bubbles never show content and say what a tap does', () => {
  assert.equal(viewOnceText({ direction: 'received', viewOnce: 'unopened' }), 'View once · Tap to open');
  assert.equal(viewOnceText({ direction: 'received', viewOnce: 'gone' }), 'Opened');
  assert.equal(viewOnceText({ direction: 'sent', viewOnce: 'gone' }), 'View once message');
});

test('chat lists and notifications never show a view-once message or read a timer notice as words', () => {
  assert.equal(attachmentPreviewText({ body: '', viewOnce: 'unopened' }), 'View once message');
  assert.equal(attachmentPreviewText({ body: 'secret', viewOnce: 'unopened' }), 'View once message');
  assert.equal(attachmentPreviewText({ body: '3600', timerNotice: 3600 }), 'Changed the disappearing-message timer');
  assert.equal(attachmentPreviewText({ body: '0', timerNotice: 0 }), 'Turned off disappearing messages');
  assert.equal(attachmentPreviewText({ body: 'hello' }), 'hello');
});

test('a scanned safety code says plainly what it means', () => {
  assert.deepEqual(describeSafetyCheck('verified', 'ada'),
    { tone: 'success', text: 'The codes match. @ada is verified on this device.' });
  assert.equal(describeSafetyCheck('mismatch', 'ada').tone, 'error');
  assert.match(describeSafetyCheck('mismatch', 'ada').text, /don’t match/);
  assert.match(describeSafetyCheck('wrong_contact', 'ada').text, /someone else/);
  assert.match(describeSafetyCheck('invalid', 'ada').text, /isn’t a safety code/);
});
