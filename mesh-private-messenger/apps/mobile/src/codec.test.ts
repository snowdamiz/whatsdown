import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseConversations,
  parseDeviceSetSummary,
  parseHistory,
  parseProfileSummary,
  payloadFromQr,
  payloadQrValue,
  profileFromQr,
  profileQrValue,
  utf8,
  vector,
  vectors,
  writeU32,
} from './codec.ts';

const u64 = (value: bigint): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
};

test('contact QR values round trip binary profiles', () => {
  const profile = Uint8Array.from({ length: 257 }, (_, index) => index % 251);
  assert.deepEqual(profileFromQr(profileQrValue(profile)), profile);
  assert.throws(() => profileFromQr('https://example.com/not-a-contact'));
});

test('device summaries and linking QR payloads stay bounded and canonical', () => {
  const current = vectors(new Uint8Array(16).fill(1), Uint8Array.of(1), Uint8Array.of(1));
  const revoked = vectors(new Uint8Array(16).fill(2), Uint8Array.of(0), Uint8Array.of(0));
  const summary = parseDeviceSetSummary(
    vectors(
      utf8('alice'),
      new Uint8Array(32).fill(3),
      u64(9n),
      Uint8Array.of(1),
      Uint8Array.of(1),
      vectors(writeU32(2), current, revoked),
    ),
  );
  assert.equal(summary.username, 'alice');
  assert.equal(summary.sequence, 9);
  assert.equal(summary.changed, true);
  assert.equal(summary.canManage, true);
  assert.equal(summary.devices[0]?.current, true);
  assert.equal(summary.devices[1]?.active, false);

  const profile = vectors(
    utf8('alice'),
    new Uint8Array(32).fill(3),
    new Uint8Array(16).fill(1),
    Uint8Array.of(9),
  );
  assert.equal(parseProfileSummary(profile).username, 'alice');

  const link = Uint8Array.from({ length: 140 }, (_, index) => index % 251);
  assert.deepEqual(payloadFromQr(payloadQrValue('link-request', link), 'link-request'), link);
  assert.throws(() => payloadFromQr(payloadQrValue('link-request', link), 'link-authorization'));
});

test('conversation and history lists reject trailing bytes and decode policy state', () => {
  const summary = vectors(
    new Uint8Array(16),
    utf8('alice'),
    new Uint8Array(32),
    new Uint8Array(16),
    utf8('0123456789abcdef'.repeat(4)),
    Uint8Array.of(0),
    Uint8Array.of(1),
    Uint8Array.of(0),
    Uint8Array.of(1),
    writeU32(60),
  );
  const conversations = parseConversations(vectors(writeU32(1), summary));
  assert.equal(conversations[0]?.username, 'alice');
  assert.equal(conversations[0]?.requestPending, true);
  assert.equal(conversations[0]?.blocked, true);
  assert.equal(conversations[0]?.keyChanged, true);

  const message = vectors(
    Uint8Array.of(2),
    new Uint8Array(16),
    u64(1_800_000_000_000n),
    utf8('hello'),
    writeU32(30),
  );
  const history = parseHistory(vectors(writeU32(1), message));
  assert.equal(history[0]?.direction, 'received');
  assert.equal(history[0]?.body, 'hello');
  assert.throws(() => parseHistory(new Uint8Array([...vectors(writeU32(0)), 1])));
  assert.equal(vector(utf8('ok')).length, 6);
});
