import assert from 'node:assert/strict';
import test from 'node:test';

import {
  boundedInteger,
  hexBytes,
  parseConversations,
  parseByteList,
  parseDeviceSetSummary,
  parseGroupDetails,
  parseGroupList,
  parseGroupHistory,
  parseHistory,
  parsePrekeyCount,
  parseProfileSummary,
  payloadFromQr,
  payloadQrValue,
  policyRequest,
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

test('profile and device-set QR limits match the canonical wire ceilings', () => {
  const profile = vectors(
    utf8('a'.repeat(64)),
    new Uint8Array(32),
    new Uint8Array(16),
    new Uint8Array(36_006),
  );
  assert.equal(profile.length, 36_134);
  assert.equal(parseProfileSummary(profile).username.length, 64);
  assert.equal(profileFromQr(profileQrValue(profile)).length, 36_134);
  assert.throws(() => profileFromQr(profileQrValue(new Uint8Array(36_135))));

  assert.equal(
    payloadFromQr(payloadQrValue('device-set', new Uint8Array(305_260)), 'device-set')
      .length,
    305_260,
  );
  assert.throws(() =>
    payloadFromQr(payloadQrValue('device-set', new Uint8Array(305_261)), 'device-set'),
  );
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

test('binary output lists decode each bounded envelope', () => {
  const first = Uint8Array.of(1, 2, 3);
  const second = Uint8Array.of(4, 5);
  assert.deepEqual(parseByteList(vectors(writeU32(2), first, second), 8, 65_606), [
    first,
    second,
  ]);
  const boundary = new Uint8Array(65_606);
  assert.equal(parseByteList(vectors(writeU32(1), boundary), 8, 65_606)[0]?.length, 65_606);
  assert.throws(() => parseByteList(vectors(writeU32(1), boundary), 8, 65_605));
  assert.throws(() => parseByteList(vectors(writeU32(9)), 8, 65_606));
});

test('Mesh-owned group summaries decode with exact bounded fields', () => {
  const groupId = new Uint8Array(32).fill(7);
  const encoded = vectors(
    writeU32(1),
    vectors(writeU32(4), Uint8Array.of(1), groupId, u64(9n), writeU32(3)),
  );
  const groups = parseGroupList(encoded);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0]?.groupId, groupId);
  assert.equal(groups[0]?.epoch, 9);
  assert.equal(groups[0]?.memberCount, 3);
  assert.throws(() =>
    parseGroupList(
      vectors(
        writeU32(1),
        vectors(writeU32(4), Uint8Array.of(2), groupId, u64(9n), writeU32(3)),
      ),
    ),
  );
});

test('Mesh-owned group history decodes bounded text records', () => {
  const accountId = new Uint8Array(32).fill(8);
  const deviceId = new Uint8Array(16).fill(9);
  const record = vectors(
    writeU32(7),
    Uint8Array.of(1),
    Uint8Array.of(2),
    u64(11n),
    accountId,
    deviceId,
    u64(1_800_000_000_000n),
    utf8('hello group'),
  );
  const history = parseGroupHistory(vectors(writeU32(1), record));
  assert.equal(history[0]?.direction, 'received');
  assert.equal(history[0]?.epoch, 11);
  assert.equal(history[0]?.body, 'hello group');
  assert.deepEqual(history[0]?.senderDeviceId, deviceId);
  assert.throws(() =>
    parseGroupHistory(
      vectors(
        writeU32(1),
        vectors(
          writeU32(7),
          Uint8Array.of(1),
          Uint8Array.of(3),
          u64(11n),
          accountId,
          deviceId,
          u64(1n),
          utf8('invalid direction'),
        ),
      ),
    ),
  );
  assert.throws(() => parseGroupHistory(new Uint8Array(65_537)));
});

test('Mesh-owned group inspection marks the local member without exposing routing tokens', () => {
  const groupId = new Uint8Array(32).fill(10);
  const accountId = new Uint8Array(32).fill(11);
  const deviceId = new Uint8Array(16).fill(12);
  const member = vectors(
    writeU32(7),
    Uint8Array.of(1),
    writeU32(7),
    Uint8Array.of(1),
    accountId,
    deviceId,
    u64(13n),
    Uint8Array.of(2),
  );
  const details = parseGroupDetails(
    vectors(
      writeU32(7),
      Uint8Array.of(1),
      groupId,
      u64(14n),
      writeU32(0),
      new Uint8Array(32).fill(15),
      new Uint8Array(32).fill(16),
      vectors(writeU32(1), member),
    ),
  );
  assert.equal(details.epoch, 14);
  assert.equal(details.members[0]?.leaf, 7);
  assert.equal(details.members[0]?.local, true);
  assert.deepEqual(details.members[0]?.accountId, accountId);
  assert.equal('mailboxToken' in (details.members[0] ?? {}), false);

  const invalidMember = vectors(
    writeU32(7),
    Uint8Array.of(1),
    writeU32(7),
    Uint8Array.of(2),
    accountId,
    deviceId,
    u64(13n),
    Uint8Array.of(2),
  );
  assert.throws(() =>
    parseGroupDetails(
      vectors(
        writeU32(7),
        Uint8Array.of(1),
        groupId,
        u64(14n),
        writeU32(0),
        new Uint8Array(32),
        new Uint8Array(32),
        vectors(writeU32(1), invalidMember),
      ),
    ),
  );
});

test('pinned transparency keys require canonical 32-byte hex', () => {
  assert.deepEqual(
    hexBytes('00ff'.repeat(16), 32),
    Uint8Array.from({ length: 32 }, (_, index) => (index % 2 === 0 ? 0 : 255)),
  );
  assert.throws(() => hexBytes('AA'.repeat(32), 32));
  assert.throws(() => hexBytes('0g'.repeat(32), 32));
  assert.throws(() => hexBytes('00', 32));
});

test('abuse work difficulty stays within the native verifier bound', () => {
  assert.equal(boundedInteger(undefined, 16, 1, 24), 16);
  assert.equal(boundedInteger('8', 16, 1, 24), 8);
  assert.throws(() => boundedInteger('0', 16, 1, 24));
  assert.throws(() => boundedInteger('1.5', 16, 1, 24));
});

test('native prekey reconciliation counts stay canonical and bounded', () => {
  assert.equal(parsePrekeyCount(writeU32(64)), 64);
  assert.throws(() => parsePrekeyCount(writeU32(65)));
  assert.throws(() => parsePrekeyCount(Uint8Array.of(0, 1)));
});

test('policy requests encode the peer reference before the action and value', () => {
  const peerReference = Uint8Array.of(0xa1, 0xb2, 0xc3);

  assert.deepEqual(
    policyRequest('/data/mobile.db', peerReference, 4, 3_600),
    vectors(utf8('/data/mobile.db'), peerReference, Uint8Array.of(4), writeU32(3_600)),
  );
});
