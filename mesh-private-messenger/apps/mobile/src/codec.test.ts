import assert from 'node:assert/strict';
import test from 'node:test';

import {
  encodeAttachmentReferences,
  linkRequestFromQr,
  parseAttachmentSummary,
  parseConversations,
  parseByteList,
  parseDeviceSetSummary,
  parseGroupDetails,
  parseGroupList,
  parseGroupHistory,
  parseGroupInvitations,
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

test('group invitations expose a bounded device reference and explicit acceptance state', () => {
  const reference = new Uint8Array(32).fill(1);
  const groupId = new Uint8Array(32).fill(2);
  const accountId = new Uint8Array(32).fill(3);
  const invitation = vectors(writeU32(5), reference, groupId, utf8('alice'), accountId, Uint8Array.of(1));
  assert.deepEqual(parseGroupInvitations(vectors(writeU32(1), invitation)), [{
    reference, groupId, username: 'alice', accountId, state: 1,
  }]);
  assert.throws(() => parseGroupInvitations(vectors(writeU32(1),
    vectors(writeU32(5), reference, groupId, utf8('alice'), accountId, Uint8Array.of(9)))));
  assert.throws(() => parseGroupInvitations(vectors(writeU32(1),
    vectors(writeU32(5), reference.slice(1), groupId, utf8('alice'), accountId, Uint8Array.of(1)))));
  assert.throws(() => parseGroupInvitations(vectors(writeU32(129))));
});

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

  const link = Uint8Array.from({ length: 1_326 }, (_, index) => index % 251);
  assert.deepEqual(linkRequestFromQr(payloadQrValue('link-request', link)), link);
  assert.throws(() =>
    linkRequestFromQr(payloadQrValue('link-request', new Uint8Array(1_327))),
  );
  assert.throws(() => linkRequestFromQr('mesh://link-request/not-base64!'));
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
    new Uint8Array(),
    Uint8Array.of(0),
  );
  const history = parseHistory(vectors(writeU32(1), message));
  assert.equal(history[0]?.direction, 'received');
  assert.equal(history[0]?.body, 'hello');
  assert.equal('attachments' in history[0]!, false);
  assert.throws(() => parseHistory(new Uint8Array([...vectors(writeU32(0)), 1])));
  assert.equal(vector(utf8('ok')).length, 6);
});

const attachmentSummary = (size: number, chunkCount = Math.ceil(size / 65_536)): Uint8Array => vectors(
  writeU32(9),
  Uint8Array.of(1, 65, 84, 82, 5),
  new Uint8Array(32).fill(1),
  new Uint8Array(32).fill(2),
  utf8('photo.jpg'),
  utf8('image/jpeg'),
  writeU32(size),
  writeU32(chunkCount),
  writeU32(65_536),
  u64(1_800_000_600_000n),
);

test('history entries expose opened attachment manifests next to their opaque reference', () => {
  const message = vectors(Uint8Array.of(1), new Uint8Array(16), u64(1_800_000_000_000n), new Uint8Array(), writeU32(0),
    attachmentSummary(70_000), Uint8Array.of(0));
  const [entry] = parseHistory(vectors(writeU32(1), message));
  assert.equal(entry?.body, '');
  assert.deepEqual(entry?.attachments, [{
    reference: Uint8Array.of(1, 65, 84, 82, 5),
    objectId: new Uint8Array(32).fill(1),
    downloadCapability: new Uint8Array(32).fill(2),
    filename: 'photo.jpg',
    mimeType: 'image/jpeg',
    size: 70_000,
    chunkCount: 2,
    chunkSize: 65_536,
    expiresAt: 1_800_000_600_000,
  }]);
  assert.deepEqual(parseAttachmentSummary(new Uint8Array()), undefined);
  assert.throws(() => parseAttachmentSummary(attachmentSummary(70_000, 1)));
  assert.throws(() => parseAttachmentSummary(attachmentSummary(0)));
  assert.throws(() => parseAttachmentSummary(attachmentSummary(256 * 65_536 + 1)));
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
    writeU32(8),
    Uint8Array.of(1),
    Uint8Array.of(2),
    u64(11n),
    accountId,
    deviceId,
    u64(1_800_000_000_000n),
    utf8('hello group'),
    new Uint8Array(),
  );
  const history = parseGroupHistory(vectors(writeU32(1), record));
  assert.equal(history[0]?.direction, 'received');
  assert.equal(history[0]?.epoch, 11);
  assert.equal(history[0]?.body, 'hello group');
  assert.deepEqual(history[0]?.senderDeviceId, deviceId);
  assert.equal('attachments' in history[0]!, false);
  const withAttachment = vectors(writeU32(8), Uint8Array.of(1), Uint8Array.of(1), u64(11n), accountId, deviceId,
    u64(1_800_000_000_000n), new Uint8Array(), attachmentSummary(10));
  assert.equal(parseGroupHistory(vectors(writeU32(1), withAttachment))[0]?.attachments?.[0]?.filename, 'photo.jpg');
  assert.throws(() =>
    parseGroupHistory(
      vectors(
        writeU32(1),
        vectors(
          writeU32(8),
          Uint8Array.of(1),
          Uint8Array.of(3),
          u64(11n),
          accountId,
          deviceId,
          u64(1n),
          utf8('invalid direction'),
          new Uint8Array(),
        ),
      ),
    ),
  );
  assert.throws(() => parseGroupHistory(new Uint8Array(65_536 + 256 * 2_048 + 1)));
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

test('native prekey reconciliation counts stay canonical and bounded', () => {
  assert.equal(parsePrekeyCount(writeU32(64)), 64);
  assert.throws(() => parsePrekeyCount(writeU32(65)));
  assert.throws(() => parsePrekeyCount(Uint8Array.of(0, 1)));
});

test('group inspection exposes a separate verified username and accepts older member records', () => {
  const member = (username?: string) => vectors(writeU32(username === undefined ? 7 : 8), Uint8Array.of(1), writeU32(0),
    Uint8Array.of(0), new Uint8Array(32), new Uint8Array(16), u64(1n), Uint8Array.of(2),
    ...(username === undefined ? [] : [utf8(username)]));
  const details = (records: Uint8Array[]) => vectors(writeU32(7), Uint8Array.of(1), new Uint8Array(32), u64(1n),
    writeU32(0), new Uint8Array(32), new Uint8Array(32), vectors(writeU32(records.length), ...records));
  assert.equal(parseGroupDetails(details([member('maya_1987')])).members[0]?.username, 'maya_1987');
  assert.equal(parseGroupDetails(details([member()])).members[0]?.username, undefined);
  assert.equal(parseGroupDetails(details([member('')])).members[0]?.username, undefined);
  assert.equal(parseGroupDetails(details(Array.from({ length: 64 }, () => member('a'.repeat(64))))).members.length, 64);
  assert.throws(() => parseGroupDetails(details([member('Maya Chen')])));
});

test('policy requests encode the peer reference before the action and value', () => {
  const peerReference = Uint8Array.of(0xa1, 0xb2, 0xc3);

  assert.deepEqual(
    policyRequest('/data/mobile.db', peerReference, 4, 3_600),
    vectors(utf8('/data/mobile.db'), peerReference, Uint8Array.of(4), writeU32(3_600)),
  );
});

test('ten attachments remain ordered in one direct or group history message', () => {
  const batch = new Uint8Array([
    1, 65, 84, 66, ...writeU32(10),
    ...vectors(...Array.from({ length: 10 }, (_, index) => attachmentSummary(index + 1))),
  ]);
  const direct = vectors(Uint8Array.of(1), new Uint8Array(16), u64(1n), utf8('album'), writeU32(0), batch, Uint8Array.of(0));
  const group = vectors(writeU32(8), Uint8Array.of(1), Uint8Array.of(1), u64(1n), new Uint8Array(32),
    new Uint8Array(16), u64(1n), utf8('album'), batch);
  for (const messages of [parseHistory(vectors(writeU32(1), direct)), parseGroupHistory(vectors(writeU32(1), group))]) {
    assert.equal(messages.length, 1);
    assert.equal(messages[0]?.body, 'album');
    assert.deepEqual(messages[0]?.attachments?.map((file) => file.size), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  }
});


test('attachment lists reject invalid counts, empty references, truncation, and trailing bytes', () => {
  const references = Array.from({ length: 10 }, (_, index) => Uint8Array.of(index + 1));
  assert.deepEqual(encodeAttachmentReferences([]), new Uint8Array());
  assert.equal(encodeAttachmentReferences([references[0]!]), references[0]);
  assert.throws(() => encodeAttachmentReferences([...references, references[0]!]), /up to 10/);
  assert.throws(() => encodeAttachmentReferences([new Uint8Array()]));
  const summary = attachmentSummary(10);
  const batch = (count: number, ...parts: Uint8Array[]) => new Uint8Array([1, 65, 84, 66, ...writeU32(count), ...vectors(...parts)]);
  const valid = batch(2, summary, summary);
  for (const invalid of [batch(11, ...Array(11).fill(summary)), batch(1, summary), batch(2, summary, new Uint8Array()),
    valid.subarray(0, valid.length - 1), new Uint8Array([...valid, 0])]) {
    const message = vectors(Uint8Array.of(1), new Uint8Array(16), u64(1n), new Uint8Array(), writeU32(0), invalid, Uint8Array.of(0));
    assert.throws(() => parseHistory(vectors(writeU32(1), message)));
  }
});
