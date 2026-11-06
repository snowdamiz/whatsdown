import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loaded, bytes, utf8, concat, uint, vector, list, action, common, badRequest, badReply } from '../scripts/backup-native-test-fixture.mjs';
const { c } = await loaded();
const id = bytes(32, 9), scope = bytes(32, 3), token = bytes(32, 7);
const fields = { ordinal: 255, direction: 2, messageId: bytes(0), text: utf8('hé'), slots: [] };
const included = (slot = 0, name = utf8('résumé.txt'), mime = utf8('text/plain'), size = 65537, key = token) => list([slot], [0], name, mime, uint(size, 4), key);
const omitted = (slot = 1, reason = 3) => list([slot], [reason]);
const row = (value = {}) => {
  const r = { ...fields, ...value };
  return list(uint(r.ordinal, 2), [r.direction], r.messageId, bytes(32, 4), bytes(16, 5), uint('18446744073709551615', 8), r.text, list(...r.slots));
};
const page = (rows = [row({ slots: [included(), omitted()] })], next = [0], offset = 0, kind = 2, scopeId = scope) => concat([2, 0], list(id, [kind], scopeId, uint(offset, 4), next, list(...rows)));
const conversation = (kind = 2, count = 1, scopeId = scope, name = utf8('café')) => list([kind], scopeId, kind === 1 ? bytes(32, 4) : bytes(0), name, uint(count, 4));
const overview = (fileCounts = [2, 1, 0, 0, 1, 0], policy = 1, counts = [1, 2, 1, 0, 0, 0, 2], scopes = [conversation()]) => concat([2], list(id, uint('18446744073709551615', 8), ...counts.map(n => uint(n, 4)), [policy], list(...fileCounts.map(n => uint(n, 4))), list(...scopes)));
const chunk = (data = bytes(1, 42), index = 1, size = 65537, kind = 2, scopeId = scope, ordinal = 255, slot = 0, key = token) => concat([2, 1], list(id, [kind], scopeId, uint(ordinal, 2), [slot], [index], uint(size, 4), key, data));

test('content chunk requests preserve exact tags widths limits and copied selector bytes', () => {
  for (const [kind, tag] of [['direct', 3], ['group', 4]]) {
    const selected = { kind, token: token.slice(), ordinal: 255, slot: 9, chunk: 255 };
    const encoded = c.encodeBackupChunkRequest(action, id, selected);
    assert.deepEqual(encoded, concat(common, id, [tag], vector(token), [255, 9, 255]));
    selected.token.fill(0); assert.deepEqual(encoded, concat(common, id, [tag], vector(token), [255, 9, 255]));
  }
  const valid = { kind: 'group', token, ordinal: 1, slot: 0, chunk: 0 };
  for (const value of [{ kind: 'unknown' }, { token: bytes(31) }, { ordinal: -1 }, { ordinal: 256 }, { slot: 10 }, { chunk: 256 }, { chunk: 0.5 }]) badRequest(() => c.encodeBackupChunkRequest(action, id, { ...valid, ...value }));
  const maximum = c.encodeBackupChunkRequest({ databasePath: 'x'.repeat(4096), expectedProfile: bytes(36134) }, id, valid);
  assert.equal(maximum.length, 40311);
  badRequest(() => c.encodeBackupChunkRequest({ ...action, expectedProfile: bytes(36135) }, id, valid));
  badRequest(() => c.encodeBackupChunkRequest(action, bytes(31), valid));
});

test('content overview conserves message and file counters while preserving zero-file and legacy scope semantics', () => {
  const value = c.decodeReadonlyBackupOverviewReply(overview());
  assert.equal(value.kind, 'content'); assert.equal(value.value.createdAt, '18446744073709551615');
  assert.deepEqual(value.value.files, { total: 2, included: 1, unavailable: 0, expired: 0, unsupported: 1, aboveProfile: 0 });
  assert.equal(value.value.policy, 'allowOmissions'); assert.equal(value.value.conversations[0].name, 'café');
  assert.equal(c.decodeReadonlyBackupOverviewReply(overview([0, 0, 0, 0, 0, 0], 0)).value.files.total, 0);
  for (const counts of [[1, 1, 0, 0, 1, 0], [4097, 4097, 0, 0, 0, 0], [11, 11, 0, 0, 0, 0]]) badReply(() => c.decodeReadonlyBackupOverviewReply(overview(counts)));
  badReply(() => c.decodeReadonlyBackupOverviewReply(overview([1, 1, 0, 0, 0, 0], 0, [1, 1, 0, 0, 0, 0, 0])));
  badReply(() => c.decodeReadonlyBackupOverviewReply(overview(undefined, 0)));
  badReply(() => c.decodeReadonlyBackupOverviewReply(overview(undefined, 2)));
  badReply(() => c.decodeReadonlyBackupOverviewReply(overview(undefined, 1, [1, 1, 1, 0, 0, 0, 2])));
  badReply(() => c.decodeReadonlyBackupOverviewReply(overview(undefined, 1, undefined, [conversation(2, 1, bytes(16))])));
});

test('content pages retain original ordinal slot identities omission reasons and independent buffer ownership', () => {
  const raw = page(), value = c.decodeReadonlyBackupPageReply(raw);
  assert.equal(value.kind, 'content'); assert.equal(value.value.kind, 'group');
  const r = value.value.entries[0]; assert.equal(r.ordinal, 255); assert.equal(r.messageId.length, 0); assert.equal(r.text, 'hé');
  assert.deepEqual(r.attachments.map(x => [x.kind, x.slot]), [['included', 0], ['omitted', 1]]);
  assert.equal(r.attachments[0].filename, 'résumé.txt'); assert.equal(r.attachments[1].reason, 'unsupported');
  raw.fill(0); assert.deepEqual(value.value.backupId, id); assert.deepEqual(r.attachments[0].token, token);
  const emptyName = c.decodeReadonlyBackupPageReply(page([row({ text: bytes(0), slots: [included(0, bytes(0))] })]));
  assert.equal(emptyName.value.entries[0].attachments[0].filename, '');
  for (const slots of [[included(1)], [included(), omitted(0)], [omitted(0, 0)], [omitted(0, 5)], Array.from({ length: 11 }, (_, i) => included(i)), [included(0, bytes(256, 97))], [included(0, bytes(0), bytes(0))], [included(0, utf8('f'), bytes(128, 97))], [included(0, utf8('f'), utf8('t'), 0)], [included(0, bytes(1, 255))]]) badReply(() => c.decodeReadonlyBackupPageReply(page([row({ slots })])));
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ text: bytes(0) })])));
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ messageId: bytes(16) })])));
});

test('content pages enforce complete UTF8 framing budgets and progressing cursors', () => {
  const descriptors = Array.from({ length: 10 }, (_, i) => included(i, utf8('é'.repeat(127) + 'x'), utf8('m'.repeat(127)), 1));
  const maximum = page([row({ ordinal: 1, text: bytes(65346, 97), slots: descriptors })], concat([1], uint(1, 4)));
  assert.equal(c.decodeReadonlyBackupPageReply(maximum).value.nextOffset, 1);
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ ordinal: 1, text: bytes(65346, 97), slots: descriptors }), row({ ordinal: 2, text: bytes(65346, 97), slots: descriptors })])));
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ ordinal: 1, text: bytes(65346, 97) }), row({ ordinal: 2, text: bytes(65346, 97) }), row({ ordinal: 3, text: bytes(381, 97) })])));
  for (const next of [concat([1], uint(0, 4)), concat([1], uint(2, 4)), [2]]) badReply(() => c.decodeReadonlyBackupPageReply(page(undefined, next)));
  badReply(() => c.decodeReadonlyBackupPageReply(page([], concat([1], uint(1, 4)))));
  assert.equal(c.decodeReadonlyBackupPageReply(page([], [0], 256)).value.entries.length, 0);
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ ordinal: 1 }), row({ ordinal: 1 })])));
  badReply(() => c.decodeReadonlyBackupPageReply(page([row({ text: bytes(1, 255) })])));
});

test('content chunks require exact nonempty final lengths and retain every echo selector independently', () => {
  const raw = chunk(), decoded = c.decodeReadonlyBackupPageReply(raw); assert.equal(decoded.kind, 'chunk');
  assert.equal(decoded.value.ordinal, 255); assert.equal(decoded.value.slot, 0); assert.equal(decoded.value.chunk, 1); assert.equal(decoded.value.totalSize, 65537);
  raw.fill(0); assert.deepEqual(decoded.value.bytes, bytes(1, 42)); assert.deepEqual(decoded.value.token, token); assert.deepEqual(decoded.value.scopeId, scope);
  assert.equal(c.decodeReadonlyBackupPageReply(chunk(bytes(65536), 0)).value.bytes.length, 65536);
  assert.equal(c.decodeReadonlyBackupPageReply(chunk(bytes(65536), 255, 16777216)).value.bytes.length, 65536);
  for (const frame of [chunk(bytes(0)), chunk(bytes(2)), chunk(bytes(65535), 0), chunk(bytes(1), 2), chunk(bytes(1), 0, 0), chunk(bytes(1), 0, 16777217), chunk(bytes(1), 1, 65537, 2, bytes(16)), chunk(bytes(1), 1, 65537, 2, scope, 256), chunk(bytes(1), 1, 65537, 2, scope, 1, 10), chunk(bytes(1), 1, 65537, 2, scope, 1, 0, bytes(31))]) badReply(() => c.decodeReadonlyBackupPageReply(frame));
});

test('content decoders reject unknown schema tags hostile lengths truncation and trailing data', () => {
  for (const [decode, valid] of [[c.decodeReadonlyBackupOverviewReply, overview()], [c.decodeReadonlyBackupPageReply, page()], [c.decodeReadonlyBackupPageReply, chunk()]]) {
    assert.ok(decode(valid));
    badReply(() => decode(concat(valid, [0]))); badReply(() => decode(valid.slice(0, -1)));
    const version = valid.slice(); version[0] = 3; badReply(() => decode(version));
    badReply(() => decode(bytes(0))); badReply(() => decode(concat([2, 0], bytes(4, 255))));
  }
  const unknown = page(); unknown[1] = 2; badReply(() => c.decodeReadonlyBackupPageReply(unknown));
});

test('readonly wrappers preserve exact original text decoder behavior and ownership', () => {
  const oldOverview = concat([1], list(id, uint(4, 8), ...[1, 1, 0, 0, 0, 0, 0].map(n => uint(n, 4)), list(conversation())));
  const oldPage = concat([1], list(id, [2], scope, uint(0, 4), [0], list(list(uint(255, 2), [2], bytes(0), bytes(32, 4), bytes(16, 5), uint(9, 8), [0], utf8('old')))));
  assert.deepEqual(c.decodeReadonlyBackupOverviewReply(oldOverview), { kind: 'text', value: c.decodeBackupOverviewReply(oldOverview) });
  assert.deepEqual(c.decodeReadonlyBackupPageReply(oldPage), { kind: 'text', value: c.decodeBackupPageReply(oldPage) });
  badReply(() => c.decodeBackupOverviewReply(overview())); badReply(() => c.decodeBackupPageReply(page()));
});
