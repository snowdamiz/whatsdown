import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loaded, bytes, utf8, concat, uint, vector, list, action, common, equalBytes } from '../scripts/backup-native-test-fixture.mjs';
const id = bytes(32, 9), scopeId = bytes(32, 3), token = bytes(32, 7);
const scope = { kind: 'group', id: scopeId };
const overview = () => concat([2], list(id, uint(9, 8), ...[1, 1, 0, 0, 0, 0, 1].map(n => uint(n, 4)), [1],
  list(...[2, 1, 0, 0, 1, 0].map(n => uint(n, 4))), list(list([2], scopeId, [], utf8('Archive'), uint(1, 4)))));
const page = () => concat([2, 0], list(id, [2], scopeId, uint(0, 4), [0], list(list(uint(23, 2), [2], [], bytes(32, 4), bytes(16, 5), uint(9, 8), utf8('hello'),
  list(list([0], [0], utf8('file.txt'), utf8('text/plain'), uint(65537, 4), token), list([1], [3]))))));
const chunk = (change = {}) => {
  const v = { backupId: id, kind: 2, scopeId, ordinal: 23, slot: 0, chunk: 1, totalSize: 65537, token, data: bytes(1, 42), ...change };
  return concat([2, 1], list(v.backupId, [v.kind], v.scopeId, uint(v.ordinal, 2), [v.slot], [v.chunk], uint(v.totalSize, 4), v.token, v.data));
};
const args = () => ({ action, backupId: id, scope, ordinal: 23, slot: 0, chunk: 1, totalSize: 65537, token });
const pageArgs = () => ({ action, backupId: id, scope, offset: 0, limit: 1 });
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const transportCleared = calls => { for (const call of calls) { assert.ok(call.request.every(n => n === 0)); if (call.response) assert.ok(call.response.every(n => n === 0)); } };

test('content services return closed overview and message variants through existing scoped native symbols', async () => {
  const { fixture } = await loaded();
  const f = fixture(symbol => symbol.endsWith('_page') ? page() : overview());
  const preview = await f.services.previewBackup({ action, wire: bytes(1), recoveryCode: 'SYNTHETIC' });
  const opened = await f.services.backupOverview({ action, backupId: id });
  const messages = await f.services.backupPage(pageArgs());
  assert.equal(preview.kind, 'content'); assert.equal(opened.kind, 'content'); assert.equal(messages.kind, 'content');
  assert.equal(opened.value.files.included, 1); assert.equal(messages.value.entries[0].attachments[1].reason, 'unsupported');
  equalBytes(messages.value.entries[0].attachments[0].token, token);
  assert.deepEqual(f.calls.map(c => c.symbol), ['mesh_messenger_backup_preview', 'mesh_messenger_backup_overview', 'mesh_messenger_backup_page']);
  transportCleared(f.calls);
});

test('attachment chunk service captures all selectors before await and keeps returned data independent', async () => {
  const { fixture } = await loaded(); const pending = deferred(); const f = fixture(() => pending.promise);
  const chosen = { ...args(), backupId: Buffer.from(id), scope: { kind: 'group', id: Buffer.from(scopeId) }, token: Buffer.from(token) };
  const loading = f.services.backupAttachmentChunk(chosen); void loading.catch(() => {});
  assert.equal(f.calls.length, 1);
  chosen.backupId.fill(55); chosen.scope.id.fill(55); chosen.token.fill(55);
  chosen.ordinal = 0; chosen.slot = 9; chosen.chunk = 0; chosen.totalSize = 1; chosen.scope.kind = 'direct';
  pending.resolve(chunk()); const result = await loading;
  assert.equal(f.calls[0].symbol, 'mesh_messenger_backup_page');
  equalBytes(f.calls[0].encoded, concat(common, id, [4], vector(token), [23, 0, 1]));
  equalBytes(result.bytes, bytes(1, 42)); equalBytes(result.token, token); equalBytes(result.scopeId, scopeId);
  assert.equal(result.totalSize, 65537); transportCleared(f.calls);
});

test('attachment chunk service refuses every mismatched echo and wipes captured and decoded buffers', async () => {
  const variants = [
    { backupId: bytes(32, 88) }, { kind: 1, scopeId: bytes(16, 3) }, { scopeId: bytes(32, 88) },
    { ordinal: 24 }, { slot: 1 }, { chunk: 0, data: bytes(65536, 42) },
    { totalSize: 65538, data: bytes(2, 42) }, { token: bytes(32, 88) },
  ];
  for (const altered of variants) {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => chunk(altered));
    await assert.rejects(f.services.backupAttachmentChunk(args()), { message: 'invalid_backup_native_reply' });
    assert.ok(ownedCopies.length > 3); assert.ok(ownedCopies.every(value => value.every(n => n === 0)));
    transportCleared(f.calls);
  }
  equalBytes(id, bytes(32, 9)); equalBytes(scopeId, bytes(32, 3)); equalBytes(token, bytes(32, 7));
});

test('message and chunk services refuse the other reply variant and malformed frames', async () => {
  for (const [reply, read] of [
    [chunk(), s => s.backupPage(pageArgs())], [page(), s => s.backupAttachmentChunk(args())],
    [concat(chunk(), [0]), s => s.backupAttachmentChunk(args())],
  ]) {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => reply.slice());
    await assert.rejects(read(f.services), { message: 'invalid_backup_native_reply' });
    assert.ok(ownedCopies.every(value => value.every(n => n === 0))); transportCleared(f.calls);
  }
});

test('attachment chunk service refuses retired epochs before dispatch and clears late or post-decode results', async () => {
  {
    const { fixture } = await loaded(); const f = fixture(() => chunk()); f.scope.dispose();
    await assert.rejects(f.services.backupAttachmentChunk(args()), /stale_epoch/); assert.equal(f.calls.length, 0);
  }
  {
    const { fixture, ownedCopies } = await loaded({ track: true }); const pending = deferred(); const f = fixture(() => pending.promise);
    const loading = f.services.backupAttachmentChunk(args()); void loading.catch(() => {});
    assert.equal(f.calls.length, 1); f.scope.dispose(); const late = chunk(); pending.resolve(late);
    await assert.rejects(loading, /stale_epoch/); assert.ok(late.every(n => n === 0));
    assert.ok(ownedCopies.every(value => value.every(n => n === 0))); transportCleared(f.calls);
  }
  {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => chunk());
    f.setCheck(() => { if (ownedCopies.some(v => v.length === 1 && v[0] === 42)) f.scope.dispose(); });
    await assert.rejects(f.services.backupAttachmentChunk(args()), /stale_epoch/);
    assert.ok(ownedCopies.some(v => v.length === 1)); assert.ok(ownedCopies.every(value => value.every(n => n === 0)));
    transportCleared(f.calls);
  }
});

test('attachment chunk service validates full selection before dispatch and preserves native refusal cleanup', async () => {
  const invalid = [
    { totalSize: 0 }, { totalSize: 16777217 }, { totalSize: 65536 }, { totalSize: 65537.5 },
    { scope: { kind: 'group', id: bytes(16) } }, { scope: { kind: 'direct', id: bytes(32) } },
    { chunk: -1 }, { chunk: 256 }, { ordinal: 256 }, { slot: 10 }, { token: bytes(31) }, { backupId: bytes(31) },
  ];
  for (const change of invalid) {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => chunk());
    await assert.rejects(f.services.backupAttachmentChunk({ ...args(), ...change }), { message: 'invalid_backup_native_request' });
    assert.equal(f.calls.length, 0); assert.ok(ownedCopies.every(value => value.every(n => n === 0)));
  }
  const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => { throw Error('backup_operation_refused'); });
  await assert.rejects(f.services.backupAttachmentChunk(args()), { message: 'backup_operation_refused' });
  assert.equal(f.calls.length, 1); assert.ok(ownedCopies.every(value => value.every(n => n === 0))); transportCleared(f.calls);
});
