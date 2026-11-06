import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loaded, bytes, utf8, concat, uint, vector, action, common, equalBytes, badRequest, createReply, draftId, originalWire, code } from '../scripts/backup-native-test-fixture.mjs';

const selections = () => [
  { scope: { kind: 'direct', id: bytes(16, 4) }, fromTime: null, throughTime: '9' },
  { scope: { kind: 'group', id: bytes(32, 5) }, fromTime: '10', throughTime: null },
];
const expected = tag => concat([tag], common.subarray(1), vector(concat([2],
  [1], vector(bytes(16, 4)), [0, 1], uint(9, 8),
  [2], vector(bytes(32, 5)), [1], uint(10, 8), [0])));
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const transportCleared = calls => {
  for (const call of calls) {
    assert.ok(call.request.every(value => value === 0));
    if (call.response) assert.ok(call.response.every(value => value === 0));
  }
};

test('content creation policies use distinct canonical tags while old text creation stays byte exact', async () => {
  const { c } = await loaded();
  const selected = selections();
  equalBytes(c.encodeBackupContentCreateRequest(action, { selections: selected, policy: 'require' }), expected(2));
  equalBytes(c.encodeBackupContentCreateRequest(action, { selections: selected, policy: 'allowOmissions' }), expected(3));
  equalBytes(c.encodeBackupRequest(action, { kind: 'create', selections: selected }), expected(1));
  equalBytes(selected[0].scope.id, bytes(16, 4)); equalBytes(selected[1].scope.id, bytes(32, 5));
  equalBytes(action.expectedProfile, bytes(3, 3));
});

test('content creation retains the exact 42004 byte maximum and owns its encoded selectors', async () => {
  const { c } = await loaded();
  const owner = { databasePath: 'a'.repeat(4096), expectedProfile: Buffer.from(bytes(36134, 7)) };
  const selected = Array.from({ length: 32 }, (_, index) => ({ scope: { kind: 'group', id: Buffer.from(bytes(32, index + 1)) },
    fromTime: '18446744073709551615', throughTime: '18446744073709551615' }));
  const legacy = c.encodeBackupRequest(owner, { kind: 'create', selections: selected });
  const encoded = c.encodeBackupContentCreateRequest(owner, { selections: selected, policy: 'require' });
  assert.equal(encoded.length, 42004); assert.equal(encoded[0], 2);
  equalBytes(encoded.subarray(1), legacy.subarray(1));
  const held = Buffer.from(encoded);
  owner.expectedProfile.fill(99); selected.forEach(value => value.scope.id.fill(99));
  equalBytes(encoded, held);
  badRequest(() => c.encodeBackupContentCreateRequest({ ...owner, databasePath: 'a'.repeat(4097) }, { selections: selected, policy: 'require' }));
});

test('content creation rejects unknown policies and every malformed selection before encoding', async () => {
  const { c } = await loaded();
  for (const policy of [null, undefined, '', 'text', 'allow', 0, 1, 2, 3]) {
    badRequest(() => c.encodeBackupContentCreateRequest(action, { selections: selections(), policy }));
  }
  for (const selected of [[], Array(33).fill(selections()[0]), [selections()[0], selections()[0]],
    [{ ...selections()[0], scope: { kind: 'direct', id: bytes(32) } }],
    [{ ...selections()[0], scope: { kind: 'unknown', id: bytes(16) } }],
    [{ ...selections()[0], fromTime: '10', throughTime: '9' }],
    [{ ...selections()[0], fromTime: '18446744073709551616' }]]) {
    badRequest(() => c.encodeBackupContentCreateRequest(action, { selections: selected, policy: 'require' }));
  }
  badRequest(() => c.encodeBackupContentCreateRequest({ ...action, databasePath: '\ud800' }, { selections: selections(), policy: 'require' }));
});

test('content creation uses the existing scoped native symbol and unchanged pending recovery reply', async () => {
  const { fixture } = await loaded(); const f = fixture(() => createReply());
  for (const [policy, tag] of [['require', 2], ['allowOmissions', 3]]) {
    const created = await f.services.createContentBackup({ action, selections: selections(), policy });
    equalBytes(created.draftId, draftId); equalBytes(created.wire, originalWire); assert.equal(created.recoveryCode, code);
    assert.equal(f.calls.at(-1).symbol, 'mesh_messenger_backup_create'); equalBytes(f.calls.at(-1).encoded, expected(tag));
    transportCleared(f.calls);
  }
  const text = await f.services.createBackup({ action, selections: selections() });
  equalBytes(f.calls.at(-1).encoded, expected(1)); equalBytes(text.wire, originalWire);
  transportCleared(f.calls);
});

test('content creation captures policy owner and all selection fields before native await', async () => {
  const { fixture } = await loaded(); const pending = deferred(); const f = fixture(() => pending.promise);
  const request = { action: { ...action, expectedProfile: Buffer.from(action.expectedProfile) }, selections: selections(), policy: 'require' };
  const creating = f.services.createContentBackup(request); void creating.catch(() => {});
  assert.equal(f.calls.length, 1); equalBytes(f.calls[0].encoded, expected(2));
  request.policy = 'allowOmissions'; request.action.databasePath = '/changed'; request.action.expectedProfile.fill(99);
  request.selections[0].scope.id.fill(99); request.selections[0].scope.kind = 'group'; request.selections[0].throughTime = '10';
  request.selections.length = 0;
  equalBytes(f.calls[0].request, expected(2));
  pending.resolve(createReply()); const created = await creating;
  equalBytes(created.wire, originalWire); equalBytes(created.draftId, draftId); transportCleared(f.calls);
});

test('content creation refuses retired epochs and clears late or post-decode recovery bytes', async () => {
  {
    const { fixture } = await loaded(); const f = fixture(() => createReply()); f.scope.dispose();
    await assert.rejects(f.services.createContentBackup({ action, selections: selections(), policy: 'require' }), /stale_epoch/);
    assert.equal(f.calls.length, 0);
  }
  {
    const { fixture, ownedCopies } = await loaded({ track: true }); const pending = deferred(); const f = fixture(() => pending.promise);
    const creating = f.services.createContentBackup({ action, selections: selections(), policy: 'allowOmissions' }); void creating.catch(() => {});
    assert.equal(f.calls.length, 1); f.scope.dispose(); const late = createReply(); pending.resolve(late);
    await assert.rejects(creating, /stale_epoch/);
    assert.ok(late.every(value => value === 0)); assert.ok(ownedCopies.every(value => value.every(byte => byte === 0))); transportCleared(f.calls);
  }
  {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => createReply());
    f.setCheck(() => { if (ownedCopies.some(value => value.length === originalWire.length)) f.scope.dispose(); });
    await assert.rejects(f.services.createContentBackup({ action, selections: selections(), policy: 'require' }), /stale_epoch/);
    assert.ok(ownedCopies.some(value => value.length === originalWire.length));
    assert.ok(ownedCopies.every(value => value.every(byte => byte === 0))); transportCleared(f.calls);
  }
});

test('content creation preserves native refusal and malformed reply cleanup without dispatching invalid policy', async () => {
  {
    const { fixture } = await loaded(); const f = fixture(() => { throw Error('backup_operation_refused'); });
    await assert.rejects(f.services.createContentBackup({ action, selections: selections(), policy: 'require' }), { message: 'backup_operation_refused' });
    assert.equal(f.calls.length, 1); transportCleared(f.calls);
  }
  for (const wire of [concat(createReply(), [0]), concat([1], vector(originalWire), vector(utf8(code)))]) {
    const { fixture, ownedCopies } = await loaded({ track: true }); const f = fixture(() => wire);
    await assert.rejects(f.services.createContentBackup({ action, selections: selections(), policy: 'allowOmissions' }), { message: 'invalid_backup_native_reply' });
    assert.ok(ownedCopies.every(value => value.every(byte => byte === 0))); transportCleared(f.calls);
  }
  const { fixture } = await loaded(); const f = fixture(() => createReply());
  await assert.rejects(f.services.createContentBackup({ action, selections: selections(), policy: 'allow' }), { message: 'invalid_backup_native_request' });
  assert.equal(f.calls.length, 0);
});
