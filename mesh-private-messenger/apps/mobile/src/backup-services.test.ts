import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loaded } from '../scripts/backup-native-test-fixture.mjs';
const { implementation, session } = await loaded();
const { createBackupServices } = implementation.namespace;
const concat = (...values) => Uint8Array.from(Buffer.concat(values.map(value => Uint8Array.from(value))));
const utf8 = value => new TextEncoder().encode(value);
const u32 = value => { const result = new Uint8Array(4); new DataView(result.buffer).setUint32(0, value); return result; };
const vector = value => concat(u32(value.length), value);
const list = (...values) => concat(vector(u32(values.length)), ...values.map(vector));
const id = new Uint8Array(32).fill(0x11), scopeId = new Uint8Array(32).fill(0x22);
const maximumTime = new Uint8Array(8).fill(0xff);
const action = { databasePath: '/synthetic/backup.db', expectedProfile: new Uint8Array([1, 2, 3]) };
const selection = { scope: { kind: 'group', id: scopeId }, fromTime: null, throughTime: null };
const createReply = concat([2], id, vector(Uint8Array.of(9, 8, 7)), vector(utf8('SYNTHETIC-RECOVERY')));
const listReply = concat([1], list(list(id, maximumTime)));
const overviewReply = (backupId = id) => concat([1], list(backupId, maximumTime,
  u32(1), u32(1), u32(0), u32(0), u32(0), u32(0), u32(0),
  list(list(Uint8Array.of(2), scopeId, new Uint8Array(), utf8('Historical group'), u32(1)))));
const record = list(Uint8Array.of(0, 23), Uint8Array.of(2), new Uint8Array(32).fill(3),
  new Uint8Array(32).fill(4), new Uint8Array(16).fill(5), maximumTime, Uint8Array.of(0), utf8('hello'));
const pageReply = (offset = 0, selectedScope = scopeId) => concat([1], list(id, Uint8Array.of(2), selectedScope,
  u32(offset), Uint8Array.of(0), list(record)));
const replies = {
  mesh_messenger_backup_create: createReply,
  mesh_messenger_backup_preview: overviewReply(),
  mesh_messenger_backup_import: concat([1], id, [1]),
  mesh_messenger_backup_list: listReply,
  mesh_messenger_backup_remove: concat([1], id, [1]),
  mesh_messenger_backup_overview: overviewReply(),
  mesh_messenger_backup_page: pageReply(),
};
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
function fixture(reply) {
  let active = true;
  const calls = [];
  const scope = session.namespace.createAppLockSession({
    checkAppLockScope() { if (!active) throw new Error('stale_epoch'); },
    async invokeScoped(symbol, request, epoch) {
      const call = { symbol, request, encoded: request.slice(), epoch };
      calls.push(call);
      const bytes = reply ? await reply(symbol) : replies[symbol].slice();
      call.response = bytes;
      return bytes;
    },
  }, '00000000-0000-4000-8000-000000000001');
  return { services: createBackupServices(scope), scope, calls, revoke() { active = false; } };
}
const pageArgs = () => ({ action, backupId: id, scope: { kind: 'group', id: scopeId }, offset: 0, limit: 1 });

test('seven operations use the captured native session and clear transport copies while preserving decoded results', async () => {
  const f = fixture(), wire = Uint8Array.of(7, 8, 9);
  const created = await f.services.createBackup({ action, selections: [selection] });
  const preview = (await f.services.previewBackup({ action, wire, recoveryCode: 'CODE' })).value;
  const imported = await f.services.importBackup({ action, wire, recoveryCode: 'CODE', confirmedId: id });
  const inventory = await f.services.listBackups({ action });
  const removed = await f.services.removeBackup({ action, backupId: id });
  const overview = (await f.services.backupOverview({ action, backupId: id })).value;
  const page = (await f.services.backupPage(pageArgs())).value;
  assert.deepEqual(f.calls.map(c => c.symbol), Object.keys(replies));
  assert.deepEqual([...created.wire], [9, 8, 7]); assert.equal(created.recoveryCode, 'SYNTHETIC-RECOVERY');
  assert.equal(preview.createdAt, '18446744073709551615');
  assert.equal(inventory[0].createdAt, '18446744073709551615');
  assert.equal(overview.conversations[0].name, 'Historical group');
  assert.equal(page.entries[0].timestamp, '18446744073709551615'); assert.equal(page.entries[0].text, 'hello');
  assert.equal(imported.disposition, 1); assert.deepEqual(removed.backupId, id);
  assert.deepEqual([...wire], [7, 8, 9]); assert.deepEqual([...action.expectedProfile], [1, 2, 3]);
  for (const call of f.calls) {
    assert.equal(call.encoded[0], 1); assert.ok(call.request.every(byte => byte === 0));
    assert.ok(call.response.every(byte => byte === 0));
  }
});

test('mismatched receipt archive or page context refuses and clears the response', async () => {
  const other = new Uint8Array(32).fill(0x55);
  const cases = [
    [concat([1], other, [1]), s => s.importBackup({ action, wire: Uint8Array.of(1), recoveryCode: 'CODE', confirmedId: id })],
    [concat([1], other, [1]), s => s.removeBackup({ action, backupId: id })],
    [overviewReply(other), s => s.backupOverview({ action, backupId: id })],
    [pageReply(1), s => s.backupPage(pageArgs())],
    [pageReply(0, other), s => s.backupPage(pageArgs())],
  ];
  for (const [reply, call] of cases) {
    const f = fixture(() => reply.slice());
    await assert.rejects(call(f.services), /^Error: invalid_backup_native_reply$/);
    assert.ok(f.calls[0].response.every(byte => byte === 0));
    assert.ok(f.calls[0].request.every(byte => byte === 0));
  }
});

test('mutating caller IDs during a native call does not retarget its receipt validation', async () => {
  const pending = deferred(), f = fixture(() => pending.promise);
  const confirmedId = id.slice();
  const importing = f.services.importBackup({ action, wire: Uint8Array.of(1), recoveryCode: 'CODE', confirmedId });
  void importing.catch(() => {});
  assert.equal(f.calls.length, 1);
  confirmedId.fill(0x66);
  pending.resolve(concat([1], id, [2]));
  const result = await importing;
  assert.equal(result.disposition, 2); assert.deepEqual(result.backupId, id);
});

test('native revocation clears a late response and a disposed session cannot start another operation', async () => {
  const pending = deferred(), f = fixture(() => pending.promise);
  const loading = f.services.listBackups({ action });
  void loading.catch(() => {});
  assert.equal(f.calls.length, 1);
  f.revoke(); const late = listReply.slice(); pending.resolve(late);
  await assert.rejects(loading, /stale_epoch/);
  assert.ok(late.every(byte => byte === 0)); assert.ok(f.calls[0].request.every(byte => byte === 0));
  f.scope.dispose();
  await assert.rejects(f.services.createBackup({ action, selections: [selection] }), /stale_epoch/);
  assert.equal(f.calls.length, 1);
});

test('native refusal and invalid framing both clear requests without returning partial data', async () => {
  const native = fixture(() => { throw new Error('backup_operation_refused'); });
  await assert.rejects(native.services.listBackups({ action }), /^Error: backup_operation_refused$/);
  assert.equal(native.calls.length, 1); assert.ok(native.calls[0].request.every(byte => byte === 0));
  const corrupt = fixture(() => concat(listReply, [0]));
  await assert.rejects(corrupt.services.listBackups({ action }), /^Error: invalid_backup_native_reply$/);
  assert.ok(corrupt.calls[0].request.every(byte => byte === 0));
  assert.ok(corrupt.calls[0].response.every(byte => byte === 0));
});

test('Buffer-backed archive and scope IDs are captured independently before asynchronous native work', async () => {
  for (const kind of ['import', 'remove', 'overview', 'page']) {
    const pending = deferred(), f = fixture(() => pending.promise);
    const mutableId = Buffer.from(id), mutableScope = Buffer.from(scopeId);
    const loading = kind === 'import'
      ? f.services.importBackup({ action, wire: Uint8Array.of(1), recoveryCode: 'CODE', confirmedId: mutableId })
      : kind === 'remove' ? f.services.removeBackup({ action, backupId: mutableId })
      : kind === 'overview' ? f.services.backupOverview({ action, backupId: mutableId })
      : f.services.backupPage({ ...pageArgs(), backupId: mutableId, scope: { kind: 'group', id: mutableScope } });
    void loading.catch(() => {});
    assert.equal(f.calls.length, 1);
    mutableId.fill(0x77); mutableScope.fill(0x88);
    pending.resolve(replies[`mesh_messenger_backup_${kind}`].slice());
    const result = await loading;
    const decoded = kind === 'overview' || kind === 'page' ? result.value : result;
    assert.deepEqual(decoded.backupId, id);
    if (kind === 'page') assert.deepEqual(decoded.scopeId, scopeId);
  }
});

{
const { loaded, bytes, draftId, otherId, utf8, concat, uint, vector, list, action, common, code, maximumWire, originalWire, createReply, stateReply, resumeReply, discardReply, equalBytes, badRequest, badReply } = await import('../scripts/backup-native-test-fixture.mjs');
test('pending services use exact scoped symbols, clear code transport and collapse cleanup statuses', async () => {
  const { fixture } = await loaded();
  const replies = { pending_state:stateReply(),pending_resume:resumeReply(),pending_discard:discardReply(),pending_repair:Uint8Array.of(1,2) };
  const f = fixture(symbol => replies[symbol.replace('mesh_messenger_backup_','')]);
  const state = await f.services.pendingBackupExport({action}); assert.equal(state.createdAt,'18446744073709551615');
  const wire = await f.services.resumeBackupExport({action,draftId,recoveryCode:code}); equalBytes(wire,originalWire);
  assert.equal(await f.services.discardBackupExport({action,draftId}),undefined);
  assert.equal(await f.services.repairBackupExport({action}),undefined);
  assert.deepEqual(f.calls.map(call=>call.symbol), Object.keys(replies).map(kind=>'mesh_messenger_backup_'+kind));
  for (const call of f.calls) { assert.ok(call.request.every(byte=>byte===0));assert.ok(call.response.every(byte=>byte===0)); }
  equalBytes(f.calls[1].encoded,concat(common,draftId,vector(utf8(code)))); equalBytes(wire,originalWire);
});

test('caller Buffer mutation cannot retarget exact draft cleanup and mismatches wipe all owned outputs', async () => {
  const { fixture, ownedCopies } = await loaded({ track: true }); const caller = Buffer.from(draftId);
  const f = fixture((_symbol,call)=>{ caller.fill(0);return discardReply(); });
  assert.equal(await f.services.discardBackupExport({action,draftId:caller}),undefined);
  assert.ok(ownedCopies.filter(value=>value.length===32).every(value=>value.every(byte=>byte===0)));
  const bad = fixture(()=>discardReply(otherId));
  await assert.rejects(bad.services.discardBackupExport({action,draftId}),/invalid_backup_native_reply/);
  assert.ok(ownedCopies.every(value=>value.every(byte=>byte===0)));
});

test('post-decode reentrant disposal wipes all owned metadata before rejecting', async () => {
  const { fixture, ownedCopies } = await loaded({ track: true });
  const f = fixture(()=>concat([1],list(list(draftId,uint(7,8)))));
  f.setCheck(()=>{ if(ownedCopies.some(value=>value.length===32)) f.scope.dispose(); });
  await assert.rejects(f.services.listBackups({action}),/stale_epoch/);
  assert.ok(ownedCopies.some(value=>value.length===32));
  assert.ok(ownedCopies.every(value=>value.every(byte=>byte===0)),'No decoded ID or captured profile survives a refused completion');
  assert.ok(f.calls[0].request.every(byte=>byte===0));assert.ok(f.calls[0].response.every(byte=>byte===0));
});

test('an existing mismatched receipt wipes captured and decoded IDs without wiping caller input', async () => {
  const { fixture, ownedCopies } = await loaded({ track: true }); const caller = Buffer.from(draftId);
  const f = fixture(()=>concat([1],otherId,[1]));
  await assert.rejects(f.services.removeBackup({action,backupId:caller}),/invalid_backup_native_reply/);
  equalBytes(caller,draftId);
  assert.ok(ownedCopies.length>=2);assert.ok(ownedCopies.every(value=>value.every(byte=>byte===0)));
});

test('reentrant revocation after resume decoding clears wire, captured identity and entered-code transport', async () => {
  const { fixture, ownedCopies } = await loaded({ track: true });
  const callerId = Buffer.from(draftId), callerProfile = Buffer.from(action.expectedProfile);
  const f = fixture(()=>resumeReply());
  f.setCheck(()=>{ if(ownedCopies.some(value=>value.length===originalWire.length)) f.scope.dispose(); });
  await assert.rejects(f.services.resumeBackupExport({ action:{...action,expectedProfile:callerProfile},draftId:callerId,recoveryCode:code }),/stale_epoch/);
  assert.ok(ownedCopies.some(value=>value.length===originalWire.length));
  assert.ok(ownedCopies.every(value=>value.every(byte=>byte===0)));
  equalBytes(callerId,draftId);equalBytes(callerProfile,action.expectedProfile);
  equalBytes(f.calls[0].encoded,concat(common,draftId,vector(utf8(code))));
  assert.ok(f.calls[0].request.every(byte=>byte===0));assert.ok(f.calls[0].response.every(byte=>byte===0));
});

}
