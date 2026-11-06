import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startBackupExport } from '../src/backup-export.ts';
import { createAppLockSession } from '../src/app-lock.ts';
import './scoped-test-fixture.mjs';

const { createBackupFileServices } = await import('../src/backup-file-io.ts');

const epoch = '00000000-0000-4000-8000-000000000001';
const makeId = n => new Uint8Array(32).fill(n);
const deferred = () => Promise.withResolvers();
function fixture({ complete, finish, kind = 'create' } = {}) {
  const calls = [], chunks = [], expectedId = makeId(7), wire = Uint8Array.of(3, 4, 5);
  const material = { draftId: makeId(7), wire, recoveryCode: 'SAVED-ONE-TIME-CODE' };
  const scope = createAppLockSession({ checkAppLockScope() {} }, epoch);
  const sink = {
    async write(offset, bytes) { calls.push('write'); assert.equal(offset, 0); chunks.push(new Uint8Array(bytes)); },
    async finish() { calls.push('finish'); if (finish) await finish(); },
    async abort() { calls.push('abort'); },
  };
  const common = { scope,
    async prepareDestination() { calls.push('prepare'); return true; },
    async chooseDestination(size) { calls.push('choose'); assert.equal(size, 3); return sink; },
    async complete(draftId) { calls.push('complete'); assert.deepEqual(draftId, expectedId); if (complete) await complete(draftId); },
  };
  const ports = kind === 'create' ? { ...common, kind,
    async create() { calls.push('create'); return material; },
  } : { ...common, kind, draftId: makeId(7),
    async resume(draftId, recoveryCode) {
      calls.push('resume'); assert.deepEqual(draftId, expectedId); assert.equal(recoveryCode, 'SAVED-ONE-TIME-CODE'); return wire;
    },
    async create() { calls.push('forbidden-create'); throw Error('resume-must-never-create'); },
  };
  const operation = kind === 'resume' ? startBackupExport(ports, 'SAVED-ONE-TIME-CODE') : startBackupExport(ports);
  return { scope, operation, material, calls, chunks, expectedId, ports, wire };
}

test('fresh create removes only its original draft ID after native publication finishes', async () => {
  const f = fixture();
  try {
    await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
    f.material.draftId.fill(9);
    assert.equal(await f.operation.save(), 'saved');
    assert.deepEqual(f.calls, ['prepare', 'create', 'choose', 'write', 'finish', 'complete']);
    assert.deepEqual(f.chunks, [Uint8Array.of(3, 4, 5)]); assert.ok(f.wire.every(byte => byte === 0));
  } finally { f.operation.discard(); f.scope.dispose(); }
});

test('fresh-scope resume preflights a destination before authenticating saved code and writes the same ciphertext without create or code echo', async () => {
  const f = fixture({ kind: 'resume' });
  try {
    assert.equal(await f.operation.ready, 'ready');
    assert.throws(() => f.operation.recoveryCode(), /backup_export_no_recovery_code/);
    await assert.rejects(f.operation.copyRecoveryCode(), /backup_export_no_recovery_code/);
    assert.equal(await f.operation.save(), 'saved');
    assert.deepEqual(f.calls, ['prepare', 'resume', 'choose', 'write', 'finish', 'complete']);
    assert.deepEqual(f.chunks, [Uint8Array.of(3, 4, 5)]); assert.ok(f.wire.every(byte => byte === 0));
  } finally { f.operation.discard(); f.scope.dispose(); }
});

test('failure to remove an already published draft is terminal savedPending and cannot publish twice', async () => {
  const f = fixture({ complete: async () => { throw Error('private-native-storage-detail'); } });
  try {
    await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
    assert.equal(await f.operation.save(), 'savedPending');
    await assert.rejects(f.operation.save(), /backup_export_expired/);
    assert.equal(f.calls.filter(value => value === 'finish').length, 1);
    assert.equal(f.calls.filter(value => value === 'complete').length, 1);
    assert.equal(f.calls.filter(value => value === 'abort').length, 0);
    assert.ok(f.wire.every(byte => byte === 0)); assert.equal(f.material.recoveryCode, '');
  } finally { f.operation.discard(); f.scope.dispose(); }
});

test('a finish returning after scope loss keeps the encrypted draft and never removes a successor', async () => {
  const finished = deferred(), entered = deferred();
  const f = fixture({ finish: async () => { entered.resolve(); await finished.promise; } });
  try {
    await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
    const saving = f.operation.save(); await entered.promise;
    f.scope.dispose(); finished.resolve();
    assert.equal(await saving, 'savedPending');
    assert.equal(f.calls.filter(value => value === 'complete').length, 0);
    assert.ok(f.wire.every(byte => byte === 0));
  } finally { f.operation.discard(); f.scope.dispose(); }
});

test('actual scoped picker rotation runs no resume/KDF; fresh owner reuses metadata before authenticating once', async () => {
  const requestId = '00000000-0000-4000-8000-000000000003', choiceId = '00000000-0000-4000-8000-000000000004';
  let selected = false, pickers = 0, resumes = 0, activeEpoch = epoch, oldScope;
  const metadata = value => JSON.stringify({ version: 1, ...value });
  const native = {
    checkAppLockScope(expected) { if (expected !== activeEpoch) throw Error('stale_epoch'); },
    async protectedFile(operation, serialized, _bytes, expected) {
      assert.equal(expected, activeEpoch); const frame = JSON.parse(serialized); assert.equal(frame.purpose, 'backup-export');
      if (operation === 'pendingChoice') return metadata(selected ? { requestId, choiceId } : {});
      if (operation === 'beginBackupChoice') return metadata({ requestId });
      if (operation === 'chooseDestination') {
        pickers++; selected = true; oldScope.dispose(); return metadata({ requestId, choiceId });
      }
      throw Error(`unexpected file operation ${operation}`);
    },
  };
  const start = scope => {
    const files = createBackupFileServices(scope);
    return startBackupExport({ kind: 'resume', scope, draftId: makeId(7),
      prepareDestination: files.prepareBackupDestination,
      async resume(id, savedCode) { resumes++; assert.deepEqual(id, makeId(7)); assert.equal(savedCode, 'SAVED-ONE-TIME-CODE'); return Uint8Array.of(3, 4, 5); },
      async complete() { throw Error('not publishing in picker rotation test'); },
      async chooseDestination() { throw Error('not publishing in picker rotation test'); },
    }, 'SAVED-ONE-TIME-CODE');
  };
  oldScope = createAppLockSession(native, epoch); const old = start(oldScope);
  let freshScope, fresh;
  try {
    await assert.rejects(old.ready, /backup_export_expired/);
    assert.equal(resumes, 0); assert.equal(pickers, 1);
    activeEpoch = '00000000-0000-4000-8000-000000000002'; freshScope = createAppLockSession(native, activeEpoch);
    fresh = start(freshScope); assert.equal(await fresh.ready, 'ready');
    assert.equal(resumes, 1); assert.equal(pickers, 1);
  } finally { old.discard(); oldScope.dispose(); fresh?.discard(); freshScope?.dispose(); }
});
