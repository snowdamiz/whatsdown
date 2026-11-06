import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startBackupExport } from '../src/backup-export.ts';
import { createAppLockSession } from '../src/app-lock.ts';

for (const kind of ['session disposal', 'export cancellation']) {
  test(`${kind} during native validation clears newly returned backup material`, async () => {
    let armed = false;
    let cancel = () => {};
    const material = { draftId: new Uint8Array(32).fill(7), wire: Uint8Array.of(7, 8, 9), recoveryCode: 'SYNTHETIC-RECOVERY-CODE' };
    const scope = createAppLockSession({
      checkAppLockScope() {
        if (armed) {
          armed = false;
          if (kind === 'session disposal') scope.dispose();
          else cancel();
        }
      },
    }, '00000000-0000-4000-8000-000000000001');
    const operation = startBackupExport({
      kind: 'create', async complete() {}, scope,
      async prepareDestination() { return true; },
      async create() { armed = true; return material; },
      async chooseDestination() { throw new Error('This export must not publish a file'); },
    });
    cancel = operation.discard;
    try {
      await assert.rejects(operation.ready, /backup_export_expired/);
      assert.deepEqual([...material.wire], [0, 0, 0]);
      assert.equal(material.recoveryCode, '');
      if (kind === 'export cancellation') scope.assertActive();
    } finally { operation.discard(); scope.dispose(); }
  });
}

const epoch = '00000000-0000-4000-8000-000000000001';
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function fixture({ size = 140000, delayedCreate, choose, write, prepare } = {}) {
  let active = true;
  const calls = [], copies = [], chunks = [];
  const creating = deferred();
  const wire = new Uint8Array(size).map((_, i) => i % 251);
  const expected = wire.slice();
  const scope = createAppLockSession({
    checkAppLockScope(value) { assert.equal(value, epoch); if (!active) throw new Error('stale_epoch'); },
    async copyProtectedText(text, value) { assert.equal(value, epoch); copies.push(text); },
  }, epoch);
  const sink = {
    async write(offset, bytes) { calls.push(['write', offset, bytes.length]); chunks.push(bytes.slice()); if (write) await write(offset, bytes); },
    async finish() { calls.push(['finish']); },
    async abort() { calls.push(['abort']); },
  };
  const material = { draftId: new Uint8Array(32).fill(7), wire, recoveryCode: 'MRC1-SYNTHETIC-TEST-CODE' };
  const operation = startBackupExport({ kind: 'create', async complete() {}, scope,
    prepareDestination: prepare ?? (async () => true),
    create: () => { creating.resolve(); return delayedCreate ? delayedCreate.promise : Promise.resolve(material); },
    chooseDestination: async (total, context) => { calls.push(['choose', total, context]); return choose ? choose(sink) : sink; },
  });
  return { operation, scope, material, expected, calls, copies, chunks, sink, creating, revoke() { active = false; } };
}

test('saving requires acknowledgement of this recovery code and writes only bounded ciphertext chunks', async () => {
  const f = fixture();
  await f.operation.ready;
  assert.equal(f.operation.recoveryCode(), f.material.recoveryCode);
  await assert.rejects(f.operation.save(), /backup_export_acknowledgement_required/);
  assert.equal(f.calls.length, 0);
  await f.operation.copyRecoveryCode();
  assert.deepEqual(f.copies, ['MRC1-SYNTHETIC-TEST-CODE']);
  await assert.rejects(f.operation.save(), /backup_export_acknowledgement_required/);
  f.operation.acknowledgeRecoveryCode(true);
  f.operation.acknowledgeRecoveryCode(false);
  await assert.rejects(f.operation.save(), /backup_export_acknowledgement_required/);
  f.operation.acknowledgeRecoveryCode(true);
  assert.equal(await f.operation.save(), 'saved');
  assert.deepEqual(f.calls.filter(c => c[0] === 'write').map(c => c.slice(1)), [[0, 65536], [65536, 65536], [131072, 8928]]);
  assert.deepEqual(Buffer.concat(f.chunks), Buffer.from(f.expected));
  assert.equal(f.calls.filter(c => c[0] === 'finish').length, 1);
  assert.equal(f.calls.filter(c => c[0] === 'abort').length, 0);
  assert.ok(f.material.wire.every(byte => byte === 0));
  assert.throws(() => f.operation.recoveryCode(), /backup_export_expired/);
  await assert.rejects(f.operation.save(), /backup_export_expired/);
});

test('an expired destination closes the prepared export instead of retrying the same missing claim', async () => {
  const f = fixture({ choose: () => null });
  await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
  await assert.rejects(f.operation.save(), /backup_export_failed/);
  assert.ok(f.material.wire.every(byte => byte === 0));
  assert.equal(f.material.recoveryCode, '');
  await assert.rejects(f.operation.save(), /backup_export_expired/);
  assert.equal(f.calls.filter(c => c[0] === 'choose').length, 1);
});

test('discarding during creation clears a late material result and never opens a destination', async () => {
  const pending = deferred();
  const f = fixture({ delayedCreate: pending });
  await f.creating.promise;
  f.operation.discard(); f.operation.discard();
  pending.resolve(f.material);
  await assert.rejects(f.operation.ready, /backup_export_expired/);
  assert.ok(f.material.wire.every(byte => byte === 0));
  assert.equal(f.calls.length, 0);
  assert.throws(() => f.operation.recoveryCode(), /backup_export_expired/);
});

test('scope disposal during destination selection aborts the late sink without writing', async () => {
  const pending = deferred();
  const f = fixture({ choose: () => pending.promise });
  await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
  const saving = f.operation.save();
  f.scope.dispose(); pending.resolve(f.sink);
  await assert.rejects(saving, /backup_export_expired/);
  assert.equal(f.calls.filter(c => c[0] === 'abort').length, 1);
  assert.equal(f.calls.filter(c => c[0] === 'write' || c[0] === 'finish').length, 0);
  assert.ok(f.material.wire.every(byte => byte === 0));
});

test('a failed chunk aborts once and closes the export without committing or leaking provider errors', async () => {
  const f = fixture({ write: async offset => { if (offset > 0) throw new Error('private-provider-path'); } });
  await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
  await assert.rejects(f.operation.save(), /^Error: backup_export_failed$/);
  assert.equal(f.calls.filter(c => c[0] === 'write').length, 2);
  assert.equal(f.calls.filter(c => c[0] === 'abort').length, 1);
  assert.equal(f.calls.filter(c => c[0] === 'finish').length, 0);
  f.operation.discard(); assert.equal(f.calls.filter(c => c[0] === 'abort').length, 1);
  assert.ok(f.material.wire.every(byte => byte === 0));
});

test('native revocation without a JS event prevents save and concurrent save cannot start a second writer', async () => {
  const old = fixture(); await old.operation.ready; old.operation.acknowledgeRecoveryCode(true); old.revoke();
  await assert.rejects(old.operation.save(), /backup_export_expired/);
  assert.equal(old.calls.length, 0); assert.ok(old.material.wire.every(byte => byte === 0));
  const pending = deferred();
  const f = fixture({ choose: () => pending.promise });
  await f.operation.ready; f.operation.acknowledgeRecoveryCode(true);
  const first = f.operation.save();
  await assert.rejects(f.operation.save(), /backup_export_busy/);
  pending.resolve(f.sink); assert.equal(await first, 'saved');
  assert.equal(f.calls.filter(c => c[0] === 'choose').length, 1);
  assert.equal(f.calls.filter(c => c[0] === 'finish').length, 1);
});

test('destination preparation finishes before any archive or recovery code is created', async () => {
  const choice = deferred();
  const f = fixture({ prepare: () => choice.promise });
  let created = false;
  void f.creating.promise.then(() => { created = true; });
  await Promise.resolve();
  try {
    assert.equal(created, false);
    assert.throws(() => f.operation.recoveryCode(), /backup_export_busy/);
    choice.resolve(true);
    assert.equal(await f.operation.ready, 'ready');
    assert.equal(created, true);
    assert.equal(f.operation.recoveryCode(), 'MRC1-SYNTHETIC-TEST-CODE');
  } finally { f.operation.discard(); }
});

test('cancelling destination preparation creates no backup material', async () => {
  const f = fixture({ prepare: async () => false });
  let created = false;
  void f.creating.promise.then(() => { created = true; });
  try {
    assert.equal(await f.operation.ready, 'cancelled');
    assert.equal(created, false);
    assert.equal(f.calls.length, 0);
    assert.throws(() => f.operation.recoveryCode(), /backup_export_expired/);
  } finally { f.operation.discard(); }
});

test('picker relock retires the old operation and a fresh explicit operation resumes the selected destination', async () => {
  const choice = deferred();
  let selected = false, pickers = 0, creates = 0, claims = 0;
  const prepare = async () => {
    if (selected) return true;
    pickers++;
    await choice.promise;
    selected = true;
    return true;
  };
  const start = scope => startBackupExport({ kind: 'create', async complete() {}, scope, prepareDestination: prepare,
    async create() { creates++; return { draftId: new Uint8Array(32).fill(7), wire: new Uint8Array([4, 5, 6]), recoveryCode: 'FRESH-CODE' }; },
    async chooseDestination() {
      assert.equal(selected, true); selected = false; claims++;
      return { async write() {}, async finish() {}, async abort() {} };
    },
  });
  const oldScope = createAppLockSession({ checkAppLockScope() {} }, epoch);
  const old = start(oldScope);
  const oldResult = old.ready.then(() => 'unexpected-ready', error => error.message);
  try {
    oldScope.dispose(); choice.resolve();
    assert.equal(await oldResult, 'backup_export_expired');
    assert.equal(creates, 0);
    const freshScope = createAppLockSession({ checkAppLockScope() {} }, '00000000-0000-4000-8000-000000000002');
    const fresh = start(freshScope);
    try {
      assert.equal(await fresh.ready, 'ready');
      assert.equal(creates, 1); assert.equal(pickers, 1);
      assert.equal(fresh.recoveryCode(), 'FRESH-CODE');
      await assert.rejects(fresh.save(), /backup_export_acknowledgement_required/);
      fresh.acknowledgeRecoveryCode(true);
      assert.equal(await fresh.save(), 'saved');
      assert.equal(claims, 1); assert.equal(pickers, 1);
      await assert.rejects(old.save(), /backup_export_expired/);
    } finally { fresh.discard(); freshScope.dispose(); }
  } finally { old.discard(); oldScope.dispose(); }
});

test('native revocation during preparation prevents creation even before its JS event', async () => {
  const choice = deferred();
  const f = fixture({ prepare: () => choice.promise });
  let created = false;
  void f.creating.promise.then(() => { created = true; });
  const result = f.operation.ready.then(() => 'unexpected-ready', error => error.message);
  f.revoke(); choice.resolve(true);
  try {
    assert.equal(await result, 'backup_export_expired');
    assert.equal(created, false);
    assert.equal(f.calls.length, 0);
  } finally { f.operation.discard(); }
});
