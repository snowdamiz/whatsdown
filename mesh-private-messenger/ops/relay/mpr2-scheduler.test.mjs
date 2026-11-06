import assert from 'node:assert/strict';
import test from 'node:test';
import { createRelayScheduler } from './scheduler.mjs';
import { createRelayEffectReader } from './effects.mjs';
import { relayStepMessage } from './transactions.mjs';
import { fixture, life, paid, plan, quote, signer, steps, widePlan } from './mpr2-journal-fixture.mjs';

test('MPR2 effects are authenticated by Mesh and fail closed on stale or malformed observations', async () => {
  const value = plan(), step = steps(value)[0], calls = [];
  let result = { state: 'present', slot: '12' };
  const reader = createRelayEffectReader({ async effect(p, effect, floor) { calls.push({ p, effect, floor }); return result; } });
  assert.deepEqual(await reader({ plan: value }, step, { minContextSlot: '11' }), result);
  assert.equal(calls[0].p, value); assert.equal(calls[0].floor, '11');
  result = { state: 'present', slot: '10' };
  await assert.rejects(reader({ plan: value }, step, { minContextSlot: '11' }), /context/i);
  result = { state: 'unknown', slot: '12' };
  await assert.rejects(reader({ plan: value }, step, { minContextSlot: '11' }), /state/i);
});

test('MPR2 scheduler replans after pending reconciliation, persists bytes before sending, and cleans only a settled receipt', async t => {
  const f = await fixture(t), sent = [], admissions = [];
  let fresh = f.value, settled = null, effectPresent = false, observations = 0;
  const verifier = {
    async receipt(p, floor) { return { status: settled ? 'settled' : 'prepared', context_slot: floor, receipt: settled }; },
    async admit(wire, floor) { assert.equal(Buffer.from(wire).toString('hex'), f.value.proof_hex); admissions.push(floor); return fresh; },
    async effect(p, effect, floor) { return { state: effectPresent ? 'present' : 'absent', slot: floor }; },
  };
  const rpc = {
    async quote() { return quote; },
    async broadcast(packet) { assert.deepEqual(f.journal.pending().signed, packet); sent.push(packet); throw new Error('response lost'); },
    async observe() { observations++; return { state: 'finalized', success: true, slot: '11', debitLamports: '5' }; },
  };
  let scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now, owner: 'scheduler' });
  f.advance(30001);
  assert.equal((await scheduler.tick()).state, 'unacknowledged');
  assert.equal(admissions.length, 1); assert.equal(sent.length, 1);
  fresh = plan('append_proof_stage', { context: '11', data: '0b000007' });
  assert.equal((await scheduler.tick()).state, 'finalized');
  assert.equal(admissions.length, 1, 'old signed plan is reconciled before requesting a fresh plan');
  f.advance(1001);
  assert.equal((await scheduler.tick()).state, 'unacknowledged');
  assert.equal(admissions.length, 2); assert.equal(sent.length, 2); assert.notEqual(sent[0].stepId, sent[1].stepId);
  assert.equal((await scheduler.tick()).state, 'finalized');
  settled = paid({ ...f.value, context_slot: '11' });
  fresh = plan('explicit_stage_close', { context: '11', data: '0e', settled: true });
  f.advance(1001);
  assert.equal((await scheduler.tick()).state, 'unacknowledged');
  assert.equal(f.journal.job(f.value.proof_hash).state, 'settled');
  assert.equal((await scheduler.tick()).state, 'finalized');
  fresh = plan(null, { context: '11', settled: true }); effectPresent = true;
  f.advance(1001);
  assert.equal((await scheduler.tick()).state, 'complete');
  assert.equal(sent.length, 3); assert.equal(observations, 3);
  assert.equal(f.journal.budget(f.now()).chargedLamports, '15');
});

test('MPR2 unknown execution keeps the old recipe through expiry and consumes the full quote after Mesh proves its effect', async t => {
  const f = await fixture(t), sent = [], effects = [], admissions = [];
  let result = 'pending';
  const verifier = {
    async receipt() { return { status: 'prepared' }; },
    async admit() { admissions.push('admit'); return f.value; },
    async effect(p, effect, floor) { effects.push({ plan: p, effect }); return { state: 'present', slot: floor }; },
  };
  const rpc = {
    async quote() { return quote; },
    async broadcast(packet) { sent.push(packet); throw new Error('unknown outcome'); },
    async observe(step, signed, readEffect) {
      assert.equal(step.id, signed.stepId);
      await readEffect({ minContextSlot: signed.minContextSlot });
      return result === 'effect' ? { state: result, slot: '11', blockHeight: String(BigInt(quote.lastValidBlockHeight) + 1n) } : { state: result };
    },
  };
  // The first effect read is absent so the real writer signs and persists it.
  const effect = verifier.effect; let first = true;
  verifier.effect = async (...args) => { if (first) { first = false; return { state: 'absent', slot: args[2] }; } return effect(...args); };
  f.advance(30001);
  let scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now });
  assert.equal((await scheduler.tick()).state, 'unacknowledged');
  const packet = f.journal.pending().signed;
  f.restart(); scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, now: f.now }); f.advance(30001);
  assert.equal((await scheduler.tick()).state, 'unacknowledged');
  assert.deepEqual(sent, [packet, packet]);
  result = 'expiry-barrier';
  assert.equal((await scheduler.tick()).state, 'expiry-barrier');
  assert.equal(f.journal.budget(f.now()).reservedLamports, '60');
  assert.equal(admissions.length, 1);
  result = 'effect';
  assert.equal((await scheduler.tick()).state, 'effect');
  assert.equal(f.journal.pending(), null);
  assert.equal(f.journal.budget(f.now()).chargedLamports, '60');
  assert.ok(effects.every(row => row.plan.operation.reason === 'initialize_proof_stage'));
});

test('MPR2 a superseded worker cannot quote or sign after a suspended Mesh read returns', async t => {
  const f = await fixture(t); let quotes = 0;
  const verifier = {
    async receipt() { return { status: 'prepared' }; },
    async admit() { return f.value; },
    async effect(p, effect, floor) { f.advance(30001); assert.ok(f.journal.claim('superseding-worker', f.now())); return { state: 'absent', slot: floor }; },
  };
  const rpc = { async quote() { quotes++; return quote; } };
  f.advance(30001); const scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now });
  await assert.rejects(scheduler.tick(), /lease/i);
  assert.equal(quotes, 0); assert.equal(f.journal.pending(), null);
  assert.equal((await scheduler.tick()).state, 'lease-busy');
});

test('MPR2 wide preparation builds its table first and waits for activation before quoting the exact packet', async t => {
  const value = widePlan(), f = await fixture(t, value), quoted = [], sent = [];
  let table = false, extended = 0, active = false;
  const verifier = {
    async receipt() { return { status: 'missing' }; },
    async admit(wire, floor, options) { assert.deepEqual(options.lookup, value.lookup); return value; },
    async effect(p, effect, floor) {
      const present = effect.kind === 'create-table' ? table : effect.kind === 'extend-table' ?
        extended > Number(effect.stepId.split('/')[1]) : false;
      return { state: present ? 'present' : 'absent', slot: floor };
    },
    async lookup(p, floor) { return { schema_version: 1, address: value.lookup.address, authority: value.submitter,
      creationSlot: '10', contextSlot: floor, lastExtendedSlot: table ? '10' : '0', deactivationSlot: '18446744073709551615', remainingBlocks: 0,
      addresses: !table ? [] : value.lookup.addresses.slice(0, extended * 20), status: !table ? 'missing' : extended < 2 ? 'extending' : active ? 'ready' : 'warm' }; },
  };
  const rpc = {
    async quote(step, view) {
      quoted.push(step.id);
      if (step.id === 'prepare') { assert.equal(view.status, 'ready'); assert.ok(view.addresses.length > 32); }
      return { ...quote, maxDebitLamports: '10', ...relayStepMessage(step, life, view) };
    },
    async broadcast(packet) { sent.push(packet); if (packet.stepId === 'create-table') table = true;
      if (packet.stepId.startsWith('extend-table/')) extended++; },
    async observe() { return { state: 'finalized', success: true, slot: '10', debitLamports: '1' }; },
  };
  f.advance(30001); const scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now });
  for (const id of ['create-table', 'extend-table/0', 'extend-table/1']) {
    f.advance(1001); assert.equal((await scheduler.tick()).state, 'broadcast'); assert.equal(sent.at(-1).stepId, id);
    assert.equal((await scheduler.tick()).state, 'finalized');
  }
  f.advance(1001); assert.equal((await scheduler.tick()).reason, 'lookup-activation');
  assert.deepEqual(quoted, ['create-table', 'extend-table/0', 'extend-table/1']);
  active = true; value.context_slot = '11'; f.advance(1001);
  assert.equal((await scheduler.tick()).state, 'broadcast'); assert.equal(sent.at(-1).stepId, 'prepare');
  assert.ok(f.journal.resources(value.proof_hash).includes(value.lookup.address));
});
