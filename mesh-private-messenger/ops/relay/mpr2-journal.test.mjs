import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayJournal } from './journal.mjs';
import { prepareRelayTransactions, signRelayStep } from './transactions.mjs';
import { fixture, life, paid, pins, plan, quote, signer, steps } from './mpr2-journal-fixture.mjs';

test('MPR2 journal reopens an exact signed packet, fences replacement, and conservatively charges unknown execution', async t => {
  const f = await fixture(t), step = steps(f.value)[0];
  const row = f.journal.reserve(f.lease, f.value.proof_hash, step.id, quote, f.now());
  const signed = await signRelayStep(step, signer, life);
  await f.journal.recordSigned(f.lease, row.id, signed, f.now());
  assert.throws(() => f.journal.revisePlan(f.lease, f.value.proof_hash, plan('append_proof_stage', { data: '0b000007' }), f.now()), /pending/i);
  const oldLease = f.lease; f.restart();
  assert.throws(() => f.journal.authorizeBroadcast(oldLease, row.id, f.now()), /lease/i);
  assert.deepEqual(f.journal.authorizeBroadcast(f.lease, row.id, f.now()), signed);
  assert.throws(() => f.journal.observeEffect(f.lease, row.id, { slot: '11', blockHeight: String(life.lastValidBlockHeight) }, f.now()), /expired/i);
  assert.equal(f.journal.budget(f.now()).reservedLamports, '60');
  f.journal.observeEffect(f.lease, row.id, { slot: '11', blockHeight: String(life.lastValidBlockHeight + 1n) }, f.now());
  assert.equal(f.journal.budget(f.now()).chargedLamports, '60');
  const next = plan('append_proof_stage', { context: '11', data: '0b000007' });
  f.journal.revisePlan(f.lease, f.value.proof_hash, next, f.now());
  assert.deepEqual(f.journal.progress(f.value.proof_hash).done, []);
  assert.deepEqual(f.journal.originalPlan(f.value.proof_hash), f.value);
  assert.equal(f.journal.job(f.value.proof_hash).plan.operation.reason, next.operation.reason);
});

test('MPR2 prepared receipts cannot unlock cleanup or become immutable paid records', async t => {
  const f = await fixture(t);
  assert.throws(() => f.journal.recordReceipt(f.lease, f.value.proof_hash, { ...paid(f.value), state: 'prepared', settled: false }, f.now()), /receipt/i);
  assert.equal(f.journal.job(f.value.proof_hash).receipt, null);
  assert.throws(() => f.journal.reserve(f.lease, f.value.proof_hash, 'close-stage', quote, f.now()), /settled/i);
  assert.throws(() => f.journal.observeStep(f.lease, f.value.proof_hash, 'close-stage', { slot: '10' }, f.now()), /settled/i);
  assert.throws(() => f.journal.revisePlan(f.lease, f.value.proof_hash, plan('explicit_stage_close', { settled: true }), f.now()), /settled|receipt/i);
  f.journal.recordReceipt(f.lease, f.value.proof_hash, paid(f.value, pins.program), f.now());
  assert.equal(f.journal.job(f.value.proof_hash).finder, f.value.finder);
  assert.equal(f.journal.job(f.value.proof_hash).receipt.finder, pins.program);
  const close = plan('explicit_stage_close', { settled: true, data: '0e' });
  assert.equal(f.journal.revisePlan(f.lease, f.value.proof_hash, close, f.now()).state, 'updated');
  const step = steps(close)[0];
  f.journal.reserve(f.lease, close.proof_hash, step.id, quote, f.now());
  assert.throws(() => f.journal.complete(f.lease, close.proof_hash, f.now()), /pending/i);
});

test('MPR2 dynamic instruction revisions discard completion and cannot reset spending or context', async t => {
  const original = plan('append_proof_stage', { data: '0b000007' }), f = await fixture(t, original);
  const step = steps(original)[0];
  f.journal.observeStep(f.lease, original.proof_hash, step.id, { slot: '12' }, f.now());
  assert.throws(() => f.journal.revisePlan(f.lease, original.proof_hash, original, f.now()), /context/i);
  const changed = plan('append_proof_stage', { context: '12', data: '0b00000707' });
  assert.equal(steps(changed)[0].id, step.id, 'same append offset can still carry different instruction intent');
  f.journal.revisePlan(f.lease, original.proof_hash, changed, f.now());
  assert.deepEqual(f.journal.progress(original.proof_hash).done, []);
  const freshStep = steps(changed)[0], row = f.journal.reserve(f.lease, original.proof_hash, freshStep.id, quote, f.now());
  await f.journal.recordSigned(f.lease, row.id, await signRelayStep(freshStep, signer, life), f.now());
  f.journal.finalize(f.lease, row.id, { success: false, debitLamports: '45', slot: '14' }, f.now());
  f.journal.revisePlan(f.lease, original.proof_hash, { ...changed, context_slot: '14' }, f.now());
  assert.equal(f.journal.budget(f.now()).chargedLamports, '45');
  f.restart();
  assert.equal(f.journal.budget(f.now()).chargedLamports, '45');
  assert.equal(f.journal.progress(original.proof_hash).minContextSlot, '14');
});

test('MPR2 migration retains a legacy signed packet and one global pending fence across protocol versions', {
  skip: !process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH && 'requires legacy Mesh admission fixtures',
}, async t => {
  const legacy = JSON.parse((await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH, 'utf8')).trim().split('\n')[0]);
  const directory = await mkdtemp(join(tmpdir(), 'mpr2-journal-upgrade-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const options = { path: join(directory, 'relay.sqlite'), identity: 'legacy:scope', pins: legacy,
    policy: { perJobLamports: '200', windowLamports: '300', maxJobs: 8 } };
  const old = new RelayJournal(options); t.after(() => old.close());
  old.accept(legacy, 1000); const lease = old.claim('legacy', 1001);
  const first = prepareRelayTransactions(legacy, { ...legacy, proofHex: legacy.proof_hex }).preparation[0];
  const reservation = old.reserve(lease, legacy.proof_hash, first.id, quote, 1002);
  const signed = await signRelayStep(first, signer, life);
  await old.recordSigned(lease, reservation.id, signed, 1003);
  const mixedPins = { program: legacy.program, log: legacy.log, mint: legacy.mint, submitter: legacy.submitter,
    usdcMint: legacy.mint, morseMint: pins.morseMint };
  const sql = new DatabaseSync(options.path); t.after(() => sql.close());
  sql.prepare('UPDATE relay_scope SET lease_until = ?').run(Date.now() + 60000);
  assert.throws(() => new RelayJournal({ ...options, pins: mixedPins }), /legacy.*worker/i);
  sql.prepare('UPDATE relay_scope SET lease_until = 0').run();
  const journal = new RelayJournal({ ...options, pins: mixedPins }); t.after(() => journal.close());
  assert.equal(sql.prepare('SELECT version FROM relay_scope').get().version, 3);
  assert.deepEqual(journal.pending().signed, signed);
  assert.throws(() => old.renew(lease, 1004), /version/i);
  const nextLease = journal.claim('mixed', 1004);
  assert.deepEqual(journal.authorizeBroadcast(nextLease, reservation.id, 1005), signed);
  const value = plan(); Object.assign(value, { program: legacy.program, log: legacy.log, submitter: legacy.submitter,
    usdc_mint: legacy.mint, morse_mint: pins.morseMint });
  value.operation.instructions[0].programId = legacy.program;
  value.operation.instructions[0].accountKeys[1] = legacy.log;
  journal.accept(value, 1006);
  const current = prepareRelayTransactions(value, { ...mixedPins, proofHex: value.proof_hex }).preparation[0];
  assert.throws(() => journal.reserve(nextLease, value.proof_hash, current.id, quote, 1007), /pending/i);
  journal.finalize(nextLease, reservation.id, { success: false, debitLamports: '45', slot: legacy.context_slot }, 1008);
  assert.equal(journal.budget(1009).chargedLamports, '45');
  const next = journal.reserve(nextLease, value.proof_hash, current.id, quote, 1010);
  journal.abandonUnsigned(nextLease, next.id, 1011);
  const receipt = { schema_version: 1, proof_hash: legacy.proof_hash, mint: legacy.mint, finder: legacy.finder };
  journal.recordReceipt(nextLease, legacy.proof_hash, receipt, 1012);
  assert.equal(journal.completeUnspent(nextLease, legacy.proof_hash, 1013), false, 'legacy signed spending remains retained');
  assert.throws(() => journal.revisePlan(nextLease, legacy.proof_hash, legacy, 1014), /settled/i);
  assert.deepEqual(journal.job(legacy.proof_hash).receipt, receipt);
});

test('MPR2 settled receipt retention keeps immutable payout identity and a permanent observation floor', async t => {
  const f = await fixture(t), proof = f.value.proof_hash;
  f.journal.recordReceipt(f.lease, proof, paid(f.value, pins.program), f.now());
  assert.throws(() => f.journal.recordReceipt(f.lease, proof, paid(f.value), f.now()), /changed/i);
  assert.equal(f.journal.completeUnspent(f.lease, proof, f.now()), true);
  f.advance(7 * 86400000 + 1); f.restart();
  assert.equal(f.journal.maintain(f.lease, f.now()).jobs, 1);
  assert.equal(f.journal.jobs().length, 0);
  assert.equal(f.journal.retention().minContextSlot, f.value.context_slot);
  assert.throws(() => f.journal.accept(plan('initialize_proof_stage', { context: '9' }), f.now()), /context/i);
});
