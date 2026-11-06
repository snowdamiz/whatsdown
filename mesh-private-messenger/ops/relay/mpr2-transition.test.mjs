import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayJournal } from './journal.mjs';
import { createRelayScheduler } from './scheduler.mjs';
import { prepareRelayTransactions, relayStepIntent, relayStepMessage, signRelayStep } from './transactions.mjs';
import { life, pins as fixturePins, quote, signer } from './mpr2-journal-fixture.mjs';

if (!process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH) throw new Error('Requires retained Mesh relay admission plans');
const plans = (await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH, 'utf8')).trim().split('\n').map(JSON.parse);
const prepare = plan => prepareRelayTransactions(plan, { ...plan, mint: plan.mint ?? plan.usdc_mint,
  usdcMint: plan.usdc_mint, morseMint: plan.morse_mint, proofHex: plan.proof_hex });
const legacy = plans.find(plan => !prepare(plan).needsLookup);
const wide = plans.find(plan => prepare(plan).needsLookup);
function current(old, context = old.context_slot, reason = 'append_proof_stage') {
  const initialize = reason === 'initialize_proof_stage', close = reason === 'explicit_stage_close';
  const data = initialize ? old.stage.initialize_hex : close ? old.stage.close_hex : old.stage.append_hex[0];
  const keys = initialize ? [old.submitter, old.log, old.stage.address, '11111111111111111111111111111111'] : [old.submitter, old.stage.address];
  return { schema_version: 2, status: close ? 'settled' : 'ready', program: old.program, log: old.log, submitter: old.submitter,
    usdc_mint: old.mint, morse_mint: fixturePins.morseMint, proof_hex: old.proof_hex, proof_hash: old.proof_hash,
    finder: old.finder, receipt: old.receipt, context_slot: context, stage: { address: old.stage.address, full_hash: old.stage.full_hash }, lookup: null,
    operation: { reason, instructions: [{ schemaVersion: 1, programId: old.program, accountKeys: keys, accountCount: keys.length,
      signerKeys: [old.submitter], writableKeys: [old.submitter, old.stage.address], dataBase64: Buffer.from(data, 'hex').toString('base64'), dataBytes: data.length / 2 }],
    rent_allocations: initialize ? [{ address: old.stage.address, space: 1024 }] : [] } };
}
const paid = (old, context = old.context_slot) => ({ schema_version: 1, proof_hash: old.proof_hash, mint: old.mint, finder: old.program, context_slot: context });
async function fixture(t, original = legacy) {
  const directory = await mkdtemp(join(tmpdir(), 'mpr2-transition-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const pins = { ...original, usdcMint: original.mint, morseMint: fixturePins.morseMint };
  const options = { path: join(directory, 'relay.sqlite'), identity: 'mixed:transition', pins,
    policy: { perJobLamports: '100', windowLamports: '150', maxJobs: 8 } };
  let journal = new RelayJournal(options), clock = 1000, lease;
  t.after(() => journal.close());
  const now = () => clock++;
  journal.accept(original, now()); lease = journal.claim('worker', now());
  return { original, options, now, get journal() { return journal; }, get lease() { return lease; },
    advance(ms = 1001) { clock += ms; },
    restart() { journal.close(); journal = new RelayJournal(options); clock += 30001; lease = journal.claim('replacement', now()); } };
}
async function signOld(f) {
  const step = prepare(f.original).preparation[0], row = f.journal.reserve(f.lease, f.original.proof_hash, step.id, quote, f.now());
  const packet = await signRelayStep(step, signer, life);
  await f.journal.recordSigned(f.lease, row.id, packet, f.now());
  return { row, packet };
}

for (const outcome of ['expired', 'finalized', 'effect']) test(`MPR1 adopts MPR2 only after ${outcome} old packet, preserving exact evidence, lifetime spending and fences`, async t => {
  const f = await fixture(t), proof = legacy.proof_hash, { row, packet } = await signOld(f);
  const context = String(BigInt(legacy.context_slot) + 1n), next = current(legacy, context, 'initialize_proof_stage');
  assert.throws(() => f.journal.revisePlan(f.lease, proof, next, f.now()), /pending/i);
  f.restart();
  assert.deepEqual(f.journal.authorizeBroadcast(f.lease, row.id, f.now()), packet);
  const observation = { slot: context, blockHeight: String(life.lastValidBlockHeight + 1n) };
  if (outcome === 'finalized') f.journal.finalize(f.lease, row.id, { ...observation, success: true, debitLamports: '45' }, f.now());
  else if (outcome === 'effect') f.journal.observeEffect(f.lease, row.id, observation, f.now());
  else f.journal.expire(f.lease, row.id, observation, f.now());
  const budget = f.journal.budget(f.now()), retention = f.journal.retention();
  assert.equal(f.journal.revisePlan(f.lease, proof, next, f.now()).state, 'updated');
  assert.deepEqual(f.journal.originalPlan(proof), legacy);
  assert.deepEqual(f.journal.job(proof).plan, next);
  assert.deepEqual(f.journal.transaction(row.id).signed, packet);
  assert.deepEqual(f.journal.budget(f.now()), budget);
  assert.deepEqual(f.journal.retention(), retention);
  assert.equal(f.journal.progress(proof).minContextSlot, context);
  assert.equal(f.journal.progress(proof).done.includes('initialize'), outcome !== 'expired', 'only exact earned instruction intent survives');
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...legacy, context_slot: context }, f.now()), /version|identity/i);
  f.restart();
  assert.deepEqual(f.journal.originalPlan(proof), legacy);
  assert.deepEqual(f.journal.budget(f.now()), budget);
  const append = prepare(current(legacy, context)).preparation[0];
  f.journal.revisePlan(f.lease, proof, current(legacy, context), f.now());
  if (outcome === 'effect') assert.throws(() => f.journal.reserve(f.lease, proof, append.id, { ...quote, maxDebitLamports: '41' }, f.now()), /job budget/i);
  const reserved = f.journal.reserve(f.lease, proof, append.id, { ...quote, maxDebitLamports: '40' }, f.now());
  const other = plans.find(plan => plan.proof_hash !== proof && ['program', 'log', 'mint', 'submitter'].every(field => plan[field] === legacy[field]));
  f.journal.accept(other, f.now());
  assert.throws(() => f.journal.revisePlan(f.lease, other.proof_hash, current(other), f.now()), /pending/i);
  f.journal.abandonUnsigned(f.lease, reserved.id, f.now());
});

test('cross-version revision rejects identity changes, stale context, missing mixed pins and every paid legacy job', async t => {
  const f = await fixture(t), proof = legacy.proof_hash, next = current(legacy);
  for (const field of ['program', 'log', 'submitter', 'finder', 'receipt', 'proof_hash', 'usdc_mint', 'morse_mint']) {
    const changed = { ...next, [field]: field === 'proof_hash' ? 'ab'.repeat(32) : legacy.stage.address };
    assert.throws(() => f.journal.revisePlan(f.lease, proof, changed, f.now()), /identity|pin|account/i, field);
  }
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, stage: { ...next.stage, address: legacy.program } }, f.now()), /identity|account/i);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, stage: { ...next.stage, full_hash: 'ab'.repeat(32) } }, f.now()), /hash/i);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, proof_hex: `${next.proof_hex.slice(0, -2)}ff` }, f.now()), /hash|identity/i);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, mint: legacy.program }, f.now()), /identity/i);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, context_slot: '1' }, f.now()), /context/i);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, { ...next, status: 'settled', operation: null }, f.now()), /settled|receipt/i);
  const noPins = new RelayJournal({ ...f.options, path: join(f.options.path, '..', 'legacy.sqlite'), pins: legacy }); t.after(() => noPins.close());
  noPins.accept(legacy, 1000); const lease = noPins.claim('legacy', 1001);
  assert.throws(() => noPins.revisePlan(lease, proof, next, 1002), /pin/i);
  const receipt = paid(legacy); f.journal.recordReceipt(f.lease, proof, receipt, f.now());
  assert.throws(() => f.journal.revisePlan(f.lease, proof, next, f.now()), /settled/i);
  assert.throws(() => f.journal.reserve(f.lease, proof, 'initialize', quote, f.now()), /settled/i);
  assert.equal(f.journal.completeUnspent(f.lease, proof, f.now()), true);
  assert.throws(() => f.journal.revisePlan(f.lease, proof, next, f.now()), /settled|completed/i);
  assert.throws(() => f.journal.recordReceipt(f.lease, proof, { ...receipt, finder: legacy.finder }, f.now()), /changed/i);
  assert.deepEqual(f.journal.job(proof).receipt, receipt);
  assert.equal(f.journal.job(proof).plan.schema_version, 1);
});

test('adoption preserves compacted lifetime spending and retained context and transaction lifetime', async t => {
  const f = await fixture(t), proof = legacy.proof_hash, { row } = await signOld(f);
  const context = String(BigInt(legacy.context_slot) + 1n);
  f.journal.finalize(f.lease, row.id, { success: false, debitLamports: '45', slot: context }, f.now());
  f.advance(7 * 86400000 + 1); f.restart();
  assert.equal(f.journal.maintain(f.lease, f.now()).transactions, 1);
  const retained = f.journal.retention();
  assert.deepEqual(retained, { minContextSlot: context, lastValidBlockHeight: quote.lastValidBlockHeight });
  f.journal.revisePlan(f.lease, proof, current(legacy, context), f.now());
  f.restart();
  assert.deepEqual(f.journal.retention(), retained); assert.deepEqual(f.journal.originalPlan(proof), legacy);
  const step = prepare(current(legacy, context)).preparation[0];
  assert.throws(() => f.journal.reserve(f.lease, proof, step.id, quote, f.now()), /lifetime/i);
  assert.throws(() => f.journal.reserve(f.lease, proof, step.id, { ...quote, lastValidBlockHeight: String(life.lastValidBlockHeight + 1n) }, f.now()), /job budget/i);
});

for (const outcome of ['expired', 'finalized']) test(`mixed scheduler resumes an unresolved MPR1 job after ${outcome} recovery through MPR2 payment and cleanup`, async t => {
  const f = await fixture(t), proof = legacy.proof_hash, { packet } = await signOld(f), sent = [], resumes = [];
  let settled = null, closed = false;
  const verifier = {
    async receipt(p, floor) { return { status: settled ? 'settled' : 'missing', context_slot: floor, receipt: p.receipt, settled_receipt: settled }; },
    async resume(p, floor, options) { assert.equal(f.journal.pending(), null); assert.equal(p.schema_version, 1); assert.deepEqual(options.lookup, p.lookup); resumes.push(floor); return current(legacy, floor); },
    async admit(wire, floor, options) { assert.equal(options.schemaVersion, 2); assert.equal(Buffer.from(wire).toString('hex'), legacy.proof_hex); return { ...current(legacy, floor, settled ? 'explicit_stage_close' : 'append_proof_stage'), ...(closed ? { operation: null } : {}) }; },
    async stage(p, floor) { assert.equal(p.schema_version, 1); return { status: 'missing', context_slot: floor }; },
    async effect(p, effect, floor) { return { state: closed ? 'present' : 'absent', slot: floor }; },
  };
  const rpc = {
    async quote(step, view) { return { ...quote, maxDebitLamports: '10', ...relayStepMessage(step, life, view) }; },
    async broadcast(value) { assert.deepEqual(value, f.journal.pending().signed); sent.push(value); },
    async observe(step, value, readEffect) {
      if (value.signature === packet.signature) {
        assert.deepEqual(value, packet); assert.equal(relayStepIntent(step), relayStepIntent(prepare(legacy).preparation[0]));
        assert.equal(resumes.length, 0); await readEffect({ minContextSlot: value.minContextSlot });
        return outcome === 'expired' ? { state: 'expired', slot: legacy.context_slot, blockHeight: String(life.lastValidBlockHeight + 1n) } :
          { state: 'finalized', success: true, slot: legacy.context_slot, debitLamports: '5' };
      }
      if (step.kind === 'append') settled = { schema_version: 2, status: 'settled', proof_hash: proof, finder: legacy.finder,
        usdc_mint: legacy.mint, morse_mint: fixturePins.morseMint, context_slot: legacy.context_slot };
      if (step.kind === 'close-stage') closed = true;
      return { state: 'finalized', success: true, slot: legacy.context_slot, debitLamports: '5' };
    },
  };
  f.advance(30001); const scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now });
  assert.equal((await scheduler.tick()).state, outcome);
  assert.equal(resumes.length, 0); assert.deepEqual(f.journal.originalPlan(proof), legacy);
  for (let turn = 0; turn < 8 && f.journal.job(proof).state !== 'complete'; turn++) { f.advance(); await scheduler.tick(); }
  assert.equal(f.journal.job(proof).state, 'complete');
  assert.equal(resumes.length, 1); assert.deepEqual(sent.map(value => value.stepId), ['append/0', 'close-stage']);
  assert.deepEqual(f.journal.originalPlan(proof), legacy); assert.deepEqual(f.journal.job(proof).receipt, settled);
  assert.equal(f.journal.budget(f.now()).chargedLamports, outcome === 'expired' ? '10' : '15');
  assert.equal(f.journal.budget(f.now()).reservedLamports, '0');
});

test('settled resume envelope records the original MPR1 receipt and cleans its old recipe without adopting MPR2', async t => {
  const f = await fixture(t), proof = legacy.proof_hash, { row } = await signOld(f), receipt = paid(legacy);
  f.journal.finalize(f.lease, row.id, { success: true, debitLamports: '5', slot: legacy.context_slot }, f.now());
  let resumes = 0;
  const verifier = { async receipt() { return { status: 'missing' }; },
    async resume() { resumes++; return { ...current(legacy, legacy.context_slot, 'explicit_stage_close'), receipt: legacy.receipt, settled_receipt: receipt }; },
    async stage(p, floor) { assert.equal(p.schema_version, 1); return { status: 'missing', context_slot: floor }; } };
  f.advance(30001); const scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc: {}, now: f.now });
  assert.equal((await scheduler.tick()).state, 'receipt-observed');
  f.advance(); assert.equal((await scheduler.tick()).state, 'complete');
  assert.equal(resumes, 1); assert.deepEqual(f.journal.job(proof).receipt, receipt);
  assert.deepEqual(f.journal.job(proof).plan, legacy); assert.deepEqual(f.journal.originalPlan(proof), legacy);
});

test('scheduler retires an owned incompatible legacy ALT with old signed recipes before version adoption', async t => {
  const f = await fixture(t, wide), proof = wide.proof_hash, sent = [];
  assert.equal(f.journal.claimResources(f.lease, proof, f.now()), true);
  let table = 'ready', settled = null, closed = false;
  const context = String(BigInt(wide.context_slot) + 1000n);
  const verifier = {
    async receipt(p, floor) { return { status: settled ? 'settled' : 'missing', context_slot: floor, receipt: settled }; },
    async resume(p, floor) { assert.equal(p.schema_version, 1); return current(wide, floor); },
    async admit(wire, floor) { return { ...current(wide, floor, settled ? 'explicit_stage_close' : 'append_proof_stage'), ...(closed ? { operation: null } : {}) }; },
    async lookup(p) { assert.equal(p.schema_version, 1); return { schema_version: 1, status: table, address: wide.lookup.address,
      authority: wide.submitter, creationSlot: wide.lookup.recent_slot, contextSlot: context,
      lastExtendedSlot: table === 'missing' ? '0' : wide.lookup.recent_slot,
      deactivationSlot: ['cooling', 'closable'].includes(table) ? wide.lookup.recent_slot : '18446744073709551615',
      remainingBlocks: table === 'cooling' ? 513 : 0, addresses: table === 'missing' ? [] : wide.lookup.addresses }; },
    async effect(p, effect, floor) { return { state: closed ? 'present' : 'absent', slot: floor }; },
  };
  const rpc = {
    async quote(step, view) { return { ...quote, maxDebitLamports: '10', ...relayStepMessage(step, life, view) }; },
    async broadcast(packet) {
      const p = f.journal.job(proof).plan; sent.push(packet.stepId);
      if (packet.stepId.includes('table')) {
        assert.equal(p.schema_version, 1); assert.deepEqual(p.lookup, wide.lookup);
        const step = prepare(p).cleanup.find(step => step.id === packet.stepId);
        assert.deepEqual(packet, await signRelayStep(step, signer, life, packet.stepId === 'close-table' ? await verifier.lookup(p) : undefined));
        if (packet.stepId === 'deactivate-table') table = 'cooling'; else table = 'missing';
      }
    },
    async observe(step) {
      if (step.kind === 'append') settled = { schema_version: 2, status: 'settled', proof_hash: proof, finder: wide.finder,
        usdc_mint: wide.mint, morse_mint: fixturePins.morseMint, context_slot: context };
      if (step.kind === 'close-stage') closed = true;
      return { state: 'finalized', success: true, slot: context, debitLamports: '5' };
    },
  };
  f.advance(30001); const scheduler = createRelayScheduler({ journal: f.journal, verifier, rpc, signer, now: f.now });
  assert.equal((await scheduler.tick()).state, 'broadcast'); assert.deepEqual(sent, ['deactivate-table']);
  assert.equal((await scheduler.tick()).state, 'finalized'); f.advance();
  assert.equal((await scheduler.tick()).reason, 'cooldown');
  assert.equal(f.journal.job(proof).plan.schema_version, 1); assert.ok(f.journal.resources(proof).includes(wide.lookup.address));
  table = 'closable';
  for (let turn = 0; turn < 12 && f.journal.job(proof).state !== 'complete'; turn++) { f.advance(); await scheduler.tick(); }
  assert.equal(f.journal.job(proof).state, 'complete');
  assert.deepEqual(sent, ['deactivate-table', 'close-table', 'append/0', 'close-stage']);
  assert.deepEqual(f.journal.originalPlan(proof), wide); assert.deepEqual(f.journal.resources(proof), []);
  assert.equal(f.journal.budget(f.now()).chargedLamports, '20');
});
