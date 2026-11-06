import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PublicSnapshot, snapshotPolicy } from './public-snapshot.mjs';

// Publication-state fixtures retain canonical Mesh financial values. Only
// retrieval metadata follows the synthetic call clock; these transport tests
// do not authenticate or invent accepted account bytes.
const report = JSON.parse(await readFile(new URL('../public-chain/fixtures/legacy-settled-history-report.json', import.meta.url)));
const section = report.history.proofs.pages[0].values;
const baseTime = Number(section.source_time_unix);
report.generated_at_unix = String(baseTime);
const atTime = time => ({ ...structuredClone(report), generated_at_unix: String(time) });
const digest = text => createHash('sha256').update(text).digest('hex');
const configuration = { schema_version: 1, scope: 'local-fixture', epochs: [],
  endpoints: ['http://127.0.0.1:19001', 'http://127.0.0.1:19002', 'http://127.0.0.1:19003'],
  minimum_context_slot: '0', max_age_seconds: report.max_age_seconds,
  legacy_collateral: { schema_version: 1, judge: section.judge, judge_slot: report.history.proofs.release_pins[0].deployment_slot,
    governance: section.judge, anchor_authority: section.judge, log_name: section.log_name, log_version: 1,
    service_public_key: section.service_public_key, mint: section.mint },
  history: { schema_version: 1, maximum_records: 128, page_size: 16 } };
async function policy(overrides = {}) {
  const raw = JSON.stringify({ ...configuration, ...overrides });
  return snapshotPolicy({ configurationJson: raw, policySha256: digest(raw), generatorSha256: 'b'.repeat(64) }, { fixture: true });
}
function storage(path) {
  const db = new DatabaseSync(path);
  return { db, alarms: [], sql: { exec(query, ...bindings) {
    const values = bindings.map(value => value instanceof ArrayBuffer ? new Uint8Array(value) : value);
    const statement = db.prepare(query);
    if (statement.columns().length) {
      const rows = statement.all(...values); return { toArray: () => rows, [Symbol.iterator]: () => rows[Symbol.iterator]() };
    }
    statement.run(...values); return { toArray: () => [], [Symbol.iterator]: function* () {} };
  } }, transactionSync(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); db.exec('COMMIT'); return value; } catch (error) { db.exec('ROLLBACK'); throw error; }
  }, async setAlarm(time) { this.alarms.push(time); } };
}
async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'morse-public-snapshot-'));
  const path = join(directory, 'snapshot.sqlite');
  let current = storage(path);
  t.after(async () => { current.db.close(); await rm(directory, { recursive: true, force: true }); });
  const p = options.policy ?? await policy(); let clock = baseTime;
  let read = async request => ({ schema_version: 1, nonce: request.nonce, policy_sha256: p.policySha256,
    generator_sha256: p.generatorSha256, started_at_unix: String(clock), completed_at_unix: String(clock), report: atTime(clock) });
  let core = new PublicSnapshot(current, p, { now: () => clock, read: request => read(request), ...options });
  return { p, get core() { return core; }, get store() { return current; }, setRead(fn) { read = fn; }, setTime(value) { clock = value; },
    restart() { current.db.close(); current = storage(path); core = new PublicSnapshot(current, p, { now: () => clock, read: request => read(request), ...options }); },
    response(request, changes = {}) { return { schema_version: 1, nonce: request.nonce, policy_sha256: p.policySha256,
      generator_sha256: p.generatorSha256, started_at_unix: String(clock), completed_at_unix: String(clock), report: atTime(clock), ...changes }; } };
}

test('public policy requires exact config/build pins, normalized distinct origins and explicit fixture scope', async () => {
  await policy();
  const raw = JSON.stringify(configuration);
  await assert.rejects(snapshotPolicy({ configurationJson: raw, policySha256: '0'.repeat(64), generatorSha256: 'b'.repeat(64) }, { fixture: true }), /policy/);
  await assert.rejects(snapshotPolicy({ configurationJson: raw, policySha256: digest(raw), generatorSha256: 'b'.repeat(64) }), /fixture/);
  for (const endpoints of [
    ['http://127.0.0.1:19001', 'http://127.0.0.1:19001/', 'http://127.0.0.1:19003'],
    ['https://RPC.example', 'https://second.example', 'https://third.example'],
    ['https://first.example/path', 'https://second.example', 'https://third.example'],
    ['https://first.example', 'https://first.example', 'https://third.example'],
  ]) await assert.rejects(policy({ scope: endpoints[0].startsWith('https:') ? 'configured-rpc' : 'local-fixture', endpoints }));
});

test('last-good bytes and settled history survive restart; new failure makes current unavailable', async t => {
  const f = await fixture(t);
  assert.equal((await f.core.tick()).status, 'available');
  const first = await f.core.view();
  if (process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY) await writeFile(join(process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY, 'publication-accepted.json'), JSON.stringify(first, null, 2) + '\n');
  assert.deepEqual(first.current, report); assert.equal(first.settled_history.length, 1);
  assert.equal(first.provider_independence, 'not-established'); assert.equal(first.phase5_complete, false);
  f.restart(); assert.deepEqual((await f.core.view()).current, report);
  f.setTime(baseTime + 1); f.setRead(async () => { throw new Error('private transport diagnostics must not be published'); });
  const failed = await f.core.tick();
  if (process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY) await writeFile(join(process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY, 'publication-unavailable.json'), JSON.stringify(failed, null, 2) + '\n');
  assert.equal(failed.status, 'unavailable'); assert.equal(failed.current, null);
  assert.deepEqual(failed.last_good.report, report); assert.equal(failed.settled_history.length, 1);
  assert(!JSON.stringify(failed).includes('private transport'));
  f.restart(); assert.equal((await f.core.view()).current, null); assert.equal((await f.core.view()).settled_history.length, 1);
});

test('future/stale/rollback clocks, repeated observations and mismatched identities never create fresh healthy old data', async t => {
  const f = await fixture(t); await f.core.tick();
  f.setTime(baseTime + 1); await f.core.tick();
  assert.equal((await f.core.view()).settled_history.length, 1, 'repeat receipt is retained once');
  for (const [changes, status] of [
    [{ nonce: 'f'.repeat(64) }, 'identity-mismatch'],
    [{ policy_sha256: 'c'.repeat(64) }, 'identity-mismatch'],
    [{ generator_sha256: 'c'.repeat(64) }, 'identity-mismatch'],
    [{ completed_at_unix: String(baseTime + 100) }, 'future-clock'],
  ]) {
    f.setRead(async request => f.response(request, changes));
    const value = await f.core.tick(); assert.equal(value.status, status); assert.equal(value.current, null); assert.equal(value.settled_history.length, 1);
  }
  f.setRead(async request => { const response = f.response(request); response.report.history.proofs.pages[0].values.judge = section.mint; return response; });
  assert.equal((await f.core.tick()).status, 'identity-mismatch');
  f.setRead(async request => f.response(request)); f.setTime(baseTime + Number(report.max_age_seconds) + 1);
  assert.equal((await f.core.tick()).status, 'stale');
  f.setTime(baseTime); assert.equal((await f.core.tick()).status, 'clock-rollback');
  assert.equal((await f.core.view()).current, null);
});

test('whole-report disagreement/refusal preserves the known settled receipt without calling it current', async t => {
  const f = await fixture(t); await f.core.tick();
  for (const [availability, status] of [['disagreed', 'disagreed'], ['unavailable', 'unavailable']]) {
    f.setRead(async request => { const response = f.response(request); response.report.history.witnesses = { availability }; return response; });
    const value = await f.core.tick(); assert.equal(value.status, status); assert.equal(value.current, null); assert.equal(value.settled_history.length, 1);
  }
  f.setRead(async request => { const response = f.response(request); response.report.history.proofs.code_current = false; return response; });
  assert.equal((await f.core.tick()).status, 'code-changed');
});

for (const stage of ['afterReservation', 'afterRead']) test(`restart recovers an interrupted generation at ${stage}, without partially publishing`, async t => {
  let stop = false;
  const f = await fixture(t, { hooks: { [stage]() { if (stop) throw new Error('owned crash injection'); } } });
  await f.core.tick(); stop = true; await assert.rejects(f.core.tick(), /owned crash/);
  assert.equal((await f.core.view()).current, null); assert.deepEqual((await f.core.view()).last_good.report, report);
  assert(f.store.alarms.length, 'recovery alarm is set before I/O');
  f.restart(); assert.equal((await f.core.tick()).status, 'collecting');
  stop = false; f.setTime(baseTime + 601);
  const recovered = await f.core.tick(); assert.equal(recovered.status, 'available'); assert.equal(recovered.generation, 3);
  assert(recovered.observations.some(row => row.status === 'interrupted')); assert.equal(recovered.settled_history.length, 1);
});

test('overlapping work is serialized and an expired older read cannot commit over a newer generation', async t => {
  const f = await fixture(t); await f.core.tick();
  let release; let started;
  const pending = new Promise(resolve => { started = resolve; });
  f.setRead(async request => { started(); return new Promise(resolve => { release = () => resolve(f.response(request)); }); });
  const old = f.core.tick(); await pending;
  const busy = await f.core.tick(); assert.equal(busy.status, 'collecting');
  f.setTime(baseTime + 601); f.setRead(async request => f.response(request));
  const latest = await f.core.tick(); assert.equal(latest.generation, 3);
  release(); await old;
  assert.equal((await f.core.view()).generation, 3); assert.equal((await f.core.view()).status, 'available');
});

test('publication transaction rollback preserves previous bytes and capacity refusal never evicts settled history', async t => {
  let crash = false;
  const f = await fixture(t, { limits: { settled: 1, observations: 2 }, hooks: { beforeCommit() { if (crash) throw new Error('owned transaction fault'); } } });
  await f.core.tick(); crash = true;
  await assert.rejects(f.core.tick(), /owned transaction fault/);
  assert.deepEqual((await f.core.view()).last_good.report, report);
  f.setTime(baseTime + 601); crash = false;
  f.setRead(async request => {
    const value = f.response(request);
    // Synthetic transport-only capacity probe: this is not a chain-authentication fixture.
    value.report.history.proofs.pages[0].values.receipts.push({ ...value.report.history.proofs.pages[0].values.receipts[0], proof_hash: 'd'.repeat(64) });
    return value;
  });
  const refused = await f.core.tick();
  assert.equal(refused.status, 'capacity-refused'); assert.equal(refused.current, null);
  assert.equal(refused.settled_history.length, 1); assert.deepEqual(refused.last_good.report, report);
  assert(refused.observations.length <= 2); f.restart(); assert.equal((await f.core.view()).status, 'capacity-refused');
  f.setRead(async request => f.response(request));
  assert.equal((await f.core.tick()).status, 'capacity-refused', 'capacity requires explicit operator repair; old selection cannot hide refused new settlement');
});


test('burn history pages retain per-value policy, clock and completeness checks', async t => {
  const value = JSON.parse(await readFile(new URL('../public-chain/fixtures/burn-history-report.json', import.meta.url)));
  const bank = JSON.parse(await readFile(new URL('../public-chain/fixtures/history-token.json', import.meta.url)));
  const m = bank.metadata;
  const p = await policy({ legacy_collateral: undefined, pins: { program: m.program, governance: m.governance,
    program_slot: m.program_slot, usdc: m.usdc, treasury: m.treasury, factory: m.factory }, epochs: [m.epoch] });
  const f = await fixture(t, { policy: p }); f.setTime(Number(value.generated_at_unix));
  const response = request => f.response(request, { report: structuredClone(value) });
  f.setRead(async request => response(request)); assert.equal((await f.core.tick()).status, 'available');
  f.setRead(async request => { const r = response(request); r.report.burns[0] = { epoch: m.epoch, availability: 'not-configured' }; return r; });
  assert.equal((await f.core.tick()).status, 'unavailable');
  f.setRead(async request => { const r = response(request); r.report.history.burns.pages[0].values[0].program = m.usdc; return r; });
  assert.equal((await f.core.tick()).status, 'identity-mismatch');
  f.setRead(async request => { const r = response(request); r.report.history.burns.pages[0].values.pop(); return r; });
  assert.equal((await f.core.tick()).status, 'identity-mismatch');
  f.setRead(async request => { const r = response(request); r.report.history.burns.pages[0].values[0].source_time_unix = String(Number(value.generated_at_unix) + 1); return r; });
  assert.equal((await f.core.tick()).status, 'future-clock');
});


test('bounded selection changes retain settlements; policy rotation and corrupted last-good bytes cannot become current', async t => {
  const f = await fixture(t); await f.core.tick();
  f.setRead(async request => { const value = f.response(request);
    // Transport-only empty filtered-set probe; account/index validation remains native.
    const proofs = value.report.history.proofs; proofs.records = []; proofs.record_count = 0; proofs.pages = [];
    return value;
  });
  const next = await f.core.tick(); assert.equal(next.status, 'available'); assert.equal(next.current.history.proofs.record_count, 0);
  assert.equal(next.settled_history.length, 1, 'an empty later selection never erases an observed settlement');
  const other = new PublicSnapshot(f.store, { ...f.p, generatorSha256: 'c'.repeat(64) }, { now: () => baseTime, read() { throw new Error('must not read under mismatched stored policy'); } });
  assert.equal((await other.tick()).status, 'identity-mismatch'); assert.equal((await other.view()).settled_history.length, 1);
  f.store.sql.exec('UPDATE public_snapshot_chunks SET bytes=? WHERE ordinal=0', new Uint8Array([1, 2, 3]).buffer);
  const corrupted = await f.core.view(); assert.equal(corrupted.status, 'storage-unavailable'); assert.equal(corrupted.current, null);
  assert.equal(corrupted.settled_history.length, 1);
});

test('multi-chunk report bytes publish atomically; report byte-cap failure preserves the previous full artifact', async t => {
  const f = await fixture(t);
  f.setRead(async request => {
    // Opaque public transport padding exercises storage bounds without changing
    // financial fixture values or claiming another accepted account snapshot.
    const value = f.response(request); value.report.transport_fixture_padding = 'p'.repeat(120000); return value;
  });
  const good = await f.core.tick(); assert.equal(good.status, 'available');
  assert.equal(f.store.sql.exec('SELECT count(*) AS count FROM public_snapshot_chunks').toArray()[0].count, 3);
  f.restart(); assert.deepEqual((await f.core.view()).current, good.current);
  f.setRead(async request => { const value = f.response(request); value.report.transport_fixture_padding = 'p'.repeat(8388608); return value; });
  const refused = await f.core.tick(); assert.equal(refused.status, 'incomplete'); assert.equal(refused.current, null);
  assert.deepEqual(refused.last_good.report, good.current); assert.equal(refused.settled_history.length, 1);
});

test('required value pages cannot become healthy not-configured sections; legacy top-level sentinels cannot carry values or clocks', async t => {
  const f = await fixture(t); await f.core.tick();
  f.setRead(async request => { const value = f.response(request); value.report.history.proofs.pages[0].values = { availability: 'not-configured' }; return value; });
  assert.equal((await f.core.tick()).status, 'unavailable');
  assert.equal((await f.core.view()).current, null); assert.equal((await f.core.view()).settled_history.length, 1);
  for (const family of ['bonds', 'slashes']) for (const replacement of [
    { availability: 'available', source_time_unix: '1', code_current: true, receipts: [] },
    { availability: 'unavailable', reason: 'legacy-values-are-explicitly-versioned-in-history-pages', source_time_unix: '1' },
    { availability: 'not-configured' },
    undefined,
  ]) {
    f.setRead(async request => { const value = f.response(request); value.report[family] = replacement; return value; });
    const refused = await f.core.tick(); assert.equal(refused.status, 'identity-mismatch'); assert.equal(refused.current, null); assert.equal(refused.settled_history.length, 1);
  }
  f.setRead(async request => f.response(request)); assert.equal((await f.core.tick()).status, 'available', 'canonical legacy unavailable sentinels remain valid; clocks are checked on real history value pages');
  f.setRead(async request => { const value = f.response(request); value.report.history.proofs.pages[0].values.source_time_unix = '1'; return value; });
  assert.equal((await f.core.tick()).status, 'stale');
});

test('configured v2 top-level sections must be available, never not-configured', async t => {
  const report = JSON.parse(await readFile(new URL('../public-chain/fixtures/collateral-history-report.json', import.meta.url)));
  const s = report.bonds;
  const p = await policy({ legacy_collateral: undefined, epochs: [], pins: { program: s.token, usdc: s.usdc_mint },
    collateral: { judge: s.judge, rewards: s.rewards, morse_mint: s.morse_mint, log_name: s.log_name, service_public_key: s.service_public_key } });
  const f = await fixture(t, { policy: p }); f.setTime(Number(report.generated_at_unix));
  const response = request => f.response(request, { report: structuredClone(report) });
  f.setRead(async request => response(request)); assert.equal((await f.core.tick()).status, 'available');
  for (const family of ['bonds', 'slashes']) {
    f.setRead(async request => { const value = response(request); value.report[family] = { availability: 'not-configured' }; return value; });
    assert.equal((await f.core.tick()).status, 'unavailable'); assert.equal((await f.core.view()).current, null);
  }
});
