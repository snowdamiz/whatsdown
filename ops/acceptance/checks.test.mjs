import assert from 'node:assert/strict';
import test from 'node:test';
import {
  RING_LEN, addressFrom, encodeLog, encodeRingEntry, encodeRingHeader, encodeWitness, memoryChain, ringEntryOffset,
  rewardsAddresses, u64le,
} from '../cloudflare/judge.mjs';
import { parseSecurityConfig, runChecks } from './checks.mjs';

const key = n => n.toString(16).padStart(2, '0').repeat(32);
const addr = n => addressFrom(new Uint8Array(32).fill(n));
const JUDGE = addr(1);
const LOG = addr(2);
const RING = addr(3);
const REWARDS = addr(4);
const NOW = Date.UTC(2026, 8, 29, 12, 0, 0);
const frame = ({ anchor = `${JUDGE} ${LOG}`, witnesses = ['witness-a', 'witness-b', 'witness-c'], issuer = '-' } = {}) => [
  '2', key(1), key(2), '16', String(Math.floor(witnesses.length / 2) + 1), String(witnesses.length),
  ...witnesses.map((id, i) => `${id} ${key(10 + i)} Morse`),
  anchor, ...(anchor === '-' ? ['0'] : ['3', 'https://rpc-1.test', 'https://rpc-2.test', 'https://rpc-3.test']),
  '1', 'https://relay.test', issuer, 'morseapp.io/log/main', '2',
].join('\n');

// A fetch that answers from a table of URL -> {status, json | text}.
function fakeHttp(routes, calls = []) {
  return async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const route = routes[String(url)];
    if (!route) return new Response('not found', { status: 404 });
    if (route instanceof Error) throw route;
    return new Response(route.json === undefined ? route.text ?? '' : JSON.stringify(route.json), { status: route.status ?? 200 });
  };
}

const status = (operations = {}, extra = {}) => ({ log: 'morse-main', status: 'ok', cluster: 'mainnet-beta', generated_at: new Date(NOW).toISOString(),
  judge_program: JUDGE, log_account: { address: LOG }, slash_history: [], operations: { anchor_mode: 'mainnet', log: 'morse-main', ...operations }, ...extra });
const health = (extra = {}) => ({ status: 'ok', checkpoint_sequence: 9, tree_size: 40, pinned: 3, threshold: 2, threshold_met: true,
  witnesses: ['witness-a', 'witness-b', 'witness-c'].map(id => ({ witness_id: id, status: 'pinned', morse_run: true, signed_current: true,
    last_signature_age_seconds: 20 })), anchor_lag_seconds: 5, last_anchor_age_seconds: 30, last_pruning_day: '2026-09-29', ...extra });

function context({ env = {}, routes = {}, lines = [], chain = memoryChain(), config = frame(), ...rest } = {}) {
  const canaryCalls = [];
  return {
    env, directory: 'https://dir.test', config: config && parseSecurityConfig(config), now: () => NOW,
    http: fakeHttp({ 'https://dir.test/v1/network/status.json': { json: status() }, 'https://dir.test/v1/transparency/health': { json: health() },
      ...routes }),
    canary: (role, extra) => { canaryCalls.push({ role, extra }); return { done: Promise.resolve(lines) }; },
    canaryCalls, chain: () => chain, ...rest,
  };
}
const only = async (id, ctx) => (await runChecks([id], ctx))[0];

test('security config: the pinned set, anchor, providers and profile of a v2 frame', () => {
  const config = parseSecurityConfig(frame());
  assert.equal(config.k, 2);
  assert.equal(config.difficulty, 16);
  assert.deepEqual(config.witnesses.map(w => w.id), ['witness-a', 'witness-b', 'witness-c']);
  assert.deepEqual(config.anchor, { judge: JUDGE, log: LOG });
  assert.equal(config.rpc.length, 3);
  assert.equal(config.profile, 'Bootstrap');
  assert.equal(config.profileLine, 'Bootstrap: all 3 witnesses are run by Morse');
  assert.match(config.setId, /^[0-9a-f]{64}$/);
  assert.equal(parseSecurityConfig(frame({ anchor: '-' })).anchor, null);
});

test('lookup: every canary account verified passes; one failure fails naming it', async () => {
  const ok = n => ({ kind: 'lookup', round: 0, account: `morse-canary-${n}`, ok: true });
  let result = await only(1, context({ lines: [ok(1), ok(2), ok(3)] }));
  assert.equal(result.status, 'ok');
  assert.match(result.detail, /3 of 3/);
  result = await only(1, context({ lines: [ok(1), { ...ok(2), ok: false, error: 'transparency_verification_failed' }, ok(3)] }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /morse-canary-2: transparency_verification_failed/);
  result = await only(1, context({ lines: [{ kind: 'error', error: 'MORSE_CANARY_CONFIG is required' }] }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /MORSE_CANARY_CONFIG is required/);
});

test('phone check: off without an anchor, ok only with two providers answering', async () => {
  const anchor = (extra = {}) => ({ kind: 'anchor', outcome: 'ok', anchor_slot: 5, public_size: 40,
    rpc: [{ url: 'https://rpc-1.test/key', status: 200 }, { url: 'https://rpc-3.test', status: 200 }], ...extra });
  assert.equal((await only(4, context({ config: frame({ anchor: '-' }) }))).status, 'skip');
  const ctx = context({ lines: [anchor()] });
  const result = await only(4, ctx);
  assert.equal(result.status, 'ok');
  assert.match(result.detail, /rpc-1\.test, rpc-3\.test/);
  assert.doesNotMatch(result.detail, /key/, 'provider paths may hold API keys');
  assert.equal(ctx.canaryCalls[0].extra.MORSE_CANARY_ANCHOR, 'on');
  assert.equal((await only(4, context({ lines: [anchor({ rpc: [{ url: 'https://rpc-1.test', status: 200 }, { url: 'https://rpc-2.test', status: 0 }] })] }))).status, 'fail');
  assert.equal((await only(4, context({ lines: [anchor({ outcome: 'stale' })] }))).status, 'fail');
});

test('lookup and phone check share one canary run', async () => {
  const ctx = context({ lines: [{ kind: 'lookup', account: 'morse-canary-1', ok: true }] });
  await runChecks([1, 4], ctx);
  assert.equal(ctx.canaryCalls.length, 1);
});

// A ring whose entries landed `latency` seconds after their checkpoint, every `every` seconds.
function ringChain(entries) {
  const chain = memoryChain();
  chain.set(LOG, encodeLog({ serviceKey: new Uint8Array(32).fill(1), ring: RING }), JUDGE);
  const ring = new Uint8Array(RING_LEN);
  ring.set(encodeRingHeader({ head: entries.length, count: entries.length }), 0);
  entries.forEach(({ ageS, latencyS, evidence = 0 }, i) => {
    const slot = 1000n + BigInt(i);
    const landed = Math.floor(NOW / 1000) - ageS;
    ring.set(encodeRingEntry({ sequence: BigInt(i + 1), treeSize: BigInt(i + 1), root: new Uint8Array(32), checkpointHash: new Uint8Array(32).fill(i),
      timestampMs: BigInt((landed - latencyS) * 1000), slot, evidence }), ringEntryOffset(i));
    chain.times.set(slot, landed);
  });
  chain.set(RING, ring, JUDGE);
  return chain;
}

test('anchoring: skipped while off; hourly heartbeats and fast anchors pass', async () => {
  const off = context({ routes: { 'https://dir.test/v1/network/status.json': { json: status({ anchor_mode: 'off' }) } } });
  assert.equal((await only(3, off)).status, 'skip');
  const good = [{ ageS: 3500, latencyS: 3 }, { ageS: 1800, latencyS: 65 }, { ageS: 60, latencyS: 4 }];
  assert.equal((await only(3, context({ chain: ringChain(good) }))).status, 'ok');
});

test('anchoring: a slow anchor, a missed heartbeat or a lagging directory fails', async () => {
  let result = await only(3, context({ chain: ringChain([{ ageS: 3000, latencyS: 3 }, { ageS: 60, latencyS: 200 }]) }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /200 s/);
  result = await only(3, context({ chain: ringChain([{ ageS: 7000, latencyS: 3 }, { ageS: 60, latencyS: 3 }]) }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /no anchor for/);
  result = await only(3, context({ chain: ringChain([{ ageS: 60, latencyS: 3 }]),
    routes: { 'https://dir.test/v1/transparency/health': { json: health({ anchor_lag_seconds: 120 }) } } }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /lag 120 s/);
  // A ring evidence entry is not an anchor.
  assert.equal((await only(3, context({ chain: ringChain([{ ageS: 3000, latencyS: 3 }, { ageS: 90, latencyS: 900, evidence: 1 }, { ageS: 60, latencyS: 3 }]) }))).status, 'ok');
});

test('monitor: status page and --once both judge inconsistencies and staleness', async () => {
  const monitor = extra => ({ 'https://monitor.test/status.json': { json: { ok: true, inconsistencies: 0, updated_at_ms: NOW - 60_000,
    last_verified_pair: { new_sequence: 9 }, pending_entries: 0, findings: [], ...extra } } });
  const env = { MORSE_MONITOR_STATUS_URL: 'https://monitor.test/status.json' };
  assert.equal((await only(5, context({ env, routes: monitor() }))).status, 'ok');
  let result = await only(5, context({ env, routes: monitor({ ok: false, inconsistencies: 1, findings: [{ severity: 'P0', kind: 'fork_kind_1', detail: 'x' }] }) }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /fork_kind_1/);
  assert.equal((await only(5, context({ env, routes: monitor({ updated_at_ms: NOW - 3_600_000 }) }))).status, 'fail');
  const runs = [];
  const monitorOnce = async args => { runs.push(args); return { code: 2, output: 'P0 morse-monitor morse-main fork_kind_2: leaf 7' }; };
  result = await only(5, context({ env: { MORSE_MONITOR_BIN: '/bin/morse-monitor', MORSE_MONITOR_STATE: '/tmp/m.sqlite' }, monitorOnce }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /fork_kind_2/);
  assert.ok(runs[0].includes('--once') && runs[0].includes('--state'));
  assert.equal((await only(5, context())).status, 'fail', 'anchoring is on but no monitor is configured');
  assert.equal((await only(5, context({ routes: { 'https://dir.test/v1/network/status.json': { json: status({ anchor_mode: 'off' }) } } }))).status, 'skip');
});

const forkEnv = { MORSE_FORK_DRILL: 'on', MORSE_CANARY_RPC: 'https://canary-rpc.test', MORSE_CANARY_JUDGE: JUDGE, MORSE_CANARY_SERVICE_SEED_HEX: key(5),
  MORSE_CANARY_WITNESS: 't3', MORSE_CANARY_WITNESS_SEED_HEX: key(6), MORSE_CANARY_ANCHOR_KEYPAIR: '[1]', MORSE_CANARY_PAYER_KEYPAIR: '[2]',
  MORSE_CANARY_RELAY: 'https://relay.test' };

test('fork drill: only when enabled, never on a canary log a drill already slashed', async () => {
  assert.equal((await only(6, context())).status, 'skip');
  const drills = [];
  const forkDrill = async options => { drills.push(options); return { proof: 'ab', proofAccount: addr(9), serviceSlashed: true, witnesses: [{ id: 't3', status: 'Slashed' }], payee: null }; };
  const canaryLog = serviceSlashed => async () => ({ serviceSlashed });
  let result = await only(6, context({ env: forkEnv, forkDrill, canaryLog: canaryLog(true) }));
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /re-provision/);
  assert.equal(drills.length, 0);
  result = await only(6, context({ env: forkEnv, forkDrill, canaryLog: canaryLog(false) }));
  assert.equal(result.status, 'ok');
  assert.equal(drills[0].log, 'morse-canary');
  assert.equal(drills[0].relay.url, 'https://relay.test');
  const { MORSE_CANARY_PAYER_KEYPAIR, ...missing } = forkEnv;
  assert.match((await only(6, context({ env: missing, forkDrill, canaryLog: canaryLog(false) }))).detail, /MORSE_CANARY_PAYER_KEYPAIR/);
});

// morse-rewards accounts (morse-judge-v1.md §10): the config names LOG, whose
// one witness is Morse's (excluded); the epoch account as settle_epoch left it.
async function rewardsChain({ epoch, settledAtS, allocations = [], budget = 5_000_000n, allocated = 0n }) {
  const chain = memoryChain();
  const at = rewardsAddresses(REWARDS);
  const config = new Uint8Array(904);
  config[0] = 1; config[1] = 1;
  config.set(new Uint8Array(32).fill(2), 72);
  chain.set(await at.config(), config, REWARDS);
  const witnessAccount = addr(20);
  chain.set(LOG, encodeLog({ serviceKey: new Uint8Array(32).fill(1), witnesses: [{ id: 'witness-a', key: new Uint8Array(32).fill(3), account: witnessAccount }] }), JUDGE);
  chain.set(witnessAccount, encodeWitness({ id: 'witness-a', key: new Uint8Array(32).fill(3), excluded: true }), JUDGE);
  if (settledAtS !== null) {
    const data = new Uint8Array(1320);
    data[0] = 2; data[1] = 1; data[3] = allocations.length;
    data.set(u64le(epoch), 8); data.set(u64le(budget), 16); data.set(u64le(allocated), 24);
    allocations.forEach((account, i) => { data.set(new Uint8Array(32).fill(account), 40 + 80 * i); data.set(u64le(1n), 40 + 80 * i + 64); });
    chain.set(await at.epoch(epoch), data, REWARDS);
  }
  chain.signaturesFor = async () => settledAtS === null ? [] : [{ signature: 'sig', slot: 1n, err: null, blockTime: settledAtS }];
  return chain;
}

test('rewards: the due epoch settled within an hour with everything carried over', async () => {
  assert.equal((await only(7, context())).status, 'skip', 'no rewards program configured');
  const epoch = Math.floor((NOW / 1000 - 3600) / 604800) - 1;
  const boundary = (epoch + 1) * 604800;
  const run = async options => only(7, context({ env: { MORSE_REWARDS_PROGRAM: REWARDS }, chain: await rewardsChain({ epoch, ...options }) }));
  let result = await run({ settledAtS: boundary + 900 });
  assert.equal(result.status, 'ok');
  assert.match(result.detail, /5000000 of 5000000 carried over/);
  assert.equal((await run({ settledAtS: boundary + 7200 })).status, 'fail');
  assert.equal((await run({ settledAtS: null })).status, 'fail');
  result = await run({ settledAtS: boundary + 900, allocations: [20], allocated: 1n });
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /excluded or inactive/);
});

test('credits: not live without an issuer, driven only when live and enabled', async () => {
  let result = await only(8, context());
  assert.equal(result.status, 'skip');
  assert.match(result.detail, /credits not live/);
  const issuer = mode => ({ 'https://issuer.test/health': { json: { mode, current_key: true } } });
  const env = { MORSE_CREDIT_ISSUER_HEALTH_URL: 'https://issuer.test/health' };
  result = await only(8, context({ env, config: frame({ issuer: 'https://credits.test' }), routes: issuer('off') }));
  assert.equal(result.status, 'skip');
  assert.match(result.detail, /credits not live/);
  result = await only(8, context({ env, config: frame({ issuer: 'https://credits.test' }), routes: issuer('live') }));
  assert.equal(result.status, 'skip');
  assert.match(result.detail, /MORSE_CREDITS_DRILL/);
  const drives = [];
  const creditsDrill = async options => { drives.push(options); return { ok: true, detail: 'bought 1 pack, redeemed 1 of 1 extras', redemptions: [{ extra: 'postage', status: 201, ms: 40 }] }; };
  result = await only(8, context({ env: { ...env, MORSE_CREDITS_DRILL: 'on' }, config: frame({ issuer: 'https://credits.test' }), routes: issuer('live'), creditsDrill }));
  assert.equal(result.status, 'ok');
  assert.equal(drives.length, 1);
  assert.deepEqual(drives[0], { issuer: 'https://credits.test', difficulty: 16 });
  assert.deepEqual(result.measurements, { redemptions: [{ extra: 'postage', status: 201, ms: 40 }] });
});

test('outage tolerance: needs a spare witness, then drills this week\'s Morse witness', async () => {
  assert.equal((await only(2, context({ config: frame({ witnesses: ['witness-a', 'witness-b'] }) }))).status, 'skip');
  const drills = [];
  const outageDrill = async options => { drills.push(options); return { ok: true, detail: 'fine', evidence: [] }; };
  const targets = { 'witness-a': { cloudflare: { account: 'acct', script: 'morse-witness-a' } }, 'witness-c': { stop: 'x', start: 'y' } };
  assert.equal((await only(2, context({ outageDrill }))).status, 'fail', 'no drill targets configured');
  const result = await only(2, context({ env: { MORSE_DRILL_WITNESSES: JSON.stringify(targets) }, outageDrill }));
  assert.equal(result.status, 'ok');
  assert.ok(['witness-a', 'witness-c'].includes(drills[0].witness));
  assert.deepEqual(drills[0].target, targets[drills[0].witness]);
  await only(2, context({ env: { MORSE_DRILL_WITNESSES: JSON.stringify(targets), MORSE_DRILL_WITNESS: 'witness-c' }, outageDrill }));
  assert.equal(drills[1].witness, 'witness-c');
});

test('a check that throws is a failure, not a crash', async () => {
  const ctx = context({ chain: { account: async () => { throw new Error('rpc down'); } } });
  const [result] = await runChecks([3], ctx);
  assert.equal(result.status, 'fail');
  assert.match(result.detail, /rpc down/);
  assert.equal(result.id, 3);
  assert.equal(result.name, 'anchoring');
});
