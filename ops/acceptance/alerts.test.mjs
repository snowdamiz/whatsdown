import assert from 'node:assert/strict';
import test from 'node:test';
import { collect, evaluate, notify } from './alerts.mjs';

const NOW = Date.UTC(2026, 8, 29, 12, 0, 0);
const SOL = 1_000_000_000;
const witnesses = (ages = {}) => ['witness-a', 'witness-b', 'witness-c'].map(id => ({ witness_id: id, status: 'pinned', morse_run: id !== 'witness-c',
  signed_current: (ages[id] ?? 20) < 60, last_signature_age_seconds: ages[id] === undefined ? 20 : ages[id] }));
const directory = (extra = {}) => ({ status: 'ok', checkpoint_sequence: 9, tree_size: 1000, pinned: 3, threshold: 2, threshold_met: true,
  witnesses: witnesses(), anchor_lag_seconds: 5, last_anchor_age_seconds: 40, last_pruning_day: '2026-09-29', ...extra });
// Snapshots as the sources would serve them at `at`.
const network = (operations = {}, extra = {}, at = NOW) => ({ log: 'morse-main', status: 'ok', generated_at: new Date(at - 30_000).toISOString(), stale: false,
  last_public_checkpoint: { time: new Date(at - 600_000).toISOString(), age_seconds: 600 }, slash_history: [],
  operations: { anchor_mode: 'mainnet', log: 'morse-main', fee_payer: { lamports: String(SOL / 2), level: 'ok' }, settled_epoch: 2939, burns: [], pages: [], ...operations },
  ...extra });
const healthy = (extra = {}, at = NOW) => ({ at, directory: directory(), network: network({}, {}, at), backend: { status: 200 }, lines: [], results: [], ...extra });

// Evaluates once; `state` carries over between calls like the state file.
const run = (signals, state = {}, at = NOW, contacts = {}) => evaluate(signals, { state, now: at, contacts });
const keys = out => out.notify.map(a => `${a.severity} ${a.key} -> ${a.recipients.join(',')}`).sort();

test('a healthy network raises nothing', () => {
  assert.deepEqual(run(healthy()).notify, []);
});

test('threshold not met pages Morse after 2 minutes, not before', () => {
  const signals = healthy({ directory: directory({ threshold_met: false }) });
  let out = run(signals);
  assert.deepEqual(out.notify, []);
  out = run({ ...signals, at: NOW + 119_000 }, out.state, NOW + 119_000);
  assert.deepEqual(out.notify, []);
  out = run({ ...signals, at: NOW + 120_000 }, out.state, NOW + 120_000);
  assert.deepEqual(keys(out), ['page threshold_not_met -> morse']);
});

test('a silent witness pages its operator at 10 minutes and Morse at 30', () => {
  const contacts = { operators: { 'witness-c': [{ format: 'json', url: 'https://c.test/hook' }] } };
  assert.deepEqual(run(healthy({ directory: directory({ witnesses: witnesses({ 'witness-c': 599 }) }) }), {}, NOW, contacts).notify, []);
  let out = run(healthy({ directory: directory({ witnesses: witnesses({ 'witness-c': 600 }) }) }), {}, NOW, contacts);
  assert.deepEqual(keys(out), ['page witness_silent:witness-c -> operator:witness-c']);
  out = run(healthy({ directory: directory({ witnesses: witnesses({ 'witness-c': 1800 }) }) }), out.state, NOW + 60_000, contacts);
  assert.deepEqual(keys(out), ['page witness_silent:witness-c -> operator:witness-c,morse'], 'escalates to Morse');
  // Morse's own witness: Morse is its operator.
  out = run(healthy({ directory: directory({ witnesses: witnesses({ 'witness-a': 700 }) }) }), {}, NOW, contacts);
  assert.deepEqual(keys(out), ['page witness_silent:witness-a -> operator:witness-a']);
  // During the outage drill the stopped witness is expected to be silent.
  out = run(healthy({ directory: directory({ witnesses: witnesses({ 'witness-a': 700 }) }), suppress: [{ witness_id: 'witness-a', until_ms: NOW + 60_000 }] }));
  assert.deepEqual(out.notify, []);
});

test('a witness that never signed counts as silent from when it was first seen', () => {
  const signals = healthy({ directory: directory({ witnesses: [...witnesses(), { witness_id: 'acme-1', status: 'shadow', morse_run: false,
    signed_current: false, last_signature_age_seconds: null }] }) });
  let out = run(signals);
  assert.deepEqual(out.notify, []);
  out = run({ ...signals, network: network({}, {}, NOW + 600_000) }, out.state, NOW + 600_000);
  assert.deepEqual(keys(out), ['page witness_silent:acme-1 -> operator:acme-1']);
});

test('anchor gap pages at 60 minutes only while anchoring is on', () => {
  const gap = seconds => healthy({ network: network({}, { last_public_checkpoint: { time: new Date(NOW - seconds * 1000).toISOString(), age_seconds: 1 } }),
    directory: directory({ last_anchor_age_seconds: seconds }) });
  assert.deepEqual(run(gap(3599)).notify, []);
  assert.deepEqual(keys(run(gap(3600))), ['page anchor_gap -> morse']);
  assert.deepEqual(run({ ...gap(7200), network: network({ anchor_mode: 'off' }) }).notify, []);
});

test('fee payer warns under 0.2 SOL and pages under 0.05 SOL', () => {
  const fee = lamports => healthy({ network: network({ fee_payer: { lamports: String(lamports) } }) });
  assert.deepEqual(run(fee(0.21 * SOL)).notify, []);
  assert.deepEqual(keys(run(fee(0.19 * SOL))), ['warn fee_payer -> morse']);
  assert.deepEqual(keys(run(fee(0.049 * SOL))), ['page fee_payer -> morse']);
});

test('a monitor inconsistency is P0 for Morse and every operator; a stuck monitor warns', () => {
  const monitor = extra => healthy({ monitor: { ok: true, inconsistencies: 0, updated_at_ms: NOW - 60_000, findings: [], ...extra } });
  assert.deepEqual(run(monitor()).notify, []);
  assert.deepEqual(keys(run(monitor({ ok: false, inconsistencies: 1, findings: [{ severity: 'P0', kind: 'fork_kind_1', detail: 'd' }] }))),
    ['P0 monitor_inconsistency -> morse,operators']);
  assert.deepEqual(keys(run(monitor({ updated_at_ms: NOW - 11 * 60_000 }))), ['warn monitor_stuck -> morse']);
});

test('relay P0 lines: fork evidence to everyone, a substituted payee to that relay\'s operator', () => {
  const lines = [
    { source: 'relay:https://relay.test', line: 'P0 fork_evidence_received log=morse-main kind=1 proof=ab12' },
    { source: 'relay:https://relay.test', line: 'P0 relay_finder_mismatch proof=cd34 expected=AAA paid=BBB' },
  ];
  let out = run(healthy({ lines }));
  assert.deepEqual(keys(out), ['P0 fork_evidence:ab12 -> morse,operators', 'P0 relay_finder_mismatch:cd34 -> relay:https://relay.test,morse']);
  out = run(healthy({ lines }), out.state, NOW + 60_000);
  assert.deepEqual(out.notify, [], 'a line is an event: told once');
  assert.deepEqual(out.resolved, [], 'and never resolved');
});

test('jobs Worker lines: burn slippage and failed chunks warn, settle_epoch late warns', () => {
  const lines = ['WARN burn_slippage chunk=5 expected=100 received=97 tx=x', 'WARN burn_chunk_failed chunk=5', 'WARN settle_epoch_late epoch=2940']
    .map(line => ({ source: 'jobs', line }));
  assert.deepEqual(keys(run(healthy({ lines }))).map(k => k.split(' ')[0]), ['warn', 'warn', 'warn']);
});

test('credits: issuer errors, spent-set failures and slow redemptions page Morse', () => {
  assert.deepEqual(keys(run(healthy({ issuer: { error: 'issuer answered 503', httpStatus: 503 } }))), ['page credits_issuer -> morse']);
  assert.deepEqual(run(healthy({ issuer: { mode: 'off', current_key: false } })).notify, []);
  const credits = redemptions => healthy({ results: [{ id: 8, name: 'credits', status: 'ok', detail: 'x', measurements: { redemptions } }] });
  assert.deepEqual(run(credits([{ extra: 'postage', status: 201, ms: 120 }])).notify, []);
  assert.deepEqual(keys(run(credits([{ extra: 'postage', status: 503, ms: 30 }]))), ['page credits_spent_set -> morse']);
  assert.deepEqual(keys(run(credits(Array.from({ length: 20 }, (_, i) => ({ extra: 'postage', status: 201, ms: i < 18 ? 100 : 900 }))))),
    ['page credits_latency -> morse'], 'p95 over 500 ms');
  // The weekly drill's result stands until the next drill, not the next 5-minute run.
  const out = run(credits([{ extra: 'postage', status: 503, ms: 30 }]));
  assert.deepEqual(run(healthy(), out.state, NOW + 300_000).resolved, []);
});

test('settle_epoch not run an hour after the boundary warns (when rewards are configured)', () => {
  const due = Math.floor((NOW / 1000 - 3600) / 604800) - 1;
  assert.deepEqual(run(healthy({ rewardsConfigured: true, network: network({ settled_epoch: due }) })).notify, []);
  assert.deepEqual(keys(run(healthy({ rewardsConfigured: true, network: network({ settled_epoch: due - 1 }) }))), [`warn settle_epoch_late:${due} -> morse`]);
  assert.deepEqual(run(healthy({ network: network({ settled_epoch: null }) })).notify, []);
});

test('bond counter: a snapshot over 5 minutes old, or providers disagreeing, warns', () => {
  assert.deepEqual(keys(run(healthy({ network: network({}, { generated_at: new Date(NOW - 301_000).toISOString() }) }))), ['warn bond_counter_stale -> morse']);
  assert.deepEqual(keys(run(healthy({ network: { ...network(), status: 'unavailable', reason: 'rpc_disagree' } }))), ['warn bond_counter -> morse']);
});

test('pruning 2 days behind, 20% monthly database growth and 8M leaves warn', () => {
  assert.deepEqual(run(healthy({ directory: directory({ last_pruning_day: '2026-09-28' }) })).notify, []);
  assert.deepEqual(keys(run(healthy({ directory: directory({ last_pruning_day: '2026-09-27' }) }))), ['warn pruning -> morse']);
  const sized = (bytes, at) => run(healthy({ database: { bytes } }, at), out?.state ?? {}, at);
  let out;
  out = sized(1_000_000, NOW - 30 * 86_400_000);
  out = sized(1_150_000, NOW);
  assert.deepEqual(out.notify, []);
  out = sized(1_250_000, NOW + 3_600_000);
  assert.deepEqual(keys(out), ['warn database_growth -> morse']);
  assert.deepEqual(run(healthy({ directory: directory({ tree_size: 7_999_999 }) })).notify, []);
  assert.deepEqual(keys(run(healthy({ directory: directory({ tree_size: 8_000_000 }) }))), ['warn log_size -> morse']);
});

test('a failed acceptance check pages Morse until the check passes again', () => {
  const failed = { id: 1, name: 'lookup', status: 'fail', detail: 'morse-canary-2: resolve_status_503' };
  let out = run(healthy({ results: [failed] }));
  assert.deepEqual(keys(out), ['page acceptance:1 -> morse']);
  out = run(healthy(), out.state, NOW + 300_000);
  assert.deepEqual(out.resolved, [], 'a run without that check changes nothing');
  out = run(healthy({ results: [{ ...failed, status: 'ok' }] }), out.state, NOW + 3_600_000);
  assert.deepEqual(out.resolved.map(a => a.key), ['acceptance:1']);
});

test('dedup: repeats pages hourly, re-notifies on escalation, resolves once cleared', () => {
  let out = {};
  const low = (lamports, at) => (out = run(healthy({ network: network({ fee_payer: { lamports: String(lamports) } }, {}, at) }, at), out.state, at));
  low(0.1 * SOL, NOW);
  assert.equal(out.notify.length, 1);
  low(0.1 * SOL, NOW + 600_000);
  assert.equal(out.notify.length, 0);
  low(0.01 * SOL, NOW + 700_000);
  assert.deepEqual(keys(out), ['page fee_payer -> morse']);
  low(0.01 * SOL, NOW + 700_000 + 3_600_000);
  assert.equal(out.notify.length, 1, 'a page repeats hourly');
  low(SOL, NOW + 5 * 3_600_000);
  assert.deepEqual(out.resolved.map(a => a.key), ['fee_payer']);
});

test('the backend and directory being unreachable page after 2 minutes', () => {
  let out = run(healthy({ backend: { status: 0, error: 'fetch failed' }, directory: { error: 'dir.test: fetch failed' } }));
  out = run(healthy({ backend: { status: 0, error: 'fetch failed' }, directory: { error: 'dir.test: fetch failed' } }), out.state, NOW + 120_000);
  assert.deepEqual(keys(out), ['page backend_unreachable -> morse', 'page directory_unreachable -> morse']);
});

test('notify: each format\'s body, operators by contact, Morse when an operator has none', async () => {
  const sent = [];
  const http = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('{}'); };
  const contacts = { morse: [{ format: 'pagerduty', routing_key: 'rk' }], operators: { 'witness-c': [{ format: 'discord', url: 'https://discord.test/c' }] },
    relays: { 'https://relay.test': [{ format: 'slack', url: 'https://slack.test/r' }] } };
  const env = { MORSE_ALERT_WEBHOOK: 'https://hooks.slack.com/services/x', MORSE_ALERT_FORMAT: 'slack' };
  await notify({
    notify: [
      { key: 'witness_silent:witness-c', severity: 'page', recipients: ['operator:witness-c'], summary: 'witness-c silent 11 min' },
      { key: 'witness_silent:acme-1', severity: 'page', recipients: ['operator:acme-1'], summary: 'acme-1 silent' },
      { key: 'relay_finder_mismatch:cd', severity: 'P0', recipients: ['relay:https://relay.test', 'morse'], summary: 'paid BBB' },
    ],
    resolved: [{ key: 'fee_payer', severity: 'page', recipients: ['morse'], summary: 'fee payer low' }],
  }, { contacts, env, http });
  const to = url => sent.filter(s => s.url === url).map(s => s.body);
  assert.match(to('https://discord.test/c')[0].content, /\[page\] witness-c silent 11 min/);
  const pager = to('https://events.pagerduty.com/v2/enqueue');
  assert.deepEqual(pager.map(b => [b.event_action, b.dedup_key, b.payload?.severity]),
    [['trigger', 'witness_silent:acme-1', 'error'], ['trigger', 'relay_finder_mismatch:cd', 'critical'], ['resolve', 'fee_payer', undefined]]);
  assert.match(to('https://hooks.slack.com/services/x')[0].text, /acme-1 silent.*no contact for operator:acme-1/);
  assert.match(to('https://slack.test/r')[0].text, /\[P0\] paid BBB/);
});

test('collect: unreachable sources become errors, log lines keep their source', async () => {
  const http = async url => {
    if (url.endsWith('/v1/transparency/health')) throw new Error('fetch failed');
    if (url.endsWith('/health')) return new Response('unavailable', { status: 503 });
    return new Response(JSON.stringify(network()));
  };
  const signals = await collect({ env: { MORSE_DIRECTORY_URL: 'https://dir.test' }, http, now: NOW,
    logs: [{ source: 'relay:https://relay.test', text: 'info line\nP0 fork_evidence_received log=morse-main kind=1 proof=ab\n' }] });
  assert.match(signals.directory.error, /fetch failed/);
  assert.equal(signals.backend.status, 503);
  assert.equal(signals.network.log, 'morse-main');
  assert.deepEqual(signals.lines, [{ source: 'relay:https://relay.test', line: 'P0 fork_evidence_received log=morse-main kind=1 proof=ab' }]);
});
