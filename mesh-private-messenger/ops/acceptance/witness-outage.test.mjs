import assert from 'node:assert/strict';
import test from 'node:test';
import { outageDrill, startWitness, stopWitness } from './witness-outage.mjs';

const ids = ['witness-a', 'witness-b', 'witness-c'];
const health = ({ stopped = null, threshold = true, lagging = [] } = {}) => ({
  threshold_met: threshold, threshold: 2, pinned: 3,
  witnesses: ids.map(id => ({ witness_id: id, status: 'pinned', morse_run: true,
    signed_current: id !== stopped && !lagging.includes(id), last_signature_age_seconds: id === stopped ? 900 : 20 })),
});

// A drill against fakes: a clock that sleeps instantly, a witness that is up or
// down, the directory's health as a function of that, and a canary watch.
function harness({ lookups = () => true, catchUp = true, before = null, during = null, statusCode = 0 } = {}) {
  let clock = Date.UTC(2026, 8, 29, 10);
  let down = false;
  let restartedAt = null;
  const calls = [];
  const lines = [{ kind: 'lookup', round: 0, ok: true }];
  let round = 0;
  const exec = async command => {
    calls.push(command);
    if (command === 'stop-c') down = true;
    if (command === 'start-c') { down = false; restartedAt = clock; }
    return { code: command === 'status-c' ? statusCode : 0, output: '' };
  };
  return {
    calls, lines,
    options: {
      witness: 'witness-c', target: { stop: 'stop-c', start: 'start-c', status: 'status-c' }, minutes: 15, exec,
      now: () => clock,
      sleep: async ms => { clock += ms; if (down) { round += 1; lines.push({ kind: 'lookup', round, ok: lookups(round) }); } },
      health: async () => {
        if (before && !down && restartedAt === null) return before;
        if (down) return during ?? health({ stopped: 'witness-c' });
        return catchUp || clock - restartedAt > 3_600_000 ? health() : health({ lagging: ['witness-c'] });
      },
      watch: () => ({ lines: () => lines, done: new Promise(() => {}), stop: async () => lines }),
      say: () => {},
    },
  };
}

test('outage drill: lookups keep verifying while one witness is down, and it catches up', async () => {
  const h = harness();
  const report = await outageDrill(h.options);
  assert.equal(report.ok, true, report.detail);
  assert.deepEqual(h.calls, ['stop-c', 'start-c', 'status-c']);
  assert.match(report.detail, /lookups verified/);
  assert.match(report.detail, /caught up/);
  assert.ok(h.lines.length >= 15, 'a lookup every minute of the window');
});

test('outage drill: a failed lookup during the window fails it, and the witness still comes back', async () => {
  const h = harness({ lookups: round => round !== 4 });
  const report = await outageDrill(h.options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /1 of \d+ lookups failed/);
  assert.ok(h.calls.includes('start-c'));
});

test('outage drill: the threshold must hold while the witness is down', async () => {
  const report = await outageDrill(harness({ during: health({ stopped: 'witness-c', threshold: false }) }).options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /threshold not met/);
});

test('outage drill: a checkpoint read seconds before its signatures land is not a missed threshold', async () => {
  const h = harness();
  let reads = 0;
  const health = h.options.health;
  h.options.health = async () => {
    const value = await health();
    // While witness-c is down, every third read catches a fresh, not yet signed checkpoint.
    return value.witnesses.find(w => w.witness_id === 'witness-c').signed_current || ++reads % 3 ? value : { ...value, threshold_met: false };
  };
  const report = await outageDrill(h.options);
  assert.equal(report.ok, true, report.detail);
});

test('outage drill: a witness that does not catch up, or reports a halt, fails', async () => {
  let report = await outageDrill(harness({ catchUp: false }).options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /did not sign the current checkpoint within 10 min/);
  report = await outageDrill(harness({ statusCode: 3 }).options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /status check exited 3/);
});

test('outage drill: never starts when the network is not healthy first', async () => {
  let h = harness({ before: health({ lagging: ['witness-c'] }) });
  let report = await outageDrill(h.options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /witness-c is not signing/);
  assert.deepEqual(h.calls, []);
  h = harness({ before: health({ lagging: ['witness-a'] }) });
  report = await outageDrill(h.options);
  assert.match(report.detail, /would leave 1 of 2/);
  assert.deepEqual(h.calls, []);
});

test('cloudflare witnesses stop and start through the workers.dev switch', async () => {
  const requests = [];
  const http = async (url, init) => { requests.push({ url, init }); return new Response(JSON.stringify({ success: true, result: {} })); };
  const target = { cloudflare: { account: 'acct1', script: 'morse-witness-a' } };
  await stopWitness(target, { http, token: 'tok' });
  await startWitness(target, { http, token: 'tok' });
  assert.equal(requests[0].url, 'https://api.cloudflare.com/client/v4/accounts/acct1/workers/scripts/morse-witness-a/subdomain');
  assert.equal(requests[0].init.method, 'POST');
  assert.equal(requests[0].init.headers.Authorization, 'Bearer tok');
  assert.deepEqual(JSON.parse(requests[0].init.body), { enabled: false, previews_enabled: false });
  assert.deepEqual(JSON.parse(requests[1].init.body), { enabled: true, previews_enabled: false });
  const refusing = async () => new Response(JSON.stringify({ success: false, errors: [{ message: 'Authentication error' }] }), { status: 403 });
  await assert.rejects(stopWitness(target, { http: refusing, token: 'tok' }), /Authentication error/);
  await assert.rejects(stopWitness(target, { http, token: '' }), /CLOUDFLARE_API_TOKEN/);
});

test('outage drill: a stop that fails restores the witness and reports it', async () => {
  const h = harness();
  h.options.exec = async command => { h.calls.push(command); return { code: command === 'stop-c' ? 1 : 0, output: 'ssh: timeout' }; };
  const report = await outageDrill(h.options);
  assert.equal(report.ok, false);
  assert.match(report.detail, /stopping witness-c failed/);
  assert.deepEqual(h.calls, ['stop-c', 'start-c']);
});
