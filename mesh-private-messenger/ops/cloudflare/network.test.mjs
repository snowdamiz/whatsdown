import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { HOURLY_CRON, MINUTE_CRON, NetworkCore, networkConfig, networkHealth, networkRoute } from './network.mjs';
import { concat, ed25519FromSeed } from './judge.mjs';
import { judge, judgeChain, ktk } from './test-chain.mjs';

test('the jobs Worker and the relay share one judge client', () => {
  assert.equal(readFileSync(new URL('./judge.mjs', import.meta.url), 'utf8'), readFileSync(new URL('../relay/judge.mjs', import.meta.url), 'utf8'),
    'copy ops/relay/judge.mjs to ops/cloudflare/judge.mjs after changing it');
});

test('network flags default to off and chain settings are checked per mode', () => {
  assert.deepEqual(networkConfig({}), { mode: 'off', logName: 'morse-main' });
  assert.throws(() => networkConfig({ MORSE_ANCHOR_MODE: 'on' }), /off, devnet or mainnet/);
  assert.throws(() => networkConfig({ MORSE_ANCHOR_MODE: 'devnet' }), /MORSE_CHAIN_DEVNET/);
  assert.throws(() => networkConfig({ MORSE_COSIGN_CRANK: 'yes' }), /on or off/);
  const chain = rpc => JSON.stringify({ rpc, judge });
  assert.throws(() => networkConfig({ MORSE_ANCHOR_MODE: 'mainnet', MORSE_CHAIN_MAINNET: chain(['http://rpc.example']) }), /https/);
  const config = networkConfig({ MORSE_ANCHOR_MODE: 'mainnet', MORSE_LOG_ID: 'morse-canary', MORSE_CHAIN_MAINNET: chain(['https://a.example/', 'https://b.example/']) });
  assert.deepEqual(config, { mode: 'mainnet', logName: 'morse-canary', rpc: ['https://a.example/', 'https://b.example/'], judge, rewards: null, cluster: 'mainnet' });
});

// A Durable Object context over node:sqlite, and the network object wired to a
// judge-shaped memory chain and a fake directory.
function context() {
  const db = new DatabaseSync(':memory:');
  const alarms = [];
  return { alarms, storage: { setAlarm: async at => alarms.push(at), sql: { exec(query, ...params) {
    const statement = db.prepare(query);
    const rows = /^\s*SELECT/i.test(query) ? statement.all(...params) : (statement.run(...params), []);
    return { toArray: () => rows };
  } } } };
}
const secret = async fill => { const seed = new Uint8Array(32).fill(fill); return JSON.stringify([...concat(seed, (await ed25519FromSeed(seed)).publicKey)]); };

async function network(extra = {}) {
  const { chain } = await judgeChain();
  chain.set((await import('./test-chain.mjs')).payer.address, new Uint8Array(), undefined, 900_000_000n);
  const served = { checkpoint: await ktk(5n, 10n), anchors: [], refreshes: 0 };
  const env = {
    MORSE_ANCHOR_MODE: 'devnet', MORSE_CHAIN_DEVNET: JSON.stringify({ rpc: ['https://a.example', 'https://b.example'], judge }),
    MORSE_COSIGN_CRANK: 'on', MORSE_FEE_PAYER_KEYPAIR: await secret(1), MORSE_ANCHOR_AUTHORITY_KEYPAIR: await secret(2),
    MESSENGER_DELIVERY_INTERNAL_TOKEN: 't', ...extra,
    DIRECTORY: { getByName: () => ({ fetch: async (url, init = {}) => {
      const path = new URL(url).pathname;
      if (served.down) return new Response(null, { status: 503 });
      if (path === '/v1/transparency/checkpoint') return new Response(served.checkpoint);
      if (path === '/v1/transparency/witnesses') return new Response(Uint8Array.of(2, 75, 84, 87, 0, 0));
      if (path === '/internal/v1/transparency/anchors') { served.anchors.push(JSON.parse(init.body)); return new Response(null, { status: 201 }); }
      if (path === '/v1/transparency/consistency') {
        served.refreshes++;
        const out = new Uint8Array(21);
        out.set([2, 75, 84, 67]); out[19] = 10;
        return new Response(out);
      }
      return new Response(null, { status: 404 });
    } }) },
  };
  let now = 1_790_000_000_000;
  const ctx = context();
  const alerts = [];
  const core = new NetworkCore(ctx, env, { chainFor: () => chain, now: () => now, alert: x => alerts.push(x) });
  env.NETWORK = { getByName: () => core };
  return { core, env, ctx, chain, served, alerts, advance: ms => { now += ms; }, now: () => now };
}

test('each new checkpoint is anchored from the alarm; one arriving within a minute waits for the next alarm', async () => {
  const n = await network();
  await n.core.afterCheckpoint();
  assert.deepEqual(n.ctx.alarms, [n.now()]);
  await n.core.alarm();
  assert.equal(n.served.anchors.length, 1);
  n.advance(20_000);
  n.served.checkpoint = await ktk(6n, 11n, 2);
  await n.core.afterCheckpoint();
  await n.core.alarm();
  assert.equal(n.served.anchors.length, 1);
  assert.equal(n.ctx.alarms.at(-1), n.now() + 40_000, 'retried exactly a minute after the last anchor');
  n.advance(40_000);
  await n.core.alarm();
  assert.equal(n.served.anchors.length, 2);
});

test('the minute cron writes the bond counter snapshot that status.json serves, cached and readable cross-origin', async () => {
  const n = await network();
  await n.core.afterCheckpoint();
  await n.core.alarm();
  await n.core.cron(MINUTE_CRON);
  const response = await networkRoute(new Request('https://backend.example/v1/network/status.json'), n.env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'public, max-age=60');
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), '*');
  const body = await response.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.last_public_checkpoint.sequence, '5');
  assert.equal(body.operations.last_anchor.sequence, '5');
  assert.equal(body.operations.fee_payer.level, 'ok');
  assert.deepEqual(body.operations.pages, []);
  assert.equal(await networkRoute(new Request('https://backend.example/v1/transparency/checkpoint'), n.env), null);
  assert.equal((await networkRoute(new Request('https://backend.example/v1/network/status.json', { method: 'POST' }), n.env)).status, 405);
  assert.equal((await networkHealth(n.env, new Response('ok'))).status, 200);
});

test('the canary deployment anchors its own log but never feeds the bond counter or settlement', async () => {
  const n = await network({ MORSE_LOG_ID: 'morse-canary' });
  await n.core.cron(MINUTE_CRON);
  const body = n.core.status();
  assert.equal(body.status, 'unavailable');
  assert.equal(body.reason, 'no_snapshot_yet');
});

test('the hourly heartbeat refreshes the checkpoint, and an hour without an anchor pages and fails /health', async () => {
  const n = await network();
  await n.core.cron(HOURLY_CRON);
  assert.equal(n.served.refreshes, 1);
  assert.equal(n.served.anchors.length, 1);
  n.served.down = true;
  n.advance(66 * 60_000);
  await n.core.cron(HOURLY_CRON);
  assert.ok(n.alerts.some(x => /^PAGE anchor_gap minutes=66/.test(x)));
  assert.deepEqual(n.core.status().operations.pages, ['anchor_gap']);
  assert.equal((await networkHealth(n.env, new Response('ok'))).status, 503);
});

test('with anchoring off, crons do nothing and C2SP push still runs after checkpoints when enabled', async () => {
  const n = await network({ MORSE_ANCHOR_MODE: 'off', MORSE_C2SP_PUSH: 'on' });
  let listed = 0;
  const directory = n.env.DIRECTORY;
  n.env.DIRECTORY = { getByName: () => ({ fetch: async (url, init) => {
    if (new URL(url).pathname === '/internal/v1/transparency/push-witnesses') { listed++; return Response.json({ witnesses: [] }); }
    return directory.getByName().fetch(url, init);
  } }) };
  await n.core.cron(MINUTE_CRON);
  await n.core.cron(HOURLY_CRON);
  await n.core.afterCheckpoint();
  await n.core.alarm();
  assert.equal(listed, 1);
  assert.equal(n.chain.sent.length, 0);
  assert.equal(n.served.refreshes, 0);
});
