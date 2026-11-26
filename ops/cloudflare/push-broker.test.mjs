import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { brokerIngress, brokerPushRequest, forwardPush, pushBrokerContainerEnv } from './push-broker.mjs';
import { isolatedConfig, pushBrokerConfig } from './prepare-build.mjs';
import { publicHealth } from './routing.mjs';

const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const isolation = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://push.test' };
const token = '4'.repeat(64);
const seed = '3'.repeat(64);

test('M4 the push broker deploys alone with only its own scheduler and container', () => {
  const config = pushBrokerConfig(original);
  assert.equal(config.name, 'morse-push-broker');
  assert.equal(config.main, 'isolated-push.mjs');
  assert.deepEqual(config.containers.map(x => x.class_name), ['IsolatedPushBroker']);
  assert.deepEqual(config.durable_objects.bindings, [
    { name: 'PUSH_BROKER', class_name: 'IsolatedPushBroker' }, { name: 'JOBS', class_name: 'JobScheduler' }]);
  for (const key of ['vars', 'r2_buckets', 'triggers', 'mtls_certificates', 'routes']) assert.equal(config[key], undefined, key);
  assert.equal(config.observability.enabled, false);
});

test('M4 the backend no longer runs the broker and reaches it only across deployments', () => {
  const backend = isolatedConfig(original, isolation);
  assert.ok(!backend.containers.some(x => x.class_name === 'PushBroker'));
  assert.ok(!backend.durable_objects.bindings.some(x => x.name === 'PUSH_BROKER'));
  assert.equal(backend.vars.MORSE_ISOLATED_PUSH, '1');
  assert.equal(backend.vars.MORSE_PUSH_BROKER_URL, 'https://push.test');
  assert.deepEqual(backend.migrations, original.migrations, 'existing Durable Object classes must not be deleted during cutover');
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_PUSH_BROKER_URL: undefined }), /HTTPS origin/);
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_PUSH_BROKER_URL: 'http://push.test' }), /HTTPS origin/);
});

test('M4 the broker container receives its own secrets and nothing else', () => {
  const overProvisioned = {
    MESSENGER_PUSH_BROKER_SEED_HEX: seed, MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token, PUSH_DATABASE_URL: 'postgres://push',
    MESSENGER_EXPO_ACCESS_TOKEN: 'expo',
    MESSENGER_DATABASE_URL: 'postgres://delivery', MESSENGER_DELIVERY_SEALING_SEED_HEX: '1'.repeat(64),
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '2'.repeat(64), MESSENGER_DELIVERY_INTERNAL_TOKEN: '5'.repeat(64),
    OBJECT_DATABASE_URL: 'postgres://objects', MESSENGER_OBJECT_INTERNAL_TOKEN: '6'.repeat(64),
  };
  assert.deepEqual(pushBrokerContainerEnv(overProvisioned), {
    MESSENGER_PUSH_BROKER_SEED_HEX: seed, MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token,
    MESSENGER_PUSH_BROKER_DATABASE_URL: 'postgres://push', MESSENGER_EXPO_ACCESS_TOKEN: 'expo',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
  });
  assert.equal(pushBrokerContainerEnv({ ...overProvisioned, MESSENGER_EXPO_ACCESS_TOKEN: undefined }).MESSENGER_EXPO_ACCESS_TOKEN, '');
  for (const missing of ['MESSENGER_PUSH_BROKER_SEED_HEX', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'PUSH_DATABASE_URL']) {
    assert.throws(() => pushBrokerContainerEnv({ ...overProvisioned, [missing]: '' }), new RegExp(`Missing ${missing}`));
  }
});

test('M4 the delivery core sends only the sealed push job and the broker bearer across deployments', async () => {
  const env = { MORSE_PUSH_BROKER_URL: 'https://push.test' };
  const outbound = new Request('http://push.internal/internal/v1/push', {
    method: 'POST', body: new Uint8Array([4, 2]),
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream', 'X-Mailbox': 'leak' },
  });
  const forwarded = brokerPushRequest(outbound, env);
  assert.equal(forwarded.url, 'https://push.test/internal/v1/push');
  assert.equal(forwarded.redirect, 'manual');
  assert.deepEqual([...forwarded.headers.keys()].sort(), ['authorization', 'content-type']);
  assert.deepEqual(new Uint8Array(await forwarded.arrayBuffer()), new Uint8Array([4, 2]));
  for (const [url, method] of [['http://push.internal/internal/v1/jobs/push', 'POST'], ['http://push.internal/internal/v1/push', 'GET'],
    ['http://push.internal/internal/v1/push?x=1', 'POST'], ['http://push.internal/health', 'GET']]) {
    assert.equal(brokerPushRequest(new Request(url, { method }), env), null, `${method} ${url}`);
  }
  assert.throws(() => brokerPushRequest(outbound, { MORSE_PUSH_BROKER_URL: 'http://push.test' }), /HTTPS origin/);
  const redirected = async () => new Response(null, { status: 307, headers: { Location: 'https://elsewhere.test' } });
  assert.equal((await forwardPush(new Request('http://push.internal/internal/v1/push', { method: 'POST', body: 'x' }), env, redirected)).status, 502);
  assert.equal((await forwardPush(new Request('http://push.internal/internal/v1/jobs/push', { method: 'POST' }), env, redirected)).status, 404);
});

test('M4 the broker Worker serves one bearer-checked route and strips client headers', async () => {
  const env = { MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token };
  const request = (path, headers = {}, method = 'POST') => new Request(`https://push.test${path}`, { method, headers, body: method === 'POST' ? 'x' : undefined });
  const good = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream', 'CF-Connecting-IP': '198.51.100.7', 'User-Agent': 'x' };
  const accepted = brokerIngress(request('/internal/v1/push', good), env);
  assert.ok(accepted instanceof Request);
  assert.equal(new URL(accepted.url).pathname, '/internal/v1/push');
  assert.deepEqual([...accepted.headers.keys()].sort(), ['authorization', 'content-type']);
  for (const [req, status] of [
    [request('/internal/v1/push'), 401],
    [request('/internal/v1/push', { Authorization: `Bearer ${'b'.repeat(64)}` }), 401],
    [request('/internal/v1/jobs/push', good), 404],
    [request('/internal/v1/push?x=1', good), 404],
    [request('/%69nternal/v1/push', good), 404],
    [request('/internal/v1/push', good, 'GET'), 404],
  ]) assert.equal(brokerIngress(req, env).status, status, `${req.method} ${req.url}`);
  assert.equal(brokerIngress(request('/internal/v1/push', good), {}).status, 503);
});

test('M4 health follows each deployment\'s own schedulers', async () => {
  const failing = kind => ({ JOBS: { getByName: name => ({ status: async () => ({ failures: name === kind ? 1 : 0 }) }) } });
  // The backend stops answering for a scheduler it no longer runs.
  assert.equal((await publicHealth({ ...failing('push'), MORSE_ISOLATED_PUSH: '1' })).status, 200);
  assert.equal((await publicHealth({ ...failing('directory'), MORSE_ISOLATED_PUSH: '1' })).status, 503);
  assert.equal((await publicHealth(failing('push'))).status, 503);
  // The broker Worker's /health covers only the push scheduler.
  assert.equal((await publicHealth(failing('push'), ['push'])).status, 503);
  assert.equal((await publicHealth(failing('directory'), ['push'])).status, 200);
});

test('M4 a scheduler whose service moved to another deployment drops its leftover work instead of failing forever', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-push-jobs-'));
  const options = convertV4MiniflareOptions({
    name: 'morse-push-move-test', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: `
        export { JobScheduler } from './jobs.mjs';
        export default { async fetch(request, env) {
          const job = env.JOBS.getByName('push');
          if (new URL(request.url).pathname === '/register') await job.register('push', '42');
          else await job.run();
          return Response.json(await job.status());
        } };` },
      ...await Promise.all(['jobs', 'witness', 'storage'].map(async name => ({ type: 'ESModule', path: `${name}.mjs`,
        contents: await readFile(new URL(`./${name}.mjs`, import.meta.url), 'utf8') }))),
    ],
    // An isolated backend: no PUSH_BROKER binding any more.
    bindings: { MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token },
    durableObjects: { JOBS: { className: 'JobScheduler', useSQLite: true, unsafeUniqueKey: 'morse-push-move-test' } },
  });
  options.resourcePersistencePath = directory;
  const mf = new Miniflare(options);
  try {
    assert.equal((await (await mf.dispatchFetch('http://test/register')).json()).pending, 1);
    assert.deepEqual(await (await mf.dispatchFetch('http://test/run')).json(), { pending: 0, due: 0, failures: 0 });
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});
