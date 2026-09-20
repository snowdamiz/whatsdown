import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { containerRequest, edgeContainerEnv, edgeRoute, sealedDeliveryRequest, sealedIngressRequest } from './edge.mjs';
import { edgeConfig, isolatedConfig } from './prepare-build.mjs';
import { publicRoute } from './routing.mjs';

const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const isolation = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test' };
const token = 'c'.repeat(64);

// Everything the backend Worker holds. The edge must end up with none of it
// except the bearer credential it presents to the delivery core.
const backendSecrets = {
  MESSENGER_DATABASE_URL: 'postgres://secret', MESSENGER_DELIVERY_SEALING_SEED_HEX: '1'.repeat(64),
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '2'.repeat(64), MESSENGER_PUSH_BROKER_SEED_HEX: '3'.repeat(64),
  MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: '4'.repeat(64), MESSENGER_OBJECT_INTERNAL_TOKEN: '5'.repeat(64),
  MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
};

test('C6 the privacy edge deploys alone and its container never receives an unsealing or database secret', () => {
  const config = edgeConfig(original, { MORSE_DELIVERY_URL: 'https://delivery.test' });
  assert.equal(config.name, 'morse-privacy-edge');
  assert.equal(config.main, 'isolated-edge.mjs');
  assert.deepEqual(config.containers.map(x => x.class_name), ['IsolatedPrivacyEdge']);
  assert.deepEqual(config.durable_objects.bindings, [{ name: 'PRIVACY_EDGE', class_name: 'IsolatedPrivacyEdge' }]);
  assert.deepEqual(config.vars, { MORSE_DELIVERY_URL: 'https://delivery.test' });
  assert.equal(config.r2_buckets, undefined);
  assert.equal(config.observability.enabled, false);
  assert.throws(() => edgeConfig(original, { MORSE_DELIVERY_URL: 'http://delivery.test' }), /HTTPS origin/);
  assert.throws(() => edgeConfig(original, {}), /HTTPS origin/);

  assert.deepEqual(edgeContainerEnv(backendSecrets), {
    MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    MESSENGER_DELIVERY_INTERNAL_URL: 'http://delivery.internal',
  });
  assert.throws(() => edgeContainerEnv({}), /Missing MESSENGER_DELIVERY_INTERNAL_TOKEN/);
});

test('C6 an isolated backend has no privacy edge and accepts only the sealed ingress route in its place', () => {
  const backend = isolatedConfig(original, isolation);
  assert.equal(backend.vars.MORSE_ISOLATED_EDGE, '1');
  assert.ok(!backend.containers.some(x => x.class_name === 'PrivacyEdge'));
  assert.ok(!backend.durable_objects.bindings.some(x => x.name === 'PRIVACY_EDGE'));

  const route = (path, env, method = 'POST') => publicRoute(new Request(`https://morse.example${path}`, { method }), env);
  const isolated = { MORSE_ISOLATED_EDGE: '1' };
  assert.equal(route('/v1/envelopes/batch', isolated), null);
  assert.equal(route('/v1/ingress/sealed', isolated), 'SEALED_INGRESS');
  assert.equal(route('/v1/ingress/sealed', isolated, 'GET'), null);
  assert.equal(route('/internal/v1/envelopes/sealed', isolated), null);
  assert.equal(route('/v1/mailbox/fetch', isolated), 'DIRECTORY');
  // The combined development Worker keeps its in-process edge and no public sealed route.
  assert.equal(route('/v1/envelopes/batch', {}), 'PRIVACY_EDGE');
  assert.equal(route('/v1/ingress/sealed', {}), null);
});

test('C6 the edge exposes one public route and forwards only the sealed body and bearer credential', async () => {
  const at = (path, method = 'POST') => edgeRoute(new Request(`https://edge.test${path}`, { method }));
  assert.equal(at('/v1/envelopes/batch'), true);
  for (const [path, method] of [['/v1/envelopes/batch', 'GET'], ['/v1/envelopes/batch?x=1', 'POST'], ['/v1/mailbox/fetch', 'POST'],
    ['/v1/ingress/sealed', 'POST'], ['/internal/v1/envelopes/sealed', 'POST'], ['/%761/envelopes/batch', 'POST']]) {
    assert.equal(at(path, method), false);
  }

  const env = { MORSE_DELIVERY_URL: 'https://delivery.test' };
  const outbound = new Request('http://delivery.internal/internal/v1/envelopes/sealed', {
    method: 'POST', body: new Uint8Array([1, 2, 3]),
    headers: { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '203.0.113.9', 'X-Forwarded-For': '203.0.113.9', Cookie: 'a=b' },
  });
  const forwarded = sealedDeliveryRequest(outbound, env);
  assert.equal(forwarded.url, 'https://delivery.test/v1/ingress/sealed');
  assert.equal(forwarded.method, 'POST');
  assert.equal(forwarded.redirect, 'manual');
  assert.deepEqual([...forwarded.headers.keys()].sort(), ['authorization', 'content-type']);
  assert.equal(forwarded.headers.get('authorization'), `Bearer ${token}`);
  assert.deepEqual(new Uint8Array(await forwarded.arrayBuffer()), new Uint8Array([1, 2, 3]));
  for (const [url, method] of [['http://delivery.internal/internal/v1/jobs/directory', 'POST'],
    ['http://delivery.internal/internal/v1/envelopes/sealed', 'GET'], ['http://delivery.internal/v1/mailbox/fetch', 'POST'],
    ['http://delivery.internal/internal/v1/envelopes/sealed?x=1', 'POST']]) {
    assert.equal(sealedDeliveryRequest(new Request(url, { method }), env), null);
  }
  assert.throws(() => sealedDeliveryRequest(outbound, { MORSE_DELIVERY_URL: 'http://delivery.test' }), /HTTPS origin/);
});

test('C6 the backend maps sealed ingress to the delivery core without any client-supplied header', async () => {
  const inbound = new Request('https://morse.example/v1/ingress/sealed', {
    method: 'POST', body: new Uint8Array([9]),
    headers: { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '198.51.100.7', 'X-Real-IP': '198.51.100.7' },
  });
  const mapped = sealedIngressRequest(inbound);
  assert.equal(new URL(mapped.url).pathname, '/internal/v1/envelopes/sealed');
  assert.deepEqual([...mapped.headers.keys()].sort(), ['authorization', 'content-type']);
  assert.deepEqual(new Uint8Array(await mapped.arrayBuffer()), new Uint8Array([9]));
});

test('C6 containers never receive client address, location, agent, or cookie headers', () => {
  const inbound = new Request('https://morse.example/v1/mailbox/fetch', {
    method: 'POST', body: new Uint8Array([7]),
    headers: {
      'Content-Type': 'application/octet-stream', Authorization: 'MeshMailbox 02',
      'CF-Connecting-IP': '198.51.100.7', 'CF-IPCountry': 'NZ', 'CF-Ray': 'abc', 'X-Forwarded-For': '198.51.100.7',
      'X-Real-IP': '198.51.100.7', 'True-Client-IP': '198.51.100.7', Forwarded: 'for=198.51.100.7',
      'User-Agent': 'fingerprint', Cookie: 'a=b', Referer: 'https://x.test', 'Accept-Language': 'en-NZ',
    },
  });
  const cleaned = containerRequest(inbound);
  assert.equal(cleaned.url, inbound.url);
  assert.equal(cleaned.method, 'POST');
  assert.deepEqual([...cleaned.headers.keys()].sort(), ['authorization', 'content-type']);

  const upgrade = containerRequest(new Request('https://morse.example/v1/mailbox/stream', {
    headers: { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Key': 'k', 'Sec-WebSocket-Version': '13',
      Authorization: 'MeshMailbox 02', 'CF-Connecting-IP': '198.51.100.7' },
  }));
  assert.deepEqual([...upgrade.headers.keys()].sort(),
    ['authorization', 'connection', 'sec-websocket-key', 'sec-websocket-version', 'upgrade']);
});
