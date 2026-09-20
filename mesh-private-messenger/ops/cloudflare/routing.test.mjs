import assert from 'node:assert/strict';
import test from 'node:test';
import { publicRoute, publicHealth } from './routing.mjs';

test('public ingress routes each API and excludes private endpoints including encoded paths', () => {
  const route = (path, method = 'POST', headers) => publicRoute(new Request(`https://morse.example${path}`, { method, headers }));
  assert.equal(route('/v1/envelopes/batch'), 'PRIVACY_EDGE');
  assert.equal(route('/v1/mailbox/fetch'), 'DIRECTORY');
  assert.equal(route('/v1/mailbox/stream', 'GET', { Upgrade: 'websocket' }), 'STREAM');
  assert.equal(route('/v1/mailbox/stream', 'GET'), null);
  assert.equal(route('/v1/attachments/grant'), 'OBJECT_STORE');
  assert.equal(route(`/v1/objects/${'a'.repeat(64)}/parts/0`, 'PUT'), 'OBJECT_STORE');
  for (const path of ['/internal/v1/envelopes/sealed', '/internal/v1/push', '/%69nternal/v1/push', '/checkpoint']) {
    assert.equal(route(path), null);
  }
  assert.equal(route('/v1/envelopes/batch', 'GET'), null);
  // The unauthenticated single-device directory is retired at every layer.
  assert.equal(route('/v1/directory/register', 'PUT'), null);
  assert.equal(route('/v1/directory/resolve', 'POST'), null);
  assert.equal(route('/v1/directory/resolve', 'GET'), null);
  assert.equal(route('/v1/devices/register', 'PUT'), 'DIRECTORY');
  assert.equal(route('/v1/devices/resolve', 'POST'), 'DIRECTORY');
});

test('public health reports cached job failures without starting services or signers', async () => {
  let failures = 0;
  const env = { JOBS: { getByName: () => ({ status: async () => ({ pending: 0, due: 0, failures }) }) } };
  for (const binding of ['DIRECTORY', 'PRIVACY_EDGE', 'OBJECT_STORE', 'PUSH_BROKER', 'WITNESS_A', 'WITNESS_B']) {
    Object.defineProperty(env, binding, { get() { throw new Error('public probe activated ' + binding); } });
  }
  const healthy = await publicHealth(env);
  assert.equal(healthy.status, 200);
  assert.equal(await healthy.text(), 'ok');
  failures = 1;
  assert.equal((await publicHealth(env)).status, 503);
});
