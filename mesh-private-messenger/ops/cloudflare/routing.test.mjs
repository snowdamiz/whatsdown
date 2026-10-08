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
  // A 512 MiB attachment has parts 0 through 8,192; the store bounds them exactly.
  for (const index of ['999', '1000', '8192']) {
    assert.equal(route(`/v1/objects/${'a'.repeat(64)}/parts/${index}`, 'GET'), 'OBJECT_STORE');
  }
  for (const index of ['01', '10000', '-1']) assert.equal(route(`/v1/objects/${'a'.repeat(64)}/parts/${index}`, 'GET'), null);
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
  assert.equal(route('/v1/accounts/delete', 'POST'), 'DIRECTORY');
  assert.equal(route('/v1/accounts/delete', 'GET'), null);
  assert.equal(route('/v1/devices/leave', 'POST'), 'DIRECTORY');
  // Phones fetch the logged credit keys; the core's credit routes stay internal.
  assert.equal(route('/v1/credits/issuer-keys', 'GET'), 'DIRECTORY');
  assert.equal(route('/v1/mailbox/policy', 'PUT'), 'DIRECTORY');
  assert.equal(route('/v1/mailbox/retention'), 'PRIVACY_EDGE');
  assert.equal(route('/internal/v1/mailbox/retention'), null);
  for (const path of ['/internal/v1/credits/redeem', '/internal/v1/credits/issuer-keys', '/v1/credits/health']) {
    assert.equal(route(path), null);
    assert.equal(route(path, 'GET'), null);
  }
});

test('the witness network routes are public and its internal routes are not', () => {
  const route = (path, method = 'GET') => publicRoute(new Request(`https://morse.example${path}`, { method }));
  assert.equal(route('/v1/transparency/checkpoint.note'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/registry'), 'DIRECTORY');
  // The directory's JSON health: the acceptance suite, alerts and operators read it.
  assert.equal(route('/v1/transparency/health'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/health', 'POST'), null);
  assert.equal(route('/v1/transparency/anchor/1'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/anchor/18446744073709551615'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/leaf', 'POST'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/leaves?start=0&count=1024'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/witnesses', 'POST'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/witnesses/12'), 'DIRECTORY');
  assert.equal(route('/v1/transparency/witnesses/18446744073709551615'), 'DIRECTORY');
  for (const [path, method] of [
    ['/v1/transparency/witnesses/', 'GET'], ['/v1/transparency/witnesses/01', 'GET'], ['/v1/transparency/witnesses/x', 'GET'],
    ['/v1/transparency/witnesses/1/2', 'GET'], ['/v1/transparency/witnesses/1', 'POST'],
    ['/v1/transparency/anchor/', 'GET'], ['/v1/transparency/anchor/01', 'GET'], ['/v1/transparency/anchor/x', 'GET'],
    ['/v1/transparency/anchor/1/2', 'GET'], ['/v1/transparency/anchor/1', 'POST'], ['/v1/transparency/registry', 'POST'],
    ['/v1/transparency/leaf', 'GET'], ['/v1/transparency/leaves', 'POST'], ['/v1/transparency/checkpoint.note', 'POST'],
    ['/internal/v1/transparency/anchors', 'POST'], ['/internal/v1/transparency/push-witnesses', 'GET'],
    ['/%69nternal/v1/transparency/anchors', 'POST'],
  ]) assert.equal(route(path, method), null, `${method} ${path}`);
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
