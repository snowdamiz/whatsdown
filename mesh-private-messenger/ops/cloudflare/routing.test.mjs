import assert from 'node:assert/strict';
import test from 'node:test';
import { publicRoute } from './routing.mjs';

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
});
