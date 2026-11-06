import assert from 'node:assert/strict';
import test from 'node:test';
import { publicRoute } from './routing.mjs';
import { issuerIngressRequest } from './issuer-ingress.mjs';

const enabled = { MORSE_CREDIT_ISSUER_INGRESS: 'on' };
const request = (operation, method = 'POST', suffix = '', headers = {}) => new Request(
  `https://core.test/v1/ingress/credits/issuers/${operation}${suffix}`, {
    method, headers: { Authorization: 'Bearer admin', Cookie: 'tracking=1',
      'X-Forwarded-For': '198.51.100.1', 'Content-Type': 'application/json', ...headers },
    ...(['POST', 'PUT'].includes(method) ? { body: operation === 'evidence' ? '1234567890123' : '{"leaf":"abc"}' } : {}),
  });

test('issuer administration has an opt-in bounded ingress and remains inaccessible from the edge route', async () => {
  for (const [operation, method, type] of [
    ['announce', 'POST', 'application/json'], ['evidence', 'POST', 'application/octet-stream'],
    ['admit', 'POST', 'application/json'], ['cursor', 'GET', 'application/octet-stream'],
  ]) {
    const input = request(operation, method);
    assert.equal(publicRoute(input), null);
    assert.equal(publicRoute(input, enabled), 'ISSUER_INGRESS');
    assert.equal(publicRoute(input, { ...enabled, MORSE_ISOLATED_EDGE: '1' }), 'ISSUER_INGRESS');
    const output = await issuerIngressRequest(input);
    assert.ok(output instanceof Request);
    assert.equal(output.url, `https://core.test/internal/credits/issuers/${operation}`);
    assert.equal(output.method, method);
    assert.equal(output.headers.get('content-type'), type);
    assert.equal(output.headers.get('authorization'), 'Bearer admin');
    assert.deepEqual([...output.headers.keys()].sort(), ['authorization', 'content-type']);
    if (method === 'POST') assert.equal(await output.text(), operation === 'evidence' ? '1234567890123' : '{"leaf":"abc"}');
  }
  for (const input of [request('prune'), request('announce', 'GET'), request('cursor', 'POST'),
    request('admit', 'POST', '?trace=1'), request('../admit'), request('%61dmit')]) {
    assert.equal(publicRoute(input, enabled), null);
    assert.equal(await issuerIngressRequest(input), null);
  }
  const noAuth = request('admit', 'POST', '', { Authorization: '' });
  assert.equal((await issuerIngressRequest(noAuth)).status, 401);
  const huge = new Request('https://core.test/v1/ingress/credits/issuers/admit', {
    method: 'POST', headers: { Authorization: 'Bearer admin' }, body: 'x'.repeat(140_001),
  });
  assert.equal((await issuerIngressRequest(huge)).status, 413);
});
