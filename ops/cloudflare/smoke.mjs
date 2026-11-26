import assert from 'node:assert/strict';
import { decapsulateResponse, decodeKeyConfig, decodeKeys, decodeResponse, encapsulateRequest, encodeRequest, hex } from './ohttp.mjs';

const origin = new URL(process.env.MORSE_BACKEND_URL);
assert.equal(origin.protocol, 'https:');
// An isolated backend has no privacy edge of its own; MORSE_EDGE_URL names the
// separately deployed one. Without it this checks the combined topology.
const edge = process.env.MORSE_EDGE_URL ? new URL(process.env.MORSE_EDGE_URL) : null;
if (edge) {
  assert.equal(edge.protocol, 'https:');
  assert.notEqual(edge.origin, origin.origin, 'the privacy edge must be a separate origin');
}
// MORSE_PUSH_BROKER_URL names the separately deployed push broker (§22 M4).
const broker = process.env.MORSE_PUSH_BROKER_URL ? new URL(process.env.MORSE_PUSH_BROKER_URL) : null;
if (broker) {
  assert.equal(broker.protocol, 'https:');
  assert.notEqual(broker.origin, origin.origin, 'the push broker must be a separate origin');
}
const checks = [
  [origin, '/health', 'GET', 200],
  [origin, '/internal/v1/jobs/directory', 'POST', 404],
  [origin, '/internal/v1/push', 'POST', 404],
  [origin, '/internal/v1/envelopes/sealed', 'POST', 404],
  [origin, '/v1/directory/register', 'PUT', 404],
  [origin, '/v1/directory/resolve', 'POST', 404],
  [origin, '/v1/mailbox/fetch', 'POST', 400],
  [origin, '/v1/attachments/grant', 'POST', 400],
  [origin, '/v1/mailbox/stream', 'GET', 404],
  ...(edge ? [
    [origin, '/v1/envelopes/batch', 'POST', 404],
    // 403 once the edge's client certificate is pinned (§22 M2), else 401.
    [origin, '/v1/ingress/sealed', 'POST', [401, 403]],
    [origin, '/v1/ingress/ohttp', 'POST', [401, 403]],
    [origin, '/v1/ohttp', 'POST', 404],
    [edge, '/health', 'GET', 200],
    [edge, '/v1/envelopes/batch', 'POST', 400],
    [edge, '/v1/ohttp', 'POST', 400],
    [edge, '/v1/ingress/sealed', 'POST', 404],
    [edge, '/v1/mailbox/fetch', 'POST', 404],
  ] : [[origin, '/v1/envelopes/batch', 'POST', 400]]),
  ...(broker ? [
    [broker, '/health', 'GET', 200],
    [broker, '/internal/v1/push', 'POST', 401],
    [broker, '/internal/v1/jobs/push', 'POST', 404],
    [broker, '/v1/mailbox/fetch', 'POST', 404],
  ] : []),
];
for (const [base, path, method, expected] of checks) {
  let response;
  // A container created by this deployment answers 503 until it has started.
  for (let attempt = 1; ; attempt++) {
    response = await fetch(new URL(path, base), { method, signal: AbortSignal.timeout(45_000) });
    await response.body?.cancel();
    if (response.status !== 503 || attempt === 30) break;
    await new Promise(resolve => setTimeout(resolve, 10_000));
  }
  assert.ok([expected].flat().includes(response.status), `${method} ${base.origin}${path}: ${response.status}, expected ${expected}`);
}

const stream = new URL('/v1/mailbox/stream', origin);
stream.protocol = 'wss:';
await new Promise((resolve, reject) => {
  const socket = new WebSocket(stream);
  const timer = setTimeout(() => {
    socket.close();
    reject(new Error('WebSocket authorization check timed out'));
  }, 15_000);
  socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('WebSocket upgrade failed')); });
  socket.addEventListener('close', event => {
    clearTimeout(timer);
    if (event.code === 1008) resolve();
    else reject(new Error(`Expected unauthorized WebSocket close, received ${event.code}`));
  });
});
// §22 M3: MESSENGER_OHTTP_KEY is the gateway key builds pin (`<key id>:<public
// key hex>`, as in client.env). The backend must publish it first, and a
// consistency query sent through the relay must come back open.
if (process.env.MESSENGER_OHTTP_KEY) {
  const [keyId, publicKey] = process.env.MESSENGER_OHTTP_KEY.split(':');
  const pinned = Buffer.concat([Buffer.from([Number(keyId)]), hex('0020'), hex(publicKey), hex('000400010003')]);
  const keys = await fetch(new URL('/v1/ohttp/keys', origin), { signal: AbortSignal.timeout(45_000) });
  assert.equal(keys.status, 200, `GET /v1/ohttp/keys: ${keys.status}`);
  assert.deepEqual(decodeKeys(new Uint8Array(await keys.arrayBuffer()))[0], pinned, 'the gateway must serve the pinned key first');
  const query = Buffer.concat([Buffer.from([2]), Buffer.from('KTS'), Buffer.alloc(16), Buffer.from([1])]);
  const { encapsulated, context } = encapsulateRequest(decodeKeyConfig(pinned), encodeRequest('POST', '/v1/transparency/consistency', query));
  const relayed = await fetch(new URL('/v1/ohttp', edge ?? origin), {
    method: 'POST', body: encapsulated, headers: { 'Content-Type': 'message/ohttp-req' }, signal: AbortSignal.timeout(45_000) });
  assert.equal(relayed.status, 200, `POST /v1/ohttp: ${relayed.status}`);
  const inner = decodeResponse(decapsulateResponse(context, new Uint8Array(await relayed.arrayBuffer())));
  assert.equal(inner.status, 200, `consistency through OHTTP: ${inner.status}`);
  assert.equal(inner.content.subarray(1, 4).toString(), 'KTC');
}
console.log('Live health, private routes, input rejection, WebSocket authorization and OHTTP passed.');
