import assert from 'node:assert/strict';

const origin = new URL(process.env.MORSE_BACKEND_URL);
assert.equal(origin.protocol, 'https:');
// An isolated backend has no privacy edge of its own; MORSE_EDGE_URL names the
// separately deployed one. Without it this checks the combined topology.
const edge = process.env.MORSE_EDGE_URL ? new URL(process.env.MORSE_EDGE_URL) : null;
if (edge) {
  assert.equal(edge.protocol, 'https:');
  assert.notEqual(edge.origin, origin.origin, 'the privacy edge must be a separate origin');
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
    [origin, '/v1/ingress/sealed', 'POST', 401],
    [edge, '/health', 'GET', 200],
    [edge, '/v1/envelopes/batch', 'POST', 400],
    [edge, '/v1/ingress/sealed', 'POST', 404],
    [edge, '/v1/mailbox/fetch', 'POST', 404],
  ] : [[origin, '/v1/envelopes/batch', 'POST', 400]]),
];
for (const [base, path, method, expected] of checks) {
  const response = await fetch(new URL(path, base), { method, signal: AbortSignal.timeout(45_000) });
  await response.body?.cancel();
  assert.equal(response.status, expected, `${method} ${base.origin}${path}`);
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
console.log('Live health, private routes, input rejection, and WebSocket authorization passed.');
