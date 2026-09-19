import assert from 'node:assert/strict';

const origin = new URL(process.env.MORSE_BACKEND_URL);
assert.equal(origin.protocol, 'https:');
for (const [path, method, expected] of [
  ['/health', 'GET', 200],
  ['/internal/v1/jobs/directory', 'POST', 404],
  ['/internal/v1/push', 'POST', 404],
  ['/v1/envelopes/batch', 'POST', 400],
  ['/v1/attachments/grant', 'POST', 400],
  ['/v1/mailbox/stream', 'GET', 404],
]) {
  const response = await fetch(new URL(path, origin), { method, signal: AbortSignal.timeout(45_000) });
  await response.body?.cancel();
  assert.equal(response.status, expected, `${method} ${path}`);
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
