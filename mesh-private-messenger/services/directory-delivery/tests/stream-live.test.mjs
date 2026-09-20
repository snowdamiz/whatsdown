import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { on, once } from 'node:events';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(new URL('../../../apps/mobile/package.json', import.meta.url));
const WebSocket = require('ws');
const http = process.env.MESSENGER_STREAM_TEST_HTTP ?? 'http://127.0.0.1:18986';
const stream = process.env.MESSENGER_STREAM_TEST_WS ?? 'ws://127.0.0.1:18990/v1/mailbox/stream';
const frame = (tag, ...fields) => Buffer.concat([Buffer.from([1]), Buffer.from(tag), ...fields]);
const u32 = (value) => { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; };
const u64 = (value) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(value)); return b; };
const vector = (value) => Buffer.concat([u32(value.length), value]);
// Pre-hardening request shape: the public mailbox address as a bearer credential.
const unsignedFetchFrame = (token) => frame('FET', token, u64(0));
const cli = process.env.MESSENGER_CLI ?? new URL('../../../clients/mesh-cli/output', import.meta.url).pathname;

async function request(path, body, status, method = 'POST') {
  const response = await fetch(`${http}${path}`, {
    method, body, headers: { 'Content-Type': 'application/octet-stream' },
    signal: AbortSignal.timeout(5_000),
  });
  assert.equal(response.status, status);
  return Buffer.from(await response.arrayBuffer());
}

// A real account-signed device, registered and signed by the Mesh CLI so this
// test never reimplements protocol codecs. The frame stays fresh for 5 minutes.
function register() {
  const output = execFileSync(cli, {
    env: { ...process.env, MESSENGER_ROLE: 'stream-fixture', MESSENGER_BASE_URL: http },
    encoding: 'utf8', timeout: 20_000,
  });
  const field = (name) => Buffer.from(output.match(new RegExp(`^stream-fixture:${name}=([0-9a-f]+)$`, 'm'))[1], 'hex');
  assert.match(output, /^stream-fixture:ok$/m);
  return { token: field('token'), fetch: field('fetch') };
}

function subscribe(t, device) {
  const socket = new WebSocket(stream, { headers: { Authorization: `MeshMailbox ${device.fetch.toString('hex')}` } });
  const abort = new AbortController();
  const messages = on(socket, 'message', { signal: AbortSignal.any([abort.signal, AbortSignal.timeout(10_000)]) });
  const received = [];
  socket.on('message', (data) => received.push(data.toString()));
  t.after(() => { abort.abort(); socket.terminate(); });
  return { socket, received, next: async () => (await messages.next()).value[0].toString() };
}

async function deliver(token) {
  const id = randomBytes(16);
  await request('/v1/envelopes/batch', frame('MSG', id, token,
    Buffer.from([0, 1]), u64(Date.now() + 60_000), u32(256), vector(Buffer.from('opaque-test-ciphertext'))), 202);
  return id;
}

test('rejects unauthorized streams and wakes only the committed recipient, including no-push devices', { timeout: 20_000 }, async (t) => {
  const denied = new WebSocket(stream);
  denied.on('error', () => {});
  t.after(() => denied.terminate());
  const [code] = await once(denied, 'close');
  assert.equal(code, 1008);

  const firstDevice = register();
  const secondDevice = register();

  // Knowing the published mailbox address grants neither a stream nor a fetch.
  const bearer = new WebSocket(stream, {
    headers: { Authorization: `MeshMailbox ${unsignedFetchFrame(firstDevice.token).toString('hex')}` },
  });
  bearer.on('error', () => {});
  t.after(() => bearer.terminate());
  assert.equal((await once(bearer, 'close'))[0], 1008);
  await request('/v1/mailbox/fetch', unsignedFetchFrame(firstDevice.token), 400);

  const first = subscribe(t, firstDevice);
  const second = subscribe(t, secondDevice);
  assert.equal(await first.next(), 'ready');
  assert.equal(await second.next(), 'ready');
  const id = await deliver(firstDevice.token);
  assert.equal(await first.next(), 'encrypted-wakeup');
  const batch = await request('/v1/mailbox/fetch', firstDevice.fetch, 200);
  assert.equal(batch[4], 1);
  assert.ok(batch.includes(id));
  assert.deepEqual(second.received, ['ready']);

  first.socket.close();
  await once(first.socket, 'close');
  await deliver(firstDevice.token);
  const resumed = subscribe(t, firstDevice);
  assert.equal(await resumed.next(), 'ready');
  const missed = await request('/v1/mailbox/fetch', firstDevice.fetch, 200);
  assert.equal(missed[4], 2);
});
