import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  ohttpContainerRequest, ohttpDeliveryRequest, ohttpIngressRequest, ohttpRelayResponse,
} from './ohttp.mjs';

const maximum = 1_048_576;
const token = 'a'.repeat(64);
const env = { MORSE_DELIVERY_URL: 'https://core.test', MESSENGER_DELIVERY_INTERNAL_TOKEN: token };
const identifying = {
  Authorization: 'account-secret', Cookie: 'identity=secret', 'User-Agent': 'fingerprint',
  'CF-Connecting-IP': '192.0.2.1', 'CF-Ray': 'request-id', 'X-Forwarded-For': '192.0.2.1',
  Forwarded: 'for=192.0.2.1', 'X-Request-ID': 'unique', Traceparent: 'unique',
  'X-Account-ID': 'account', 'Accept-Language': 'en-NZ', Referer: 'https://private.test',
};
const incoming = (url = 'https://edge.test/v1/ohttp', size = 55, headers = {}) => new Request(url, {
  method: 'POST', headers: { 'Content-Type': 'message/ohttp-req', ...identifying, ...headers },
  body: new Uint8Array(size).fill(91),
});
const response = (size = 48, headers = {}, status = 200) => new Response(new Uint8Array(size).fill(92), {
  status, headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store', ...headers },
});
const headers = (request) => Object.fromEntries(request.headers);
const rejected = (promise, status) => assert.rejects(promise, error => error.status === status);

test('opaque request crosses fixed hops with no identifying headers and only an edge-owned credential', async () => {
  const raw = incoming();
  const clean = await ohttpContainerRequest(raw);
  assert.equal(clean.url, raw.url);
  assert.equal(clean.method, 'POST');
  assert.equal(clean.redirect, 'manual');
  assert.deepEqual(headers(clean), { accept: 'message/ohttp-res', 'cache-control': 'no-store', 'content-type': 'message/ohttp-req' });
  assert.deepEqual(new Uint8Array(await clean.arrayBuffer()), new Uint8Array(55).fill(91));

  const sent = await ohttpDeliveryRequest(incoming('http://delivery.internal/internal/v1/ohttp'), env);
  assert.equal(sent.url, 'https://core.test/v1/ingress/ohttp');
  assert.equal(sent.redirect, 'manual');
  assert.deepEqual(headers(sent), { accept: 'message/ohttp-res', authorization: `Bearer ${token}`, 'cache-control': 'no-store', 'content-type': 'message/ohttp-req' });
  const mapped = await ohttpIngressRequest(sent, {});
  assert.equal(mapped.url, 'https://core.test/internal/v1/ohttp');
  assert.deepEqual(headers(mapped), headers(sent));
  assert.deepEqual(new Uint8Array(await mapped.arrayBuffer()), new Uint8Array(55).fill(91));
});

test('method, exact path, query, fragment, origin and protocol are not caller-selectable', async () => {
  for (const path of ['/v1/ohttp/', '/v1/%6fhttp', '/v1/ohttp?target=x', '/v1/ohttp#trace', '/v1/prekeys/bundle']) {
    assert.equal(await ohttpContainerRequest(incoming('https://edge.test' + path)), null);
  }
  assert.equal(await ohttpContainerRequest(new Request('https://edge.test/v1/ohttp')), null);
  assert.equal(await ohttpContainerRequest(incoming('http://edge.test/v1/ohttp')), null);
  for (const url of ['http://attacker.test/internal/v1/ohttp', 'http://delivery.internal/internal/v1/ohttp/',
    'http://delivery.internal/internal/v1/ohttp?target=x', 'http://delivery.internal/internal/v1/ohttp#trace',
    'http://delivery.internal/internal/v1/prekeys/bundle', 'https://delivery.internal/internal/v1/ohttp']) {
    assert.equal(await ohttpDeliveryRequest(incoming(url), env), null);
  }
  for (const path of ['/v1/ingress/ohttp/', '/v1/ingress/%6fhttp', '/v1/ingress/ohttp?x=1', '/v1/ingress/ohttp#trace']) {
    assert.equal(await ohttpIngressRequest(incoming('https://core.test' + path), {}), null);
  }
  for (const origin of ['http://core.test', 'https://core.test/', 'https://core.test/path', 'https://core.test?x=1']) {
    await rejected(ohttpDeliveryRequest(incoming('http://delivery.internal/internal/v1/ohttp'), { ...env, MORSE_DELIVERY_URL: origin }), 503);
  }
});

test('request media, encoding and wire limits are checked before forwarding', async () => {
  for (const value of ['', 'application/octet-stream', 'message/ohttp-req; charset=utf-8', 'message/ohttp-req, message/ohttp-req']) {
    await rejected(ohttpContainerRequest(incoming(undefined, 55, { 'Content-Type': value })), 415);
  }
  await rejected(ohttpContainerRequest(incoming(undefined, 55, { 'Content-Encoding': 'gzip' })), 415);
  for (const size of [0, 54]) await rejected(ohttpContainerRequest(incoming(undefined, size)), 400);
  assert.equal((await (await ohttpContainerRequest(incoming(undefined, maximum))).arrayBuffer()).byteLength, maximum);
  await rejected(ohttpContainerRequest(incoming(undefined, maximum + 1)), 413);
  // An understated transport length is not an allocation or admission oracle.
  await rejected(ohttpContainerRequest(incoming(undefined, maximum + 1, { 'Content-Length': '55' })), 413);
});

test('stream overflow is cancelled and request cancellation interrupts a stalled read', async () => {
  let cancelled = false;
  const stream = new ReadableStream({ start(c) { c.enqueue(new Uint8Array(maximum)); c.enqueue(new Uint8Array(1)); }, cancel() { cancelled = true; } });
  await rejected(ohttpContainerRequest(new Request('https://edge.test/v1/ohttp', {
    method: 'POST', headers: { 'Content-Type': 'message/ohttp-req' }, body: stream, duplex: 'half',
  })), 413);
  assert.equal(cancelled, true);
  const controller = new AbortController();
  let stalledCancelled = false;
  const pending = ohttpContainerRequest(new Request('https://edge.test/v1/ohttp', {
    method: 'POST', headers: { 'Content-Type': 'message/ohttp-req' },
    body: new ReadableStream({ cancel() { stalledCancelled = true; } }), duplex: 'half', signal: controller.signal,
  }));
  controller.abort();
  await rejected(pending, 408);
  assert.equal(stalledCancelled, true);
});

test('the existing mTLS policy fails closed and a public credential cannot replace the edge secret', async () => {
  for (const secret of [undefined, '', 'short', ' '.repeat(64), 'a'.repeat(257), 'a'.repeat(32) + '\n']) {
    await rejected(ohttpDeliveryRequest(incoming('http://delivery.internal/internal/v1/ohttp'), { ...env, MESSENGER_DELIVERY_INTERNAL_TOKEN: secret }), 503);
  }
  await rejected(ohttpDeliveryRequest(incoming('http://delivery.internal/internal/v1/ohttp'), { ...env, MORSE_EDGE_MTLS_CERTIFICATE_ID: 'unsupported' }), 503);
  const policy = { MORSE_SEALED_INGRESS_MTLS: 'required', MORSE_SEALED_INGRESS_ORIGIN: 'https://core.test', MORSE_EDGE_CLIENT_CERT_SHA256: 'f'.repeat(64) };
  const at = () => incoming('https://core.test/v1/ingress/ohttp', 55, { Authorization: `Bearer ${token}` });
  assert.equal(await ohttpIngressRequest(at(), policy), null);
  const valid = at();
  Object.defineProperty(valid, 'cf', { value: { tlsClientAuth: { certPresented: '1', certVerified: 'SUCCESS', certRevoked: '0', certFingerprintSHA256: 'f'.repeat(64) } } });
  assert.ok(await ohttpIngressRequest(valid, policy));
  for (const value of ['', 'account-secret', 'Bearer short']) {
    await rejected(ohttpIngressRequest(incoming('https://core.test/v1/ingress/ohttp', 55, { Authorization: value }), {}), 401);
  }
});

test('successful replies preserve opaque bytes and replace all response metadata', async () => {
  for (const size of [48, maximum]) {
    const raw = response(size, { ...identifying, 'Set-Cookie': 'tracker=1', Etag: 'unique', Location: 'https://target.test', 'Retry-After': '9999' });
    const clean = await ohttpRelayResponse(raw);
    assert.equal(clean.status, 200);
    assert.deepEqual(headers(clean), { 'cache-control': 'no-store', 'content-type': 'message/ohttp-res' });
    assert.deepEqual(new Uint8Array(await clean.arrayBuffer()), new Uint8Array(size).fill(92));
  }
});

test('redirects, malformed successes and outer failures never return plaintext or tracking headers', async () => {
  for (const status of [201, 301, 302, 307, 308, 400, 401, 429, 500, 503]) {
    const out = await ohttpRelayResponse(response(70, { 'Set-Cookie': 'track', Location: 'https://attacker.test' }, status));
    assert.equal(out.status, status >= 400 ? status : 502);
    assert.equal((await out.arrayBuffer()).byteLength, 0);
    assert.deepEqual(headers(out), { 'cache-control': 'no-store' });
  }
  for (const raw of [response(47), response(maximum + 1), response(60, { 'Content-Type': 'text/plain' }),
    response(60, { 'Cache-Control': 'public' }), response(60, { 'Content-Encoding': 'gzip' })]) {
    const out = await ohttpRelayResponse(raw);
    assert.equal(out.status, 502);
    assert.equal((await out.arrayBuffer()).byteLength, 0);
    assert.deepEqual(headers(out), { 'cache-control': 'no-store' });
  }
});

test('transport stream errors and response cancellation produce only empty bounded failures', async () => {
  const broken = new Response(new ReadableStream({ start(c) { c.error(new Error('upstream secret error')); } }), {
    headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store' },
  });
  const out = await ohttpRelayResponse(broken);
  assert.equal(out.status, 502);
  assert.equal(await out.text(), '');
  const controller = new AbortController();
  let cancelled = false;
  const pending = ohttpRelayResponse(new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
    headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store' },
  }), controller.signal);
  controller.abort();
  assert.equal((await pending).status, 502);
  assert.equal(cancelled, true);
});

test('a producer that never finishes cannot outlive the five-second body deadline', async () => {
  let cancelled = false;
  const start = performance.now();
  // AbortSignal.timeout is unreferenced in Node. Keep this test process alive
  // while exercising the real production deadline rather than a fake clock.
  const keepAlive = setInterval(() => {}, 1_000);
  try {
    const out = await ohttpRelayResponse(new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
      headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store' },
    }));
    assert.equal(out.status, 502);
    assert.equal(cancelled, true);
    assert.ok(performance.now() - start >= 4_900);
    assert.ok(performance.now() - start < 8_000);
    assert.equal(await out.text(), '');
  } finally {
    clearInterval(keepAlive);
  }
});

test('many one-byte chunks stay within a bounded retained-memory envelope', () => {
  const child = spawnSync(process.execPath, ['--expose-gc', fileURLToPath(new URL('./ohttp-stream-memory.fixture.mjs', import.meta.url))], {
    encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(child.status, 0, child.stdout + child.stderr);
});

test('a stream with repeated empty chunks is refused without waiting for later data', async () => {
  let chunks = 0;
  let cancelled = false;
  const out = await ohttpRelayResponse(new Response(new ReadableStream({
    pull(c) {
      if (chunks++ < 128) c.enqueue(new Uint8Array());
      else { c.enqueue(new Uint8Array(48)); c.close(); }
    },
    cancel() { cancelled = true; },
  }), { headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store' } }));
  assert.equal(out.status, 502);
  assert.equal(await out.text(), '');
  assert.equal(cancelled, true);
  assert.ok(chunks < 128);
});
