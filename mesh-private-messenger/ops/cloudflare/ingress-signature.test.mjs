import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { forwardSealed, sealedIngress } from './edge.mjs';
import { ingressMessage, signedIngressRequest } from './ingress-signature.mjs';
import { isolatedConfig } from './prepare-build.mjs';

const token = 'c'.repeat(64);
const now = 1_790_000_000_000;
const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const isolation = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://push.test' };

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { seed: Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url').toString('hex'),
    publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') };
}
const edgeKey = keyPair();
const otherKey = keyPair();

// The edge's outbound request as its container sends it.
const outbound = (body = new Uint8Array([1, 2, 3])) => new Request('http://delivery.internal/internal/v1/envelopes/sealed', {
  method: 'POST', body, headers: { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '203.0.113.9' } });

async function signed({ key = edgeKey.seed, at = now, body, host = 'api.morse.test' } = {}) {
  const request = new Request(`https://${host}/v1/ingress/sealed`, {
    method: 'POST', body: body ?? new Uint8Array([1, 2, 3]),
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' } });
  return signedIngressRequest(request, key, at);
}

const rehost = async (request, host) => new Request(`https://${host}/v1/ingress/sealed`, {
  method: 'POST', headers: request.headers, body: await request.arrayBuffer() });

function backend(vars = {}) {
  const forwarded = [];
  const seen = new Map();
  return { forwarded, env: {
    MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    MORSE_EDGE_INGRESS_PUBLIC_KEY: edgeKey.publicKey,
    INGRESS_NONCES: { getByName: () => ({ claim: async (nonce, expires) => {
      if (seen.has(nonce)) return false;
      seen.set(nonce, expires);
      return true;
    } }) },
    DIRECTORY: { getByName: () => ({ fetch: async request => { forwarded.push(request); return new Response(null, { status: 202 }); } }) },
    ...vars,
  } };
}

test('M2 the canonical ingress message binds method, host, path, time, nonce and the body hash', () => {
  assert.equal(new TextDecoder().decode(ingressMessage({ method: 'POST', host: 'api.morse.test', path: '/v1/ingress/sealed',
    timestamp: 1790000000, nonce: '00112233445566778899aabbccddeeff', bodyHash: 'ab'.repeat(32) })),
  `morse-ingress-v1\nPOST\napi.morse.test\n/v1/ingress/sealed\n1790000000\n00112233445566778899aabbccddeeff\n${'ab'.repeat(32)}`);
});

test('M2 the backend admits only requests signed by the pinned edge key, fresh and once, before the bearer', async () => {
  const { env, forwarded } = backend();
  const valid = await signed();
  const replay = valid.clone();
  assert.equal((await sealedIngress(valid, env, now)).status, 202);
  assert.deepEqual(new Uint8Array(await forwarded[0].arrayBuffer()), new Uint8Array([1, 2, 3]));
  assert.deepEqual([...forwarded[0].headers.keys()].sort(), ['authorization', 'content-type'], 'no signature header reaches the core');

  const unsigned = new Request('https://api.morse.test/v1/ingress/sealed', { method: 'POST', body: 'x', headers: { Authorization: `Bearer ${token}` } });
  const tampered = await signed();
  const tamperedBody = new Request(tampered.url, { method: 'POST', headers: tampered.headers, body: new Uint8Array([1, 2, 4]) });
  const noBearer = await signed();
  noBearer.headers.delete('authorization');
  for (const [name, request, status, at = now] of [
    ['replayed', replay, 403],
    ['missing', unsigned, 403],
    ['wrong key', await signed({ key: otherKey.seed }), 403],
    ['body tampered', tamperedBody, 403],
    ['stale', await signed({ at: now - 61_000 }), 403],
    ['from the future', await signed({ at: now + 61_000 }), 403],
    ['signed for another backend', await rehost(await signed({ host: 'canary.morse.test' }), 'api.morse.test'), 403],
    ['bearer missing after a valid signature', noBearer, 401],
  ]) {
    const before = forwarded.length;
    assert.equal((await sealedIngress(request, env, at)).status, status, name);
    assert.equal(forwarded.length, before, `${name}: never reaches the delivery core`);
  }
});

test('M2 edge keys rotate by pinning both; a bad pin or a missing nonce store fails closed; no pin keeps the bearer alone', async () => {
  const rotating = backend({ MORSE_EDGE_INGRESS_PUBLIC_KEY: `${otherKey.publicKey},${edgeKey.publicKey}` });
  assert.equal((await sealedIngress(await signed({ key: otherKey.seed }), rotating.env, now)).status, 202);
  assert.equal((await sealedIngress(await signed(), rotating.env, now)).status, 202);
  const rotated = backend({ MORSE_EDGE_INGRESS_PUBLIC_KEY: otherKey.publicKey });
  assert.equal((await sealedIngress(await signed(), rotated.env, now)).status, 403);

  for (const vars of [{ MORSE_EDGE_INGRESS_PUBLIC_KEY: `${edgeKey.publicKey},` }, { INGRESS_NONCES: undefined }]) {
    const { env, forwarded } = backend(vars);
    assert.equal((await sealedIngress(await signed(), env, now)).status, 503);
    assert.equal(forwarded.length, 0);
  }
  const { env } = backend({ MORSE_EDGE_INGRESS_PUBLIC_KEY: undefined });
  assert.equal((await sealedIngress(new Request('https://api.morse.test/v1/ingress/sealed', {
    method: 'POST', body: 'x', headers: { Authorization: `Bearer ${token}` } }), env, now)).status, 202);
});

test('M2 the edge signs what it forwards with its own key, and the backend accepts exactly that', async () => {
  const sent = [];
  const edgeEnv = { MORSE_DELIVERY_URL: 'https://api.morse.test', MORSE_EDGE_INGRESS_SIGNING_KEY: edgeKey.seed };
  const response = await forwardSealed(outbound(), edgeEnv, async request => { sent.push(request); return new Response(null, { status: 204 }); });
  assert.equal(response.status, 204);
  assert.deepEqual([...sent[0].headers.keys()].sort(),
    ['authorization', 'content-type', 'morse-ingress-nonce', 'morse-ingress-signature', 'morse-ingress-timestamp']);
  const { env } = backend();
  assert.equal((await sealedIngress(sent[0], env, Date.now())).status, 202);
  // Without the key the edge sends as before, unsigned.
  const plain = [];
  await forwardSealed(outbound(), { MORSE_DELIVERY_URL: 'https://api.morse.test' }, async request => { plain.push(request); return new Response(null, { status: 204 }); });
  assert.equal(plain[0].headers.get('morse-ingress-signature'), null);
});

test('credits: the redeem call is signed and verified like the sealed record, and a signature does not move between paths', async () => {
  const redeem = new Request('http://delivery.internal/internal/v1/credits/redeem', {
    method: 'POST', body: new Uint8Array([8, 9]), headers: { Authorization: `Bearer ${token}` } });
  const edgeEnv = { MORSE_DELIVERY_URL: 'https://api.morse.test', MORSE_EDGE_INGRESS_SIGNING_KEY: edgeKey.seed };
  const sent = [];
  assert.equal((await forwardSealed(redeem, edgeEnv, async request => { sent.push(request); return new Response(null, { status: 201 }); })).status, 201);
  assert.equal(sent[0].url, 'https://api.morse.test/v1/ingress/credits/redeem');
  const { env, forwarded } = backend();
  const copy = new Request(sent[0].url, { method: 'POST', headers: sent[0].headers, body: await sent[0].clone().arrayBuffer() });
  assert.equal((await sealedIngress(sent[0], env, Date.now())).status, 202);
  assert.equal(new URL(forwarded[0].url).pathname, '/internal/v1/credits/redeem');
  const moved = new Request('https://api.morse.test/v1/ingress/sealed', { method: 'POST', headers: copy.headers, body: await copy.arrayBuffer() });
  assert.equal((await sealedIngress(moved, backend().env, Date.now())).status, 403);
});

test('M2 the backend build pins the edge public keys', () => {
  const pinned = isolatedConfig(original, { ...isolation, MORSE_EDGE_INGRESS_PUBLIC_KEY: `${edgeKey.publicKey.toUpperCase()}, ${otherKey.publicKey}` });
  assert.equal(pinned.vars.MORSE_EDGE_INGRESS_PUBLIC_KEY, `${edgeKey.publicKey},${otherKey.publicKey}`);
  assert.equal(isolatedConfig(original, isolation).vars.MORSE_EDGE_INGRESS_PUBLIC_KEY, undefined);
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_EDGE_INGRESS_PUBLIC_KEY: 'abc' }), /Ed25519 public key/);
  assert.ok(original.durable_objects.bindings.some(x => x.name === 'INGRESS_NONCES' && x.class_name === 'IngressNonces'));
  assert.ok(isolatedConfig(original, isolation).durable_objects.bindings.some(x => x.name === 'INGRESS_NONCES'));
});

test('M2 the nonce store accepts each nonce once within its window and forgets it afterwards', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-nonces-'));
  const options = convertV4MiniflareOptions({
    name: 'morse-nonce-test', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: `
        export { IngressNonces } from './ingress-nonces.mjs';
        export default { async fetch(request, env) {
          const { nonce, expires } = await request.json();
          return Response.json(await env.INGRESS_NONCES.getByName('primary').claim(nonce, expires));
        } };` },
      { type: 'ESModule', path: 'ingress-nonces.mjs', contents: await readFile(new URL('./ingress-nonces.mjs', import.meta.url), 'utf8') },
    ],
    durableObjects: { INGRESS_NONCES: { className: 'IngressNonces', useSQLite: true, unsafeUniqueKey: 'morse-nonce-test' } },
  });
  options.resourcePersistencePath = directory;
  const mf = new Miniflare(options);
  const claim = async (nonce, expires) => (await mf.dispatchFetch('http://test', { method: 'POST', body: JSON.stringify({ nonce, expires }) })).json();
  try {
    const later = Date.now() + 60_000;
    assert.equal(await claim('a'.repeat(32), later), true);
    assert.equal(await claim('a'.repeat(32), later), false);
    assert.equal(await claim('b'.repeat(32), Date.now() - 1), true);
    // An expired nonce's timestamp can no longer pass the window, so it is dropped.
    assert.equal(await claim('b'.repeat(32), later), true);
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test('M2 the key helper writes the edge signing key outside the repository and prints the backend pin', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { existsSync, mkdtempSync, rmSync, statSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const run = promisify(execFile);
  const script = fileURLToPath(new URL('./ingress-key.mjs', import.meta.url));
  const parent = mkdtempSync(join(tmpdir(), 'morse-ingress-key-'));
  const out = join(parent, 'key');
  try {
    const { stdout } = await run(process.execPath, [script, out]);
    const path = join(out, 'edge-ingress-signing-key.hex');
    assert.equal(statSync(out).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o077, 0);
    const seed = readFileSync(path, 'utf8');
    assert.match(seed, /^[a-f0-9]{64}$/);
    assert.ok(!stdout.includes(seed), 'the private key is never printed');
    const publicKey = stdout.match(/^MORSE_EDGE_INGRESS_PUBLIC_KEY=([a-f0-9]{64})$/m)[1];
    const { env } = backend({ MORSE_EDGE_INGRESS_PUBLIC_KEY: publicKey });
    assert.equal((await sealedIngress(await signed({ key: seed }), env, now)).status, 202);
    await assert.rejects(run(process.execPath, [script, out]), /not empty/);
    const inside = fileURLToPath(new URL('./.ingress-key-refused', import.meta.url));
    await assert.rejects(run(process.execPath, [script, inside]), /outside the repository/);
    assert.equal(existsSync(inside), false);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('M2 signing and verification run in workerd with its WebCrypto Ed25519', async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({
    name: 'morse-signature-workerd', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: `
        import { signedIngressRequest, verifiedIngressBody } from './ingress-signature.mjs';
        export default { async fetch(request, env) {
          const seen = new Set();
          const nonces = { getByName: () => ({ claim: async nonce => !seen.has(nonce) && Boolean(seen.add(nonce)) }) };
          const signed = await signedIngressRequest(new Request('https://api.morse.test/v1/ingress/sealed', { method: 'POST', body: 'sealed' }), env.SEED);
          const verified = await verifiedIngressBody(signed.clone(), { MORSE_EDGE_INGRESS_PUBLIC_KEY: env.PUBLIC_KEY, INGRESS_NONCES: nonces });
          const replayed = await verifiedIngressBody(signed, { MORSE_EDGE_INGRESS_PUBLIC_KEY: env.PUBLIC_KEY, INGRESS_NONCES: nonces });
          return Response.json({ body: new TextDecoder().decode(verified.body), replayed: replayed.status });
        } };` },
      ...await Promise.all(['ingress-signature', 'storage'].map(async name => ({ type: 'ESModule', path: `${name}.mjs`,
        contents: await readFile(new URL(`./${name}.mjs`, import.meta.url), 'utf8') }))),
    ],
    bindings: { SEED: edgeKey.seed, PUBLIC_KEY: edgeKey.publicKey },
  }));
  try {
    assert.deepEqual(await (await mf.dispatchFetch('http://test')).json(), { body: 'sealed', replayed: 403 });
  } finally {
    await mf.dispose();
  }
});
