import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { forwardSealed, sealedIngress } from './edge.mjs';
import { edgeConfig, isolatedConfig } from './prepare-build.mjs';

const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const token = 'c'.repeat(64);
const fingerprint = 'ab'.repeat(32);
const issuer = 'CN=Morse edge ingress CA';
const isolation = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://push.test' };

// request.cf.tlsClientAuth as Cloudflare fills it for a hostname with client
// certificate verification on.
const verified = { certPresented: '1', certVerified: 'SUCCESS', certRevoked: '0',
  certFingerprintSHA256: fingerprint, certIssuerDNRFC2253: issuer };

function ingress(tlsClientAuth, headers = { Authorization: `Bearer ${token}` }) {
  const request = new Request('https://ingress.morse.test/v1/ingress/sealed', { method: 'POST', body: new Uint8Array([7]), headers });
  if (tlsClientAuth !== undefined) request.cf = { tlsClientAuth };
  return request;
}

function backend(vars = {}) {
  const calls = [];
  return { calls, env: {
    MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    // The pin as an operator pastes it from openssl: colon-separated, upper case.
    MORSE_INGRESS_CLIENT_CERT_SHA256: fingerprint.toUpperCase().match(/../g).join(':'),
    MORSE_INGRESS_CLIENT_CERT_ISSUER: issuer,
    DIRECTORY: { getByName: () => ({ fetch: async request => { calls.push(request); return new Response(null, { status: 202 }); } }) },
    ...vars,
  } };
}

test('M2 the sealed ingress admits only the pinned, verified edge certificate together with the bearer', async () => {
  for (const [name, auth, headers, status] of [
    ['valid', verified, undefined, 202],
    ['no certificate information', undefined, undefined, 403],
    ['no certificate presented', { ...verified, certPresented: '0', certVerified: 'NONE', certFingerprintSHA256: '' }, undefined, 403],
    ['unverified', { ...verified, certVerified: 'FAILED:self signed certificate' }, undefined, 403],
    ['revoked', { ...verified, certRevoked: '1' }, undefined, 403],
    ['wrong fingerprint', { ...verified, certFingerprintSHA256: 'cd'.repeat(32) }, undefined, 403],
    ['wrong issuer', { ...verified, certIssuerDNRFC2253: 'CN=Someone else' }, undefined, 403],
    ['bearer missing', verified, {}, 401],
    ['wrong bearer', verified, { Authorization: `Bearer ${'d'.repeat(64)}` }, 401],
  ]) {
    const { env, calls } = backend();
    const response = await sealedIngress(ingress(auth, headers), env);
    assert.equal(response.status, status, name);
    assert.equal(calls.length, status === 202 ? 1 : 0, `${name}: a refused request never reaches the delivery core`);
  }

  const { env, calls } = backend();
  await sealedIngress(ingress(verified), env);
  const [forwarded] = calls;
  assert.equal(new URL(forwarded.url).pathname, '/internal/v1/envelopes/sealed');
  assert.deepEqual([...forwarded.headers.keys()].sort(), ['authorization', 'content-type']);
});

test('M2 certificate rotation pins two fingerprints; a malformed pin fails closed', async () => {
  const rotated = backend({ MORSE_INGRESS_CLIENT_CERT_SHA256: `${'cd'.repeat(32)},${fingerprint}`, MORSE_INGRESS_CLIENT_CERT_ISSUER: undefined });
  assert.equal((await sealedIngress(ingress(verified), rotated.env)).status, 202);
  // A trailing comma must not pin "no fingerprint".
  for (const pin of [`${fingerprint},`, 'not-hex']) {
    const { env, calls } = backend({ MORSE_INGRESS_CLIENT_CERT_SHA256: pin });
    assert.equal((await sealedIngress(ingress({ ...verified, certFingerprintSHA256: '' }), env)).status, 503, pin);
    assert.equal(calls.length, 0);
  }
  const unconfigured = backend({ MESSENGER_DELIVERY_INTERNAL_TOKEN: '' });
  assert.equal((await sealedIngress(ingress(verified), unconfigured.env)).status, 503);
});

test('M2 without a pinned certificate the bearer is the only guard, as before the operator step', async () => {
  const { env } = backend({ MORSE_INGRESS_CLIENT_CERT_SHA256: undefined, MORSE_INGRESS_CLIENT_CERT_ISSUER: undefined });
  assert.equal((await sealedIngress(ingress(undefined), env)).status, 202);
  assert.equal((await sealedIngress(ingress(undefined, {}), env)).status, 401);
});

test('M2 the edge presents its client certificate through the mTLS binding, never a plain fetch', async () => {
  const presented = [];
  const env = { MORSE_DELIVERY_URL: 'https://ingress.morse.test',
    DELIVERY_CLIENT_CERT: { fetch: async request => { presented.push(request); return new Response(null, { status: 204 }); } } };
  const plain = async () => assert.fail('the edge must not send without its certificate');
  const outbound = () => new Request('http://delivery.internal/internal/v1/envelopes/sealed', {
    method: 'POST', body: new Uint8Array([1]), headers: { Authorization: `Bearer ${token}`, 'CF-Connecting-IP': '203.0.113.9' } });
  assert.equal((await forwardSealed(outbound(), env, plain)).status, 204);
  assert.equal(presented[0].url, 'https://ingress.morse.test/v1/ingress/sealed');
  assert.deepEqual([...presented[0].headers.keys()].sort(), ['authorization', 'content-type']);

  env.DELIVERY_CLIENT_CERT.fetch = async () => new Response(null, { status: 302, headers: { Location: 'https://elsewhere.test' } });
  assert.equal((await forwardSealed(outbound(), env, plain)).status, 502);
  assert.equal((await forwardSealed(new Request('http://delivery.internal/v1/mailbox/fetch', { method: 'POST' }), env, plain)).status, 404);
  // Before the operator uploads a certificate the edge sends with its bearer alone.
  let plainCalls = 0;
  const response = await forwardSealed(outbound(), { MORSE_DELIVERY_URL: env.MORSE_DELIVERY_URL }, async () => { plainCalls++; return new Response(null, { status: 204 }); });
  assert.equal(response.status, 204);
  assert.equal(plainCalls, 1);
});

test('M2 builds bind the edge certificate and pin it on the backend, on its own ingress hostname', () => {
  const id = '0f1e2d3c-4b5a-4968-8776-655443322110';
  const edge = edgeConfig(original, { MORSE_DELIVERY_URL: 'https://ingress.morse.test', MORSE_EDGE_CLIENT_CERT_ID: id });
  assert.deepEqual(edge.mtls_certificates, [{ binding: 'DELIVERY_CLIENT_CERT', certificate_id: id }]);
  assert.equal(edgeConfig(original, { MORSE_DELIVERY_URL: 'https://ingress.morse.test' }).mtls_certificates, undefined);
  assert.throws(() => edgeConfig(original, { MORSE_DELIVERY_URL: 'https://ingress.morse.test', MORSE_EDGE_CLIENT_CERT_ID: 'x' }), /certificate ID/);

  const pinned = isolatedConfig(original, { ...isolation, MORSE_INGRESS_CLIENT_CERT_SHA256: fingerprint.toUpperCase().match(/../g).join(':'),
    MORSE_INGRESS_CLIENT_CERT_ISSUER: issuer, MORSE_INGRESS_HOSTNAME: 'ingress.morse.test' });
  assert.equal(pinned.vars.MORSE_INGRESS_CLIENT_CERT_SHA256, fingerprint);
  assert.equal(pinned.vars.MORSE_INGRESS_CLIENT_CERT_ISSUER, issuer);
  assert.deepEqual(pinned.routes, [{ pattern: 'ingress.morse.test', custom_domain: true }]);
  // The backend never holds the edge's certificate.
  assert.equal(pinned.mtls_certificates, undefined);
  const plain = isolatedConfig(original, isolation);
  assert.equal(plain.vars.MORSE_INGRESS_CLIENT_CERT_SHA256, undefined);
  assert.equal(plain.routes, undefined);
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_INGRESS_CLIENT_CERT_SHA256: 'abc' }), /fingerprint/);
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_INGRESS_HOSTNAME: 'https://ingress.morse.test/' }), /hostname/);
});
