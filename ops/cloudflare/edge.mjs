import { timingSafeEqual } from 'node:crypto';
import { httpsOrigin } from './witness.mjs';
import { signedIngressRequest, verifiedIngressBody } from './ingress-signature.mjs';

// Sealed delivery only separates "who is sending" from "which mailbox" when the
// component that sees the source connection cannot unseal, and the component
// that unseals never sees the source connection. These helpers keep both sides
// of that boundary in one reviewable place.

const sealedPath = '/internal/v1/envelopes/sealed';
const ingressPath = '/v1/ingress/sealed';
// The edge redeems a request's credits at the core before it forwards the
// sealed record (protocol/credits-v1.md): same guards, its own paths.
const redeemPath = '/internal/v1/credits/redeem';
const redeemIngressPath = '/v1/ingress/credits/redeem';
// Longer storage, bought through the edge with credits (protocol/credits-v1.md).
const retentionPath = '/internal/v1/mailbox/retention';
const retentionIngressPath = '/v1/ingress/mailbox/retention';
// Oblivious HTTP (protocol/ohttp-v1.md): the edge relays encapsulated requests
// to the core's gateway, which it reaches the same way.
const ohttpPath = '/internal/v1/ohttp';
const ohttpIngressPath = '/v1/ingress/ohttp';
const ingressPaths = new Map([[sealedPath, ingressPath], [redeemPath, redeemIngressPath], [retentionPath, retentionIngressPath],
  [ohttpPath, ohttpIngressPath]]);
const internalPaths = new Map([[ingressPath, sealedPath], [redeemIngressPath, redeemPath], [retentionIngressPath, retentionPath],
  [ohttpIngressPath, ohttpPath]]);
const ohttpPaths = new Set([ohttpPath, ohttpIngressPath]);

// Headers a Mesh service legitimately reads (Accept picks the KTW version).
// Everything else, including every client address, location, agent, and
// cookie header, stops at the Worker.
const forwardedHeaders = ['content-type', 'authorization', 'accept'];
const upgradeHeaders = ['upgrade', 'connection', 'sec-websocket-key', 'sec-websocket-version',
  'sec-websocket-protocol', 'sec-websocket-extensions'];

function pick(source, names) {
  const headers = new Headers();
  for (const name of names) {
    const value = source.get(name);
    if (value !== null) headers.set(name, value);
  }
  return headers;
}

export function containerRequest(request) {
  const upgrade = request.headers.get('upgrade')?.toLowerCase() === 'websocket';
  const headers = pick(request.headers, upgrade ? [...forwardedHeaders, ...upgradeHeaders] : forwardedHeaders);
  return new Request(request.url, {
    method: request.method, headers, redirect: 'manual',
    ...(request.body ? { body: request.body, duplex: 'half' } : {}),
  });
}

function sealedHeaders(request) {
  const headers = pick(request.headers, ['authorization']);
  headers.set('content-type', ohttpPaths.has(new URL(request.url).pathname) ? 'message/ohttp-req' : 'application/octet-stream');
  return headers;
}

export function edgeContainerEnv(env) {
  if (!env.MESSENGER_DELIVERY_INTERNAL_TOKEN) throw new Error('Missing MESSENGER_DELIVERY_INTERNAL_TOKEN');
  return {
    MESSENGER_DELIVERY_INTERNAL_TOKEN: env.MESSENGER_DELIVERY_INTERNAL_TOKEN,
    MESSENGER_DELIVERY_INTERNAL_URL: 'http://delivery.internal',
    // Credit purchases pass through the edge so the issuer never sees a buyer.
    ...(env.MORSE_CREDIT_ISSUER_URL ? { MORSE_CREDIT_ISSUER_URL: 'http://issuer.internal' } : {}),
  };
}

const issuerPaths = new Set(['/v1/credits/quote', '/v1/credits/issue']);

// The isolated edge Worker serves envelope submission and, when an issuer is
// configured, the two credit purchase routes.
export function edgeRoute(request, env = {}) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.search) return false;
  return url.pathname === '/v1/envelopes/batch' || url.pathname === '/v1/mailbox/retention' || url.pathname === '/v1/ohttp'
    || (Boolean(env.MORSE_CREDIT_ISSUER_URL) && issuerPaths.has(url.pathname));
}

// Edge container -> credit issuer: the body and its type, nothing else.
// The edge Worker adds its own issuer bearer (MORSE_CREDIT_EDGE_TOKEN), which
// its container never holds.
export function issuerRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || !issuerPaths.has(url.pathname) || url.search || !env.MORSE_CREDIT_ISSUER_URL) return null;
  const headers = { 'content-type': 'application/octet-stream',
    ...(env.MORSE_CREDIT_EDGE_TOKEN ? { authorization: `Bearer ${env.MORSE_CREDIT_EDGE_TOKEN}` } : {}) };
  return new Request(`${httpsOrigin(env.MORSE_CREDIT_ISSUER_URL)}${url.pathname}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers, signal: AbortSignal.timeout(60_000),
  });
}

// Edge container -> delivery core, across deployments. Only the sealed record
// and the edge's bearer credential leave the edge.
export function sealedDeliveryRequest(request, env) {
  const url = new URL(request.url);
  const target = ingressPaths.get(url.pathname);
  if (request.method !== 'POST' || !target || url.search) return null;
  return new Request(`${httpsOrigin(env.MORSE_DELIVERY_URL)}${target}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

// Isolated backend: the public sealed-ingress route maps onto the delivery
// core's bearer-authenticated internal route.
export function sealedIngressRequest(request, body = request.body) {
  const url = new URL(request.url);
  url.pathname = internalPaths.get(url.pathname) ?? sealedPath;
  return new Request(url, {
    method: 'POST', body, duplex: 'half', redirect: 'manual', headers: sealedHeaders(request),
  });
}

// Edge side of M2: credentials that live only in the edge deployment. With
// MORSE_EDGE_INGRESS_SIGNING_KEY (a Worker secret the container never sees) the
// edge signs each sealed record; with the DELIVERY_CLIENT_CERT mTLS binding it
// sends through that certificate. Without either it sends with its bearer alone.
export async function forwardSealed(request, env, plainFetch = fetch) {
  let forwarded = sealedDeliveryRequest(request, env);
  if (!forwarded) return new Response(null, { status: 404 });
  if (env.MORSE_EDGE_INGRESS_SIGNING_KEY) forwarded = await signedIngressRequest(forwarded, env.MORSE_EDGE_INGRESS_SIGNING_KEY);
  if (!forwarded) return new Response(null, { status: 413 });
  const response = await (env.DELIVERY_CLIENT_CERT ? env.DELIVERY_CLIENT_CERT.fetch(forwarded) : plainFetch(forwarded));
  if (response.status >= 300 && response.status < 400) return new Response(null, { status: 502 });
  return response;
}

export function bearerMatches(request, token) {
  const encoder = new TextEncoder();
  const supplied = encoder.encode(request.headers.get('authorization') ?? '');
  const expected = encoder.encode(`Bearer ${token}`);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

const fingerprintHex = value => String(value ?? '').replaceAll(':', '').toLowerCase();

// "ab:CD:..." or "abcd...", comma-separated for rotation -> lowercase hex list.
export function certificatePins(value) {
  const pins = String(value).split(',').map(x => fingerprintHex(x.trim()));
  if (!pins.every(x => /^[a-f0-9]{64}$/.test(x))) throw new Error('Expected SHA-256 certificate fingerprints');
  return pins;
}

function certificateStatus(request, env) {
  if (env.MORSE_INGRESS_CLIENT_CERT_SHA256) {
    let pins;
    try { pins = certificatePins(env.MORSE_INGRESS_CLIENT_CERT_SHA256); } catch { return 503; }
    const cert = request.cf?.tlsClientAuth;
    const admitted = cert?.certPresented === '1' && cert.certVerified === 'SUCCESS' && cert.certRevoked !== '1'
      && pins.includes(fingerprintHex(cert.certFingerprintSHA256))
      && (!env.MORSE_INGRESS_CLIENT_CERT_ISSUER || cert.certIssuerDNRFC2253 === env.MORSE_INGRESS_CLIENT_CERT_ISSUER);
    if (!admitted) return 403;
  }
  return 0;
}

// Backend side of M2. Once MORSE_EDGE_INGRESS_PUBLIC_KEY is set, the sealed
// ingress needs the edge's signature (pinned key, fresh, nonce not seen); once
// MORSE_INGRESS_CLIENT_CERT_SHA256 is set, the edge's client certificate
// (verified by the zone and pinned here). Only then is the bearer checked, and
// nothing refused reaches the delivery core.
export async function sealedIngress(request, env, now = Date.now()) {
  const certificate = certificateStatus(request, env);
  if (certificate) return new Response(null, { status: certificate });
  let body = request.body;
  if (env.MORSE_EDGE_INGRESS_PUBLIC_KEY) {
    const signed = await verifiedIngressBody(request, env, now);
    if (signed.status) return new Response(null, { status: signed.status });
    body = signed.body;
  }
  if (!env.MESSENGER_DELIVERY_INTERNAL_TOKEN) return new Response(null, { status: 503 });
  if (!bearerMatches(request, env.MESSENGER_DELIVERY_INTERNAL_TOKEN)) return new Response(null, { status: 401 });
  return env.DIRECTORY.getByName('primary').fetch(sealedIngressRequest(request, body));
}
