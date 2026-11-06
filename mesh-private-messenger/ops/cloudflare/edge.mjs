import { httpsOrigin } from './witness.mjs';
import { assertSealedEdgeTopology, sealedIngressClientAllowed } from './sealed-ingress-policy.mjs';
import { ohttpConfig } from './ohttp.mjs';

// Sealed delivery only separates "who is sending" from "which mailbox" when the
// component that sees the source connection cannot unseal, and the component
// that unseals never sees the source connection. These helpers keep both sides
// of that boundary in one reviewable place.

const sealedPath = '/internal/v1/envelopes/sealed';
const ingressPath = '/v1/ingress/sealed';
const creditPaths = new Set(['/v1/credits/issuer', '/v1/credits/quote', '/v1/credits/issue', '/v1/credits/lightning/quote', '/v1/credits/lightning/issue', '/v1/credits/retention', '/v1/credits/signup', '/v1/credits/signup-policy', '/v1/credits/reconcile', '/v1/credits/postage', '/v1/credits/postage/reconcile', '/v1/credits/postage-policy']);

// Headers a Mesh service legitimately reads. Everything else, including every
// client address, location, agent, and cookie header, stops at the Worker.
const forwardedHeaders = ['content-type', 'authorization'];
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
  const headers = pick(request.headers, creditPaths.has(new URL(request.url).pathname)
    ? ['content-type'] : upgrade ? [...forwardedHeaders, ...upgradeHeaders] : forwardedHeaders);
  return new Request(request.url, {
    method: request.method, headers, redirect: 'manual',
    ...(request.body ? { body: request.body, duplex: 'half' } : {}),
  });
}

function sealedHeaders(request) {
  const headers = pick(request.headers, ['authorization']);
  headers.set('content-type', 'application/octet-stream');
  return headers;
}

export function edgeContainerEnv(env) {
  if (!env.MESSENGER_DELIVERY_INTERNAL_TOKEN) throw new Error('Missing MESSENGER_DELIVERY_INTERNAL_TOKEN');
  return {
    ...ohttpConfig(env),
    MESSENGER_DELIVERY_INTERNAL_TOKEN: env.MESSENGER_DELIVERY_INTERNAL_TOKEN,
    MESSENGER_DELIVERY_INTERNAL_URL: 'http://delivery.internal',
    ...(env.MORSE_CREDIT_ISSUER_URL ? (() => {
      httpsOrigin(env.MORSE_CREDIT_ISSUER_URL);
      if (!env.MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN) throw new Error('Missing MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN');
      return { MESSENGER_CREDIT_ISSUER_INTERNAL_URL: 'http://issuer.internal',
        MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN: env.MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN };
    })() : {}),
  };
}

// The isolated edge serves sealed delivery and anonymous credit purchases.
export function edgeRoute(request) {
  const url = new URL(request.url);
  return request.method === 'POST' && (url.pathname === '/v1/envelopes/batch' || creditPaths.has(url.pathname)) && !url.search;
}

export function creditIssuerRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.search ||
      !['/internal/v1/credits/quote', '/internal/v1/credits/issue', '/internal/v1/credits/lightning/quote', '/internal/v1/credits/lightning/issue'].includes(url.pathname)) return null;
  return new Request(`${httpsOrigin(env.MORSE_CREDIT_ISSUER_URL)}${url.pathname}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

export function creditDiscoveryRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || !['/v1/credits/issuer', '/v1/credits/retention', '/v1/credits/signup', '/v1/credits/signup-policy', '/v1/credits/reconcile', '/v1/credits/postage-policy'].includes(url.pathname) || url.search) return null;
  return new Request(`${httpsOrigin(env.MORSE_DELIVERY_URL)}${url.pathname}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: { 'Content-Type': 'application/octet-stream' }, signal: AbortSignal.timeout(30_000),
  });
}

// A fixed container virtual host, intercepted by ObjectStore.outboundByHost.
// This cannot become an arbitrary core-admin proxy or carry client metadata.
export function creditAttachmentRequest(request) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.origin !== 'http://credit-core.internal' ||
      url.pathname !== '/internal/credits/attachments/grant' || url.search || url.hash) return null;
  return new Request(request.url, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

// Edge container -> delivery core, across deployments. Only the sealed record
// and the edge's bearer credential leave the edge.
export function sealedDeliveryRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== sealedPath || url.search) return null;
  assertSealedEdgeTopology(env);
  return new Request(`${httpsOrigin(env.MORSE_DELIVERY_URL)}${ingressPath}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

// Isolated backend: the public sealed-ingress route maps onto the delivery
// core's bearer-authenticated internal route.
export function sealedIngressRequest(request, env = {}) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== ingressPath || url.search || url.hash || !sealedIngressClientAllowed(request, env)) return null;
  url.pathname = sealedPath;
  return new Request(url, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual', headers: sealedHeaders(request),
  });
}

// Only opaque postage carriers and encrypted replies traverse this hop. These
// two paths never map to the generic plaintext action redemption or recovery.
export function postageDeliveryRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.origin !== 'http://delivery.internal' || url.search || url.hash ||
      !['/internal/credits/postage', '/internal/credits/postage/reconcile'].includes(url.pathname)) return null;
  const path = url.pathname.replace('/internal/credits/', '/v1/ingress/');
  return new Request(`${httpsOrigin(env.MORSE_DELIVERY_URL)}${path}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

export function postageIngressRequest(request) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.search || url.hash ||
      !['/v1/ingress/postage', '/v1/ingress/postage/reconcile'].includes(url.pathname)) return null;
  url.pathname = url.pathname.replace('/v1/ingress/', '/internal/credits/');
  return new Request(url, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual', headers: sealedHeaders(request),
  });
}
