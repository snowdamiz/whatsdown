import { httpsOrigin } from './witness.mjs';

// Sealed delivery only separates "who is sending" from "which mailbox" when the
// component that sees the source connection cannot unseal, and the component
// that unseals never sees the source connection. These helpers keep both sides
// of that boundary in one reviewable place.

const sealedPath = '/internal/v1/envelopes/sealed';
const ingressPath = '/v1/ingress/sealed';

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
  const headers = pick(request.headers, upgrade ? [...forwardedHeaders, ...upgradeHeaders] : forwardedHeaders);
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
    MESSENGER_DELIVERY_INTERNAL_TOKEN: env.MESSENGER_DELIVERY_INTERNAL_TOKEN,
    MESSENGER_DELIVERY_INTERNAL_URL: 'http://delivery.internal',
  };
}

// The isolated edge Worker serves exactly one public route.
export function edgeRoute(request) {
  const url = new URL(request.url);
  return request.method === 'POST' && url.pathname === '/v1/envelopes/batch' && !url.search;
}

// Edge container -> delivery core, across deployments. Only the sealed record
// and the edge's bearer credential leave the edge.
export function sealedDeliveryRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== sealedPath || url.search) return null;
  return new Request(`${httpsOrigin(env.MORSE_DELIVERY_URL)}${ingressPath}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: sealedHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

// Isolated backend: the public sealed-ingress route maps onto the delivery
// core's bearer-authenticated internal route.
export function sealedIngressRequest(request) {
  const url = new URL(request.url);
  url.pathname = sealedPath;
  return new Request(url, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual', headers: sealedHeaders(request),
  });
}
