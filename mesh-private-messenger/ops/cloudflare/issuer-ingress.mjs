import { boundedBody } from './storage.mjs';

// Deliberately separate from the privacy edge. The core authenticates this
// credential before decoding or touching issuer keys. No generic admin proxy.
const operations = new Map([
  ['POST announce', { type: 'application/json', limit: 2048 }],
  ['POST evidence', { type: 'application/octet-stream', limit: 13 }],
  ['POST admit', { type: 'application/json', limit: 140000 }],
  ['GET cursor', { type: 'application/octet-stream', limit: 0 }],
]);

export function issuerIngressOperation(request) {
  const url = new URL(request.url);
  const match = /^\/v1\/ingress\/credits\/issuers\/([a-z]+)$/.exec(url.pathname);
  return !url.search && match && operations.has(`${request.method} ${match[1]}`) ? match[1] : null;
}

export async function issuerIngressRequest(request) {
  const operation = issuerIngressOperation(request);
  if (!operation) return null;
  const authorization = request.headers.get('authorization');
  if (!authorization?.startsWith('Bearer ') || authorization.length > 263) {
    return new Response(null, { status: 401 });
  }
  const policy = operations.get(`${request.method} ${operation}`);
  const body = await boundedBody(request, policy.limit);
  if (!body) return new Response(null, { status: 413 });
  const url = new URL(request.url);
  url.pathname = `/internal/credits/issuers/${operation}`;
  return new Request(url, {
    method: request.method, redirect: 'manual',
    headers: { 'Content-Type': policy.type, Authorization: authorization },
    ...(request.method === 'POST' ? { body } : {}),
  });
}
