import { boundedBody } from './storage.mjs';

// §22 M2 without mTLS: the edge signs every sealed-ingress request with an
// Ed25519 key that only the edge deployment holds, and the backend verifies it
// against pinned public keys before it checks the bearer. The format is
// protocol/sealed-delivery-v1.md, "Edge request signatures".

export const ingressHeaders = { timestamp: 'morse-ingress-timestamp', nonce: 'morse-ingress-nonce', signature: 'morse-ingress-signature' };
export const ingressWindowSeconds = 60;
// Buffered to hash; the delivery core enforces the real sealed-record limits.
const bodyLimit = 1 << 20;

const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = text => Uint8Array.from(text.match(/../g), x => parseInt(x, 16));
// PKCS#8 wrapping of a raw 32-byte Ed25519 seed (RFC 8410).
const pkcs8Prefix = unhex('302e020100300506032b657004220420');

export function ingressMessage({ method, host, path, timestamp, nonce, bodyHash }) {
  return new TextEncoder().encode(['morse-ingress-v1', method, host, path, String(timestamp), nonce, bodyHash].join('\n'));
}

// "AB..., cd..." -> lowercase hex list; comma-separated while rotating.
export function ingressPublicKeys(value) {
  const keys = String(value).split(',').map(x => x.trim().toLowerCase());
  if (!keys.every(x => /^[a-f0-9]{64}$/.test(x))) throw new Error('Expected Ed25519 public keys (64 hex, comma-separated)');
  return keys;
}

const bodyHash = async body => hex(await crypto.subtle.digest('SHA-256', body));
const signedParts = (request, timestamp, nonce, hash) => {
  const url = new URL(request.url);
  return ingressMessage({ method: request.method, host: url.host, path: url.pathname, timestamp, nonce, bodyHash: hash });
};

// Edge: the forwarded request with its three signature headers, or null when
// the body is too large to sign.
export async function signedIngressRequest(request, secret, now = Date.now()) {
  const seedHex = String(secret).trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(seedHex)) throw new Error('MORSE_EDGE_INGRESS_SIGNING_KEY must be a 64-hex Ed25519 seed');
  const body = await boundedBody(request, bodyLimit);
  if (!body) return null;
  const timestamp = Math.floor(now / 1000);
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey('pkcs8', new Uint8Array([...pkcs8Prefix, ...unhex(seedHex)]), { name: 'Ed25519' }, false, ['sign']);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key, signedParts(request, timestamp, nonce, await bodyHash(body)));
  const headers = new Headers(request.headers);
  headers.set(ingressHeaders.timestamp, String(timestamp));
  headers.set(ingressHeaders.nonce, nonce);
  headers.set(ingressHeaders.signature, hex(signature));
  return new Request(request.url, { method: request.method, headers, body, redirect: 'manual', signal: request.signal });
}

// Backend: { body } for a request signed by a pinned key, inside the window,
// with a nonce not seen before; otherwise { status }.
export async function verifiedIngressBody(request, env, now = Date.now()) {
  let keys;
  try { keys = ingressPublicKeys(env.MORSE_EDGE_INGRESS_PUBLIC_KEY); } catch { return { status: 503 }; }
  if (!env.INGRESS_NONCES) return { status: 503 };
  const timestamp = request.headers.get(ingressHeaders.timestamp) ?? '';
  const nonce = request.headers.get(ingressHeaders.nonce) ?? '';
  const signature = request.headers.get(ingressHeaders.signature) ?? '';
  if (!/^(0|[1-9][0-9]{0,15})$/.test(timestamp) || !/^[a-f0-9]{32}$/.test(nonce) || !/^[a-f0-9]{128}$/.test(signature)) return { status: 403 };
  if (Math.abs(now / 1000 - Number(timestamp)) > ingressWindowSeconds) return { status: 403 };
  const body = await boundedBody(request, bodyLimit);
  if (!body) return { status: 413 };
  const message = signedParts(request, timestamp, nonce, await bodyHash(body));
  let valid = false;
  for (const pin of keys) {
    const key = await crypto.subtle.importKey('raw', unhex(pin), { name: 'Ed25519' }, false, ['verify']);
    if (await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(signature), message)) { valid = true; break; }
  }
  if (!valid) return { status: 403 };
  // Claimed only once the signature holds, so unsigned traffic can't fill the store.
  const fresh = await env.INGRESS_NONCES.getByName('primary').claim(nonce, (Number(timestamp) + ingressWindowSeconds + 1) * 1000);
  return fresh ? { body } : { status: 403 };
}
