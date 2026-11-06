import { httpsOrigin } from './witness.mjs';
import { assertSealedEdgeTopology, sealedIngressClientAllowed } from './sealed-ingress-policy.mjs';

// HTTP boundary only: crypto, Binary HTTP and target admission belong to Mesh.
// Routes require explicit rollout configuration; deployments default to off.
const maximum = 1_048_576;
const requestType = 'message/ohttp-req';
const responseType = 'message/ohttp-res';

class OhttpHttpError extends Error {
  constructor(status) {
    super('OHTTP transport refused');
    this.status = status;
  }
}

function route(request, path, origin) {
  const url = new URL(request.url);
  return request.method === 'POST' && url.pathname === path && !url.search && !url.hash &&
    !url.username && !url.password && (origin ? url.origin === origin : url.protocol === 'https:');
}

export function ohttpEnabled(env = {}) {
  return env.MORSE_OHTTP === 'on';
}

export function ohttpConfig(env = {}) {
  if (env.MORSE_OHTTP === undefined) return {};
  if (!['off', 'on'].includes(env.MORSE_OHTTP)) throw new Error('MORSE_OHTTP must be off or on');
  return { MORSE_OHTTP: env.MORSE_OHTTP };
}

// Public deployment pins only. Mesh validates the complete canonical key
// collection and proves each configured public key matches its protected seed.
export function ohttpGatewayConfig(env = {}) {
  const mode = ohttpConfig(env);
  if (!ohttpEnabled(env)) return mode;
  const origin = env.MESSENGER_OHTTP_CORE_ORIGIN;
  const keys = env.MESSENGER_OHTTP_KEY_CONFIG_HEX;
  let canonical;
  try { canonical = httpsOrigin(origin); } catch { /* fixed error below */ }
  if (!canonical || canonical !== origin || typeof keys !== 'string' ||
      keys.length < 86 || keys.length > 412 || keys.length % 2 || !/^[a-f0-9]+$/.test(keys)) {
    throw new Error('Invalid OHTTP gateway public configuration');
  }
  return { ...mode, MESSENGER_OHTTP_CORE_ORIGIN: origin, MESSENGER_OHTTP_KEY_CONFIG_HEX: keys };
}

export function ohttpGatewayEnv(env = {}) {
  const pins = ohttpGatewayConfig(env);
  if (!ohttpEnabled(env)) return pins;
  const values = {};
  for (const name of ['MESSENGER_OHTTP_PRIVATE_KEY_0_HEX', 'MESSENGER_OHTTP_PRIVATE_KEY_1_HEX']) {
    const value = env[name];
    if (name.endsWith('_1_HEX') && value === undefined) continue;
    if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) {
      throw new Error('Invalid OHTTP gateway private configuration');
    }
    values[name] = value;
  }
  return { ...pins, ...values };
}

export function ohttpIngressRoute(request, env = {}) {
  return ohttpEnabled(env) && env.MORSE_ISOLATED_EDGE === '1' &&
    route(request, '/v1/ingress/ohttp') && sealedIngressClientAllowed(request, env);
}

function validToken(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 256 &&
    value.trim() === value && !/[\r\n]/.test(value);
}

function cancel(body) {
  // A stalled producer must not delay refusal, including its cancellation hook.
  try { void body?.cancel().catch(() => {}); } catch { /* already locked/closed */ }
}

function mediaAllowed(message, media) {
  const encoding = message.headers.get('content-encoding');
  return message.headers.get('content-type') === media && (encoding === null || encoding === 'identity');
}

async function readChunk(reader, signal) {
  let rejectAbort;
  const aborted = new Promise((_, reject) => { rejectAbort = reject; });
  const onAbort = () => rejectAbort(new OhttpHttpError(408));
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    if (signal.aborted) throw new OhttpHttpError(408);
    return await Promise.race([reader.read(), aborted]);
  } finally {
    // A shared pending abort promise would retain one reaction per read.
    signal.removeEventListener('abort', onAbort);
  }
}

async function opaqueBody(message, minimum, incomingSignal) {
  const reader = message.body?.getReader();
  if (!reader) throw new OhttpHttpError(400);
  const signal = incomingSignal
    ? AbortSignal.any([incomingSignal, AbortSignal.timeout(5_000)]) : AbortSignal.timeout(5_000);
  const output = new Uint8Array(maximum);
  let size = 0;
  let emptyChunks = 0;
  const deadline = performance.now() + 5_000;
  try {
    for (;;) {
      // Ready microtasks can otherwise starve the timeout callback.
      if (performance.now() >= deadline) throw new OhttpHttpError(408);
      const { done, value } = await readChunk(reader, signal);
      if (done) {
        if (size < minimum) throw new OhttpHttpError(400);
        return output.slice(0, size);
      }
      if (!(value instanceof Uint8Array)) throw new OhttpHttpError(400);
      if (value.byteLength === 0) {
        if (++emptyChunks > 32) throw new OhttpHttpError(400);
      } else {
        emptyChunks = 0;
      }
      if (value.byteLength > maximum - size) throw new OhttpHttpError(413);
      output.set(value, size);
      size += value.byteLength;
    }
  } catch (error) {
    cancel(reader);
    throw error instanceof OhttpHttpError ? error : new OhttpHttpError(400);
  } finally {
    reader.releaseLock();
  }
}

async function forward(request, target, authorization) {
  if (!mediaAllowed(request, requestType)) {
    cancel(request.body);
    throw new OhttpHttpError(415);
  }
  const body = await opaqueBody(request, 55, request.signal);
  const headers = new Headers({ 'Content-Type': requestType, Accept: responseType, 'Cache-Control': 'no-store' });
  if (authorization) headers.set('Authorization', authorization);
  return new Request(target, {
    method: 'POST', headers, body, redirect: 'manual',
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(30_000)]),
  });
}

export async function ohttpContainerRequest(request) {
  if (!route(request, '/v1/ohttp')) return null;
  return forward(request, request.url);
}

export async function ohttpDeliveryRequest(request, env) {
  if (!route(request, '/internal/v1/ohttp', 'http://delivery.internal')) return null;
  let origin;
  try {
    assertSealedEdgeTopology(env);
    origin = httpsOrigin(env.MORSE_DELIVERY_URL);
    if (origin !== env.MORSE_DELIVERY_URL || !validToken(env.MESSENGER_DELIVERY_INTERNAL_TOKEN)) throw new Error();
  } catch {
    throw new OhttpHttpError(503);
  }
  // The incoming Authorization is never a source for this credential.
  return forward(request, origin + '/v1/ingress/ohttp', `Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}`);
}

export async function ohttpIngressRequest(request, env = {}) {
  if (!route(request, '/v1/ingress/ohttp') || !sealedIngressClientAllowed(request, env)) return null;
  const authorization = request.headers.get('authorization') ?? '';
  if (!authorization.startsWith('Bearer ') || !validToken(authorization.slice(7))) throw new OhttpHttpError(401);
  const url = new URL(request.url);
  url.pathname = '/internal/v1/ohttp';
  // Syntax is checked here; the Mesh gateway must authenticate the exact token.
  return forward(request, url, authorization);
}

function emptyFailure(status) {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store' } });
}

export function ohttpHttpFailure(error) {
  return emptyFailure(error instanceof OhttpHttpError ? error.status : 503);
}

export async function ohttpRelayResponse(response, signal) {
  if (response.status !== 200) {
    cancel(response.body);
    return emptyFailure(response.status >= 400 && response.status <= 599 ? response.status : 502);
  }
  if (!mediaAllowed(response, responseType) || response.headers.get('cache-control') !== 'no-store') {
    cancel(response.body);
    return emptyFailure(502);
  }
  try {
    const body = await opaqueBody(response, 48, signal);
    return new Response(body, { status: 200, headers: { 'Content-Type': responseType, 'Cache-Control': 'no-store' } });
  } catch {
    return emptyFailure(502);
  }
}
