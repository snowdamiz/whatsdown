import { createHash, timingSafeEqual } from 'node:crypto';
import { httpsOrigin } from './witness.mjs';
import { boundedBody } from './storage.mjs';

const brokerOnly = ['MESSENGER_PUSH_BROKER_SEED_HEX', 'PUSH_DATABASE_URL', 'MESSENGER_PUSH_BROKER_DATABASE_URL', 'MESSENGER_EXPO_ACCESS_TOKEN'];

export function assertBackendPushIsolation(env) {
  if (brokerOnly.some(name => env[name] !== undefined)) throw new Error('Isolated backend must not hold broker-only credentials');
}

function credential(env) {
  const token = env.MESSENGER_PUSH_BROKER_INTERNAL_TOKEN;
  if (typeof token !== 'string' || token.length < 32 || token.length > 256 || token.trim() !== token || /[\r\n]/.test(token)) {
    throw new Error('Invalid broker request credential');
  }
  return token;
}

export function directoryPushUrl(env) {
  if (env.MORSE_ISOLATED_PUSH_BROKER !== undefined) {
    if (env.MORSE_ISOLATED_PUSH_BROKER !== '1') throw new Error('Invalid isolated broker mode');
    assertBackendPushIsolation(env);
    httpsOrigin(env.MORSE_PUSH_BROKER_URL);
    credential(env);
  }
  return 'http://push.internal/internal/v1/push';
}

function authorized(request, token) {
  const header = request.headers.get('authorization');
  if (typeof header !== 'string' || header.length > 263) return false;
  const hash = value => createHash('sha256').update(value).digest();
  return timingSafeEqual(hash(header), hash(`Bearer ${token}`));
}

export function pushBrokerContainerEnv(env) {
  if (!env.MESSENGER_PUSH_BROKER_SEED_HEX) throw new Error('Missing broker seed');
  if (!env.PUSH_DATABASE_URL) throw new Error('Missing broker queue database');
  return {
    MESSENGER_PUSH_BROKER_SEED_HEX: env.MESSENGER_PUSH_BROKER_SEED_HEX,
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: credential(env),
    MESSENGER_PUSH_BROKER_DATABASE_URL: env.PUSH_DATABASE_URL,
    MESSENGER_EXPO_ACCESS_TOKEN: env.MESSENGER_EXPO_ACCESS_TOKEN ?? '',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
  };
}

export async function pushBrokerIngressRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== '/v1/ingress/push' || url.search || url.hash) return new Response(null, { status: 404 });
  let token, origin;
  try { token = credential(env); origin = httpsOrigin(env.MORSE_PUSH_BROKER_URL); } catch { return new Response(null, { status: 503 }); }
  if (url.origin !== origin) return new Response(null, { status: 404 });
  if (!authorized(request, token)) return new Response(null, { status: 401 });
  const body = await boundedBody(request, 621);
  if (!body?.length) return new Response(null, { status: 422 });
  return new Request('http://push.internal/internal/v1/push', {
    method: 'POST', body, redirect: 'manual', headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${token}` },
  });
}

export async function forwardPushWake(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.origin !== 'http://push.internal' || url.pathname !== '/internal/v1/push' || url.search || url.hash) {
    return new Response(null, { status: 404 });
  }
  if (env.MORSE_ISOLATED_PUSH_BROKER !== '1') return new Response(null, { status: 503 });
  let token, origin;
  try { assertBackendPushIsolation(env); token = credential(env); origin = httpsOrigin(env.MORSE_PUSH_BROKER_URL); }
  catch { return new Response(null, { status: 503 }); }
  if (!authorized(request, token)) return new Response(null, { status: 401 });
  const body = await boundedBody(request, 621);
  if (!body?.length) return new Response(null, { status: 422 });
  try {
    const response = await fetch(`${origin}/v1/ingress/push`, {
      method: 'POST', body, redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${token}` },
    });
    await response.body?.cancel();
    return new Response(null, { status: [204, 401, 422, 503].includes(response.status) ? response.status : 502 });
  } catch { return new Response(null, { status: 503 }); }
}
