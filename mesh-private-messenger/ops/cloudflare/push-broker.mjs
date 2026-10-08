import { httpsOrigin } from './witness.mjs';
import { bearerMatches } from './edge.mjs';

// §22 M4. The push broker holds the key that opens provider tokens; the backend
// holds the mailbox -> push binding link. Each lives in its own deployment, and
// the only thing that crosses is a sealed push job with the broker's bearer.

const pushPath = '/internal/v1/push';

// Built from an allowlist so an over-provisioned deployment still passes the
// container nothing but the broker's own settings.
export function pushBrokerContainerEnv(env) {
  for (const name of ['MESSENGER_PUSH_BROKER_SEED_HEX', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'PUSH_DATABASE_URL']) {
    if (!env[name]) throw new Error(`Missing ${name}`);
  }
  return {
    MESSENGER_PUSH_BROKER_SEED_HEX: env.MESSENGER_PUSH_BROKER_SEED_HEX,
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: env.MESSENGER_PUSH_BROKER_INTERNAL_TOKEN,
    MESSENGER_PUSH_BROKER_DATABASE_URL: env.PUSH_DATABASE_URL,
    MESSENGER_EXPO_ACCESS_TOKEN: env.MESSENGER_EXPO_ACCESS_TOKEN ?? '',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
  };
}

function pushHeaders(request) {
  const headers = new Headers({ 'content-type': 'application/octet-stream' });
  const authorization = request.headers.get('authorization');
  if (authorization !== null) headers.set('authorization', authorization);
  return headers;
}

const isPush = (request, url) => request.method === 'POST' && url.pathname === pushPath && !url.search;

// Delivery core -> broker, across deployments.
export function brokerPushRequest(request, env) {
  const url = new URL(request.url);
  if (!isPush(request, url)) return null;
  return new Request(`${httpsOrigin(env.MORSE_PUSH_BROKER_URL)}${pushPath}`, {
    method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: pushHeaders(request), signal: AbortSignal.timeout(30_000),
  });
}

export async function forwardPush(request, env, fetcher = fetch) {
  const forwarded = brokerPushRequest(request, env);
  if (!forwarded) return new Response(null, { status: 404 });
  const response = await fetcher(forwarded);
  if (response.status >= 300 && response.status < 400) return new Response(null, { status: 502 });
  return response;
}

// The broker Worker's one route: a Response when refused, else the request for
// its container. The bearer is checked here too, so junk never wakes the container.
export function brokerIngress(request, env) {
  const url = new URL(request.url);
  if (!isPush(request, url)) return new Response(null, { status: 404 });
  const token = env.MESSENGER_PUSH_BROKER_INTERNAL_TOKEN;
  if (!token) return new Response(null, { status: 503 });
  if (!bearerMatches(request, token)) return new Response(null, { status: 401 });
  return new Request(url, { method: 'POST', body: request.body, duplex: 'half', redirect: 'manual', headers: pushHeaders(request) });
}
