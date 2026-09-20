const directoryRoutes = new Set([
  'PUT /v1/devices/register', 'POST /v1/devices/resolve', 'POST /v1/devices/revoke',
  'POST /v1/prekeys/one-time/batch', 'POST /v1/prekeys/bundle',
  'POST /v1/mailbox/fetch', 'POST /v1/mailbox/ack',
  'PUT /v1/push/bind', 'POST /v1/push/unbind',
  'GET /v1/transparency/checkpoint',
  'GET /v1/transparency/inclusion', 'POST /v1/transparency/inclusion',
  'GET /v1/transparency/consistency', 'POST /v1/transparency/consistency',
  'GET /v1/transparency/witnesses', 'POST /v1/transparency/witnesses',
]);

// An isolated backend never terminates a sender's connection: its privacy edge
// is a separate deployment, and the only submission route it exposes is the
// bearer-authenticated sealed ingress that edge calls.
export function publicRoute(request, env = {}) {
  const path = new URL(request.url).pathname;
  const route = `${request.method} ${path}`;
  const isolatedEdge = env.MORSE_ISOLATED_EDGE === '1';
  if (route === 'POST /v1/envelopes/batch') return isolatedEdge ? null : 'PRIVACY_EDGE';
  if (route === 'POST /v1/ingress/sealed') return isolatedEdge ? 'SEALED_INGRESS' : null;
  if (route === 'GET /v1/mailbox/stream' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') return 'STREAM';
  if (directoryRoutes.has(route)) return 'DIRECTORY';
  if (request.method === 'POST' && /^\/v1\/attachments\/(grant|complete|delete)$/.test(path)) return 'OBJECT_STORE';
  if (['GET', 'PUT'].includes(request.method) && /^\/v1\/objects\/[a-f0-9]{64}\/parts\/(0|[1-9][0-9]{0,2})$/.test(path)) return 'OBJECT_STORE';
  return null;
}

// Public probes inspect bounded cached state; only scheduled jobs start work.
export async function publicHealth(env) {
  const checks = await Promise.all(['directory', 'push', 'objects', 'witness'].map(async kind =>
    (await env.JOBS.getByName(kind).status()).failures === 0));
  const healthy = checks.every(Boolean);
  return new Response(healthy ? 'ok' : 'unavailable', { status: healthy ? 200 : 503 });
}
