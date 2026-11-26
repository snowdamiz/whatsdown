const directoryRoutes = new Set([
  'PUT /v1/devices/register', 'POST /v1/devices/resolve', 'POST /v1/devices/revoke',
  'POST /v1/accounts/delete', 'POST /v1/devices/leave',
  'POST /v1/prekeys/one-time/batch', 'POST /v1/prekeys/bundle',
  'POST /v1/mailbox/fetch', 'POST /v1/mailbox/ack',
  'PUT /v1/push/bind', 'POST /v1/push/unbind',
  'GET /v1/transparency/checkpoint',
  'GET /v1/transparency/inclusion', 'POST /v1/transparency/inclusion',
  'GET /v1/transparency/consistency', 'POST /v1/transparency/consistency',
  'GET /v1/transparency/witnesses', 'POST /v1/transparency/witnesses',
  'GET /v1/transparency/checkpoint.note', 'GET /v1/transparency/registry', 'GET /v1/transparency/health',
  'POST /v1/transparency/leaf', 'GET /v1/transparency/leaves',
  'GET /v1/credits/issuer-keys', 'PUT /v1/mailbox/policy', 'GET /v1/ohttp/keys',
]);

// An isolated backend never terminates a sender's connection: its privacy edge
// is a separate deployment, and the only submission route it exposes is the
// bearer-authenticated sealed ingress that edge calls (and its credit redeem
// call, guarded the same way).
export function publicRoute(request, env = {}) {
  const path = new URL(request.url).pathname;
  const route = `${request.method} ${path}`;
  const isolatedEdge = env.MORSE_ISOLATED_EDGE === '1';
  if (['POST /v1/envelopes/batch', 'POST /v1/mailbox/retention', 'POST /v1/ohttp'].includes(route)) return isolatedEdge ? null : 'PRIVACY_EDGE';
  if (['POST /v1/ingress/sealed', 'POST /v1/ingress/credits/redeem', 'POST /v1/ingress/mailbox/retention', 'POST /v1/ingress/ohttp'].includes(route)) {
    return isolatedEdge ? 'SEALED_INGRESS' : null;
  }
  if (route === 'GET /v1/mailbox/stream' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') return 'STREAM';
  if (directoryRoutes.has(route)) return 'DIRECTORY';
  if (request.method === 'GET' && /^\/v1\/transparency\/(anchor|witnesses)\/(0|[1-9][0-9]{0,19})$/.test(path)) return 'DIRECTORY';
  if (request.method === 'POST' && /^\/v1\/attachments\/(grant|complete|delete)$/.test(path)) return 'OBJECT_STORE';
  if (['GET', 'PUT'].includes(request.method) && /^\/v1\/objects\/[a-f0-9]{64}\/parts\/(0|[1-9][0-9]{0,3})$/.test(path)) return 'OBJECT_STORE';
  return null;
}

// Public probes inspect bounded cached state; only scheduled jobs start work.
// An isolated backend leaves the push scheduler to the broker's deployment.
export async function publicHealth(env, kinds = ['directory', ...(env.MORSE_ISOLATED_PUSH === '1' ? [] : ['push']), 'objects', 'witness']) {
  const checks = await Promise.all(kinds.map(async kind =>
    (await env.JOBS.getByName(kind).status()).failures === 0));
  const healthy = checks.every(Boolean);
  return new Response(healthy ? 'ok' : 'unavailable', { status: healthy ? 200 : 503 });
}
