import { issuerIngressOperation } from './issuer-ingress.mjs';
import { sealedIngressClientAllowed, sealedIngressMtlsConfigured } from './sealed-ingress-policy.mjs';
import { ohttpIngressRoute } from './ohttp.mjs';

const directoryRoutes = new Set([
  'PUT /v1/devices/register', 'POST /v1/devices/resolve', 'POST /v1/devices/revoke',
  'POST /v1/accounts/delete', 'POST /v1/devices/leave',
  'POST /v1/prekeys/one-time/batch', 'POST /v1/prekeys/bundle',
  'POST /v1/mailbox/fetch', 'POST /v1/mailbox/ack',
  'PUT /v1/push/bind', 'POST /v1/push/unbind',
  'GET /v1/transparency/checkpoint', 'POST /v1/transparency/checkpoint',
  'GET /v1/transparency/inclusion', 'POST /v1/transparency/inclusion',
  'GET /v1/transparency/consistency', 'POST /v1/transparency/consistency',
  'GET /v1/transparency/registry', 'GET /v1/transparency/witnesses', 'POST /v1/transparency/witnesses',
  'GET /v1/transparency/checkpoint.note', 'GET /v2/transparency/checkpoint.note',
  'GET /v2/transparency/checkpoint', 'POST /v2/transparency/checkpoint', 'POST /v2/devices/resolve',
  'GET /v2/transparency/inclusion', 'POST /v2/transparency/inclusion',
  'GET /v2/transparency/consistency', 'POST /v2/transparency/consistency',
  'GET /v2/transparency/witnesses', 'POST /v2/transparency/witnesses',
  'POST /v2/transparency/legacy-bridge',
  'POST /v1/transparency/leaf', 'POST /v2/transparency/leaf',
]);

// An isolated backend never terminates a sender's connection: its privacy edge
// is a separate deployment, and the only submission route it exposes is the
// bearer-authenticated sealed ingress that edge calls.
export function publicRoute(request, env = {}) {
  const path = new URL(request.url).pathname;
  const route = `${request.method} ${path}`;
  if (ohttpIngressRoute(request, env)) return 'OHTTP_INGRESS';
  if (env.MORSE_CREDIT_ISSUER_INGRESS === 'on' && issuerIngressOperation(request)) return 'ISSUER_INGRESS';
  const isolatedEdge = env.MORSE_ISOLATED_EDGE === '1';
  if (request.method === 'POST' && ['/v1/credits/issuer', '/v1/credits/quote', '/v1/credits/issue', '/v1/credits/lightning/quote', '/v1/credits/lightning/issue', '/v1/credits/retention', '/v1/credits/signup', '/v1/credits/signup-policy', '/v1/credits/reconcile', '/v1/credits/postage', '/v1/credits/postage/reconcile', '/v1/credits/postage-policy'].includes(path)) {
    if (new URL(request.url).search) return null;
    return isolatedEdge ? (['/v1/credits/issuer', '/v1/credits/retention', '/v1/credits/signup', '/v1/credits/signup-policy', '/v1/credits/reconcile', '/v1/credits/postage-policy'].includes(path) ? 'DIRECTORY' : null) : 'PRIVACY_EDGE';
  }
  if (route === 'POST /v1/envelopes/batch') return isolatedEdge || sealedIngressMtlsConfigured(env) ? null : 'PRIVACY_EDGE';
  if (route === 'POST /v1/ingress/sealed') {
    const url = new URL(request.url);
    return isolatedEdge && !url.search && !url.hash && sealedIngressClientAllowed(request, env) ? 'SEALED_INGRESS' : null;
  }
  if (request.method === 'POST' && ['/v1/ingress/postage', '/v1/ingress/postage/reconcile'].includes(path)) {
    return isolatedEdge && !new URL(request.url).search ? 'POSTAGE_INGRESS' : null;
  }
  if (route === 'GET /v1/mailbox/stream' && request.headers.get('Upgrade')?.toLowerCase() === 'websocket') return 'STREAM';
  if (directoryRoutes.has(route)) return 'DIRECTORY';
  const anchor = request.method === 'GET' && /^\/v[12]\/transparency\/anchor\/([1-9][0-9]{0,19})$/.exec(path);
  if (anchor && BigInt(anchor[1]) <= 18446744073709551615n) return 'DIRECTORY';
  if (request.method === 'POST' && path === '/v1/attachments/paid-grant') {
    return env.MORSE_PAID_LARGE_ATTACHMENTS === 'on' && !new URL(request.url).search ? 'OBJECT_STORE' : null;
  }
  if (request.method === 'POST' && /^\/v2\/attachments\/(complete|delete)$/.test(path)) {
    return new URL(request.url).search ? null : 'OBJECT_STORE';
  }
  if (['GET', 'PUT'].includes(request.method)) {
    const large = /^\/v2\/objects\/[a-f0-9]{64}\/parts\/(0|[1-9][0-9]{0,3})$/.exec(path);
    if (large) return Number(large[1]) <= 8192 && !new URL(request.url).search ? 'OBJECT_STORE' : null;
  }
  if (request.method === 'POST' && /^\/v1\/attachments\/(grant|complete|delete)$/.test(path)) return 'OBJECT_STORE';
  if (['GET', 'PUT'].includes(request.method) && /^\/v1\/objects\/[a-f0-9]{64}\/parts\/(0|[1-9][0-9]{0,2})$/.test(path)) return 'OBJECT_STORE';
  return null;
}

// Public probes inspect bounded cached state; only scheduled jobs start work.
export async function publicHealth(env) {
  const isolatedPush = env.MORSE_ISOLATED_PUSH_BROKER !== undefined;
  const kinds = ['directory', ...(isolatedPush ? [] : ['push']), 'objects', 'witness'];
  const anchorMode = env.MORSE_ANCHOR_MODE ?? 'off';
  if (anchorMode !== 'off') kinds.push('anchor');
  const snapshots = await Promise.all(kinds.map(kind => env.JOBS.getByName(kind).status()));
  const services = Object.fromEntries(kinds.map((kind, index) => [kind, snapshots[index].failures === 0]));
  const cached = snapshots[kinds.indexOf('witness')].witness;
  const now = Date.now();
  const valid = cached && Number.isSafeInteger(cached.observed_at) && cached.observed_at <= now + 60_000;
  const elapsed = valid ? Math.max(0, now - cached.observed_at) : Infinity;
  const age = value => Number.isSafeInteger(value) ? value + elapsed : null;
  const checkpointAge = valid ? age(cached.checkpoint_age_ms) : null;
  const thresholdMet = !!(valid && services.witness && cached.threshold_met === true &&
    checkpointAge !== null && checkpointAge >= -60_000 && checkpointAge <= 300_000);
  const witness = valid ? { ...cached, threshold_met: thresholdMet,
    checkpoint_age_ms: checkpointAge, anchor_lag_ms: age(cached.anchor_lag_ms),
    witnesses: Array.isArray(cached.witnesses) ? cached.witnesses.map(value => ({
      ...value, last_signature_age_ms: age(value.last_signature_age_ms),
    })) : [],
  } : { threshold_met: false };
  let anchor = { mode: 'off' };
  if (anchorMode !== 'off') {
    const cachedAnchor = snapshots[kinds.indexOf('anchor')].anchor;
    const fresh = cachedAnchor && cachedAnchor.mode === anchorMode && Number.isSafeInteger(cachedAnchor.observedAt) &&
      cachedAnchor.observedAt <= now + 60_000 && now - cachedAnchor.observedAt <= 120_000;
    services.anchor = !!(services.anchor && fresh && cachedAnchor.issues?.length === 0 && cachedAnchor.fee?.level === 'healthy');
    const last = cachedAnchor?.lastPost;
    anchor = { mode: anchorMode, observed_at: cachedAnchor?.observedAt ?? null,
      age_ms: fresh ? Math.max(0, now - cachedAnchor.observedAt) : null,
      pending_transactions: cachedAnchor?.pending ?? null, issues: cachedAnchor?.issues ?? ['status_unavailable'],
      fee_payer_level: cachedAnchor?.fee?.level ?? null, balance_lamports: cachedAnchor?.fee?.balanceLamports ?? null,
      alert_configured: cachedAnchor?.alert?.configured === true, alert_pending: cachedAnchor?.alert?.pending === true,
      last_post: last ? { version: last.version, sequence: last.sequence, tree_size: last.treeSize,
        checkpoint_hash: last.checkpointHash, slot: last.slot, ring_index: last.ringIndex } : null };
  }
  const healthy = Object.values(services).every(Boolean) && thresholdMet;
  return Response.json({ healthy, services, witness, anchor, ...(isolatedPush ? { push_broker: { mode: 'external', health: 'not-observed' } } : {}) }, {
    status: healthy ? 200 : 503, headers: { 'Cache-Control': 'no-store' },
  });
}
