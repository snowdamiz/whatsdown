import { timingSafeEqual } from 'node:crypto';
import { boundedBody } from './storage.mjs';

export function httpsOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Expected an HTTPS origin'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Expected an HTTPS origin');
  return url.origin;
}

// The directory's shadow and pinned registry entries (INTERFACES §7), with
// push_url: every Morse-run witness to invoke and C2SP witness to push to.
export async function pushWitnesses(env) {
  const response = await env.DIRECTORY.getByName('primary').fetch('http://service/internal/v1/transparency/push-witnesses', {
    headers: { Authorization: `Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}` }, signal: AbortSignal.timeout(30_000),
  });
  const body = await boundedBody(response, 1 << 20);
  if (response.status !== 200 || !body) throw new Error(`Push witness list unavailable (${response.status})`);
  const { witnesses } = JSON.parse(new TextDecoder().decode(body));
  if (!Array.isArray(witnesses)) throw new Error('Invalid push witness list');
  return witnesses;
}

// witness-a -> WITNESS_A: its Durable Object binding, or WITNESS_A_URL and
// WITNESS_A_INVOKE_TOKEN when witnesses are deployed separately.
export const witnessEnvName = id => id.toUpperCase().replaceAll('-', '_');

// Asks every Morse-run Mesh witness in the registry (shadow or pinned) that this
// Worker can reach to check the directory: through WITNESS_<ID>_URL and
// WITNESS_<ID>_INVOKE_TOKEN when witnesses are deployed separately, or the
// WITNESS_<ID> binding in the combined topology. push_url plays no part (it is
// a C2SP witness's add-checkpoint endpoint). A witness with neither runs in pull
// mode and is skipped; an empty list is a normal state.
export async function attestWitnesses(env, fetcher = fetch, listed = null) {
  const isolated = env.MORSE_ISOLATED_WITNESSES === '1';
  const witnesses = (listed ?? await pushWitnesses(env))
    .filter(x => x.morse_run === true && x.software === 'mesh' && ['shadow', 'pinned'].includes(x.status))
    .filter(x => isolated ? env[`${witnessEnvName(x.witness_id)}_URL`] || env[`${witnessEnvName(x.witness_id)}_INVOKE_TOKEN`] : env[witnessEnvName(x.witness_id)]);
  const results = await Promise.allSettled(witnesses.map(async ({ witness_id: id }) => {
    const name = witnessEnvName(id);
    if (!isolated) return env[name].getByName('primary').attest();
    const origin = httpsOrigin(env[`${name}_URL`]);
    const token = env[`${name}_INVOKE_TOKEN`];
    if (!/^[a-f0-9]{64}$/.test(token ?? '')) throw new Error('Missing witness invocation token');
    const response = await fetcher(`${origin}/attest`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(60_000),
      headers: { Authorization: `Bearer ${token}` },
    });
    await response.body?.cancel();
    if (response.status !== 204) throw new Error(`Witness ${id} attestation failed (${response.status})`);
  }));
  if (isolated) {
    const unlisted = Object.keys(env).filter(key => /^[A-Z0-9_]+_INVOKE_TOKEN$/.test(key) && key !== 'WITNESS_INVOKE_TOKEN' && env[key])
      .map(key => key.slice(0, -'_INVOKE_TOKEN'.length)).filter(name => !witnesses.some(x => witnessEnvName(x.witness_id) === name));
    if (unlisted.length) console.error(`Witness jobs: ${unlisted.join(', ')} configured but not a shadow or pinned Morse-run Mesh registry entry`);
  }
  const failed = results.find(x => x.status === 'rejected');
  if (failed) throw failed.reason;
}

export async function witnessRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== '/attest' || url.search) return new Response(null, { status: 404 });
  const token = env.WITNESS_INVOKE_TOKEN;
  if (!/^[a-f0-9]{64}$/.test(token ?? '')) return new Response(null, { status: 503 });
  const supplied = request.headers.get('Authorization') ?? '';
  const expected = `Bearer ${token}`;
  const encoder = new TextEncoder();
  const suppliedBytes = encoder.encode(supplied);
  const expectedBytes = encoder.encode(expected);
  if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) return new Response(null, { status: 401 });
  // No caller-supplied checkpoint or message reaches the signing process.
  // Deployed Workers give every POST a body stream, so only bytes are refused.
  if (!(await boundedBody(request, 0))) return new Response(null, { status: 400 });
  try {
    await env.WITNESS.getByName('primary').attest();
    return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    console.error(String(error).slice(0, 500));
    return new Response(null, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  }
}

export function directoryRequest(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/v1/transparency/') || !['GET', 'POST'].includes(request.method) || url.search) return null;
  return new Request(`${httpsOrigin(env.MORSE_DIRECTORY_URL)}${url.pathname}`, {
    method: request.method, body: request.body, duplex: 'half', redirect: 'manual',
    headers: { 'Content-Type': 'application/octet-stream' }, signal: AbortSignal.timeout(60_000),
  });
}

export async function initializeWitness(env) {
  const store = env.WITNESS_STATE.getByName('primary');
  const existing = await store.fetch('http://checkpoint.internal/');
  await existing.body?.cancel();
  if (existing.status === 200) return;
  if (existing.status !== 404) throw new Error('Witness checkpoint unavailable');
  const initial = env.WITNESS_INITIAL_CHECKPOINT_HEX;
  // Only a new witness identity may bootstrap without continuity history.
  if (initial === 'new-identity') return;
  if (!/^[a-f0-9]{376}$/.test(initial ?? '')) throw new Error('Witness requires explicit checkpoint transfer');
  const bytes = Uint8Array.from(initial.match(/../g), byte => parseInt(byte, 16));
  const stored = await store.fetch('http://checkpoint.internal/', {
    method: 'PUT', body: bytes, headers: { 'If-Match': 'none' },
  });
  if (![204, 409].includes(stored.status)) throw new Error('Witness checkpoint transfer failed');
}
