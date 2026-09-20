import { timingSafeEqual } from 'node:crypto';

export function httpsOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Expected an HTTPS origin'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Expected an HTTPS origin');
  return url.origin;
}

export async function attestWitnesses(env, fetcher = fetch) {
  if (env.MORSE_ISOLATED_WITNESSES !== '1') {
    return Promise.all([env.WITNESS_A.getByName('primary').attest(), env.WITNESS_B.getByName('primary').attest()]);
  }
  await Promise.all(['A', 'B'].map(async name => {
    const origin = httpsOrigin(env[`WITNESS_${name}_URL`]);
    const token = env[`WITNESS_${name}_INVOKE_TOKEN`];
    if (!/^[a-f0-9]{64}$/.test(token ?? '')) throw new Error('Missing witness invocation token');
    const response = await fetcher(`${origin}/attest`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(60_000),
      headers: { Authorization: `Bearer ${token}` },
    });
    await response.body?.cancel();
    if (response.status !== 204) throw new Error(`Witness ${name} attestation failed`);
  }));
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
  if (request.body) return new Response(null, { status: 400 });
  try {
    await env.WITNESS.getByName('primary').attest();
    return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
  } catch {
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
