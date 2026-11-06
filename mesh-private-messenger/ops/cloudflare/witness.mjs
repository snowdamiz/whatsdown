import { timingSafeEqual } from 'node:crypto';
import { boundedBody } from './storage.mjs';

export function httpsOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Expected an HTTPS origin'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Expected an HTTPS origin');
  return url.origin;
}

async function registryRequest(env, path) {
  const response = await env.DIRECTORY.getByName('primary').fetch(`http://service/internal/v1/transparency/${path}`, {
    headers: { Authorization: `Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}` },
    redirect: 'manual', signal: AbortSignal.timeout(10_000),
  });
  if (response.status !== 200) { await response.body?.cancel(); throw new Error('Witness registry unavailable'); }
  const bytes = await boundedBody(response, 65536);
  if (!bytes) throw new Error('Witness registry response too large');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

export async function attestWitnesses(env, fetcher = fetch) {
  const registry = await registryRequest(env, 'push-witnesses');
  if (!Array.isArray(registry.witnesses) || registry.witnesses.length > 256) throw new Error('Invalid witness registry');
  const ids = new Set();
  const witnesses = registry.witnesses.map(value => {
    if (!/^[a-z0-9-]{1,64}$/.test(value.witness_id ?? '') || ids.has(value.witness_id)) throw new Error('Invalid witness registry');
    ids.add(value.witness_id);
    const url = new URL(value.push_url);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.href !== value.push_url) throw new Error('Expected a canonical HTTPS witness endpoint');
    if (!['mesh', 'c2sp'].includes(value.software ?? 'mesh')) throw new Error('Unsupported witness software');
    return value;
  });
  const tokens = JSON.parse(env.MESSENGER_WITNESS_PUSH_TOKENS ?? '{}');
  if (!tokens || typeof tokens !== 'object' || Array.isArray(tokens)) throw new Error('Invalid witness invocation tokens');
  const results = await Promise.allSettled(witnesses.map(async ({ witness_id: id, push_url: url, software }) => {
    if (software === 'c2sp') {
      if (env.MORSE_C2SP_PUSH !== 'on') return;
      // Mesh constructs the signed note and consistency proof, handles the
      // witness's size retry, and admits only its registered fresh cosignature.
      const response = await env.DIRECTORY.getByName('primary').fetch('http://service/internal/v2/transparency/c2sp-push', {
        method: 'POST', body: id, redirect: 'manual', signal: AbortSignal.timeout(30_000),
        headers: { Authorization: `Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}` },
      });
      await response.body?.cancel();
      if (response.status !== 204) throw new Error(`Witness ${id} C2SP push failed (${response.status})`);
      return;
    }
    if (env.MORSE_ISOLATED_WITNESSES !== '1') {
      const binding = env[id.toUpperCase().replaceAll('-', '_')];
      if (!binding) throw new Error(`Missing local witness binding for ${id}`);
      return binding.getByName('primary').attest();
    }
    // Existing A/B deployments can keep their named secrets during migration.
    const legacy = id === 'witness-a' ? 'A' : id === 'witness-b' ? 'B' : undefined;
    const token = Object.hasOwn(tokens, id) ? tokens[id] : legacy && env[`WITNESS_${legacy}_INVOKE_TOKEN`];
    if (!/^[a-f0-9]{64}$/.test(token ?? '')) throw new Error(`Missing invocation token for ${id}`);
    const response = await fetcher(url, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(60_000),
      headers: { Authorization: `Bearer ${token}` },
    });
    await response.body?.cancel();
    if (response.status !== 204) throw new Error(`Witness ${id} attestation failed (${response.status})`);
  }));
  // A failed minority must not disable a healthy majority. The directory checks
  // registered keys against the current checkpoint, including pull witnesses.
  const health = await registryRequest(env, 'witness-health');
  if (typeof health.threshold_met !== 'boolean') throw new Error('Invalid witness health');
  if (!health.threshold_met) throw new Error('Witness threshold not met for current checkpoint');
  return { ...health, push_failures: results.filter(result => result.status === 'rejected').length };
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
  if (!/^\/v[12]\/transparency\//.test(url.pathname) || !['GET', 'POST'].includes(request.method) || url.search) return null;
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
