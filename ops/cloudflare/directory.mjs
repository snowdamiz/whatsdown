// The directory as the network jobs see it: the container binding, small reads,
// and the internal bearer for /internal routes (INTERFACES §7).
import { boundedBody } from './storage.mjs';

export function directoryClient(env, limit = 1 << 20) {
  return async function call(path, { method = 'GET', body, headers = {}, internal = false } = {}) {
    const response = await env.DIRECTORY.getByName('primary').fetch(`http://service${path}`, {
      method, body, signal: AbortSignal.timeout(30_000),
      headers: { ...headers, ...(internal ? { Authorization: `Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}` } : {}) },
    });
    const bytes = await boundedBody(response, limit);
    if (!bytes) throw new Error(`${path}: response too large`);
    return { status: response.status, bytes, contentType: response.headers.get('Content-Type') ?? '', text: () => new TextDecoder().decode(bytes) };
  };
}

const be64 = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };

// POST /v1/transparency/consistency with a KTS v2 query; KTC v2 back:
// u8 2 ‖ "KTC" ‖ u64 old ‖ u64 new ‖ u8 p ‖ p × 32. new = 0 asks for the
// current checkpoint, which the directory refreshes as a lookup would.
export async function consistencyV2(call, oldSize, newSize, tree) {
  const query = new Uint8Array([2, ...new TextEncoder().encode('KTS'), ...be64(oldSize), ...be64(newSize), tree]);
  const { status, bytes } = await call('/v1/transparency/consistency', { method: 'POST', body: query, headers: { 'Content-Type': 'application/octet-stream' } });
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (status !== 200 || bytes.length < 21 || bytes[0] !== 2 || new TextDecoder().decode(bytes.subarray(1, 4)) !== 'KTC'
    || view.getBigUint64(4) !== BigInt(oldSize) || (newSize && view.getBigUint64(12) !== BigInt(newSize))
    || bytes.length !== 21 + 32 * bytes[20]) throw new Error(`Consistency proof unavailable (${status})`);
  return { oldSize: view.getBigUint64(4), newSize: view.getBigUint64(12), path: Array.from({ length: bytes[20] }, (_, i) => bytes.slice(21 + 32 * i, 53 + 32 * i)) };
}

export async function currentCheckpoint(call) {
  const { status, bytes } = await call('/v1/transparency/checkpoint');
  if (status !== 200 || bytes.length !== 188) throw new Error(`Checkpoint unavailable (${status})`);
  return bytes;
}
