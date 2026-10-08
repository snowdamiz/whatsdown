export async function boundedBody(request, limit) {
  const output = new Uint8Array(limit);
  const reader = request.body?.getReader();
  let size = 0;
  if (!reader) return output.subarray(0, 0);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return output.subarray(0, size);
    if (size + value.length > limit) {
      await reader.cancel();
      return null;
    }
    output.set(value, size);
    size += value.length;
  }
}

// A 512 MiB attachment has parts 0 through 8,192 (opaque-object-wire-v1.md).
const MAXIMUM_PARTS = 8193;

// Deleting a whole object (`DELETE /{id}` with X-Part-Count) removes its parts
// in batches, so a large object goes in a few calls rather than one per part.
async function deleteObject(request, env, id) {
  const header = request.headers.get('X-Part-Count') ?? '';
  const count = Number(header);
  if (request.method !== 'DELETE' || !/^[1-9][0-9]{0,3}$/.test(header) || count > MAXIMUM_PARTS) {
    return new Response(null, { status: 400 });
  }
  const keys = Array.from({ length: count }, (_, index) => `opaque/${id}.${index}`);
  for (let start = 0; start < keys.length; start += 1000) await env.OBJECTS.delete(keys.slice(start, start + 1000));
  return new Response(null, { status: 204 });
}

// The object store's one call into the core: redeeming a large file's credits.
export function objectStoreCore(request, env) {
  const url = new URL(request.url);
  if (request.method !== 'POST' || url.pathname !== '/internal/v1/credits/redeem' || url.search) {
    return new Response(null, { status: 404 });
  }
  return env.DIRECTORY.getByName('primary').fetch(request);
}

// Only the object-store container's outbound handler exposes this binding.
export const objectStorage = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const whole = /^\/([a-f0-9]{64})$/.exec(url.pathname);
    if (whole && !url.search) return deleteObject(request, env, whole[1]);
    const match = /^\/([a-f0-9]{64})\.(0|[1-9][0-9]{0,3})$/.exec(url.pathname);
    if (!match || Number(match[2]) >= MAXIMUM_PARTS || url.search) return new Response(null, { status: 400 });
    const key = `opaque${url.pathname}`;
    switch (request.method) {
      case 'GET': {
        const object = await env.OBJECTS.get(key);
        return new Response(object?.body ?? null, { status: object ? 200 : 404 });
      }
      case 'PUT': {
        const body = await boundedBody(request, 65608);
        if (!body?.length) return new Response(null, { status: 413 });
        const created = await env.OBJECTS.put(key, body, { onlyIf: { etagDoesNotMatch: '*' } });
        if (created) return new Response(null, { status: 201 });
        const stored = await env.OBJECTS.get(key);
        if (!stored || stored.size !== body.length) return new Response(null, { status: 409 });
        const existing = new Uint8Array(await stored.arrayBuffer());
        return new Response(null, { status: existing.every((byte, index) => byte === body[index]) ? 200 : 409 });
      }
      case 'DELETE':
        await env.OBJECTS.delete(key);
        return new Response(null, { status: 204 });
      default:
        return new Response(null, { status: 405 });
    }
  },
};
