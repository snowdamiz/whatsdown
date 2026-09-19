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

// Only the object-store container's outbound handler exposes this binding.
export const objectStorage = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const match = /^\/([a-f0-9]{64})\.(0|[1-9][0-9]{0,2})$/.exec(url.pathname);
    if (!match || Number(match[2]) > 256 || url.search) return new Response(null, { status: 400 });
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
