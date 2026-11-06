import { DurableObject } from 'cloudflare:workers';
import { boundedBody } from './storage.mjs';

export class CheckpointStore extends DurableObject {
  async fetch(request) {
    const evidence = /\/evidence\/(timing|history)$/.exec(new URL(request.url).pathname);
    if (evidence) {
      const key = `evidence-${evidence[1]}`;
      if (request.method === 'GET') {
        const body = await this.ctx.storage.get(key);
        return new Response(body ?? null, { status: body ? 200 : 404, headers: { 'Content-Type': 'application/json' } });
      }
      if (request.method !== 'PUT') return new Response(null, { status: 405 });
      const body = await boundedBody(request, 2048);
      if (!body?.length) return new Response(null, { status: 400 });
      await this.ctx.storage.transaction(async storage => {
        if (!await storage.get(key)) await storage.put(key, body);
      });
      return new Response(null, { status: 204 });
    }
    if (request.method === 'GET') {
      const stored = await this.ctx.storage.get('checkpoint');
      return new Response(stored?.body ?? null, { status: stored ? 200 : 404 });
    }
    if (request.method !== 'PUT') return new Response(null, { status: 405 });
    const body = await boundedBody(request, 4096);
    const expected = request.headers.get('If-Match');
    if (!body?.length || !expected || !/^(none|[a-f0-9]{64})$/.test(expected)) {
      return new Response(null, { status: 400 });
    }
    const digest = await crypto.subtle.digest('SHA-256', body);
    const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    const accepted = await this.ctx.storage.transaction(async storage => {
      const previous = await storage.get('checkpoint');
      if (previous?.hash === hash) return true;
      if ((previous?.hash ?? 'none') !== expected) return false;
      await storage.put('checkpoint', { body, hash });
      return true;
    });
    return new Response(null, { status: accepted ? 204 : 409 });
  }
}
