import { Container } from '@cloudflare/containers';
import { JobScheduler } from './jobs.mjs';
import { boundedBody } from './storage.mjs';
import { pushBrokerContainerEnv, pushBrokerIngressRequest } from './push-broker.mjs';
export { ContainerProxy } from '@cloudflare/containers';

export class IsolatedPushBroker extends Container {
  defaultPort = 18088;
  sleepAfter = '5m';
  entrypoint = ['/app/push-broker'];
  envVars = pushBrokerContainerEnv(this.env);
}

IsolatedPushBroker.outboundByHost = {
  'jobs.internal': async (request, env) => {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.origin !== 'http://jobs.internal' || url.pathname !== '/push' || url.search || url.hash) {
      return new Response(null, { status: 404 });
    }
    const body = await boundedBody(request, 20);
    const id = body && new TextDecoder().decode(body);
    if (!id || !/^(0|[1-9][0-9]{0,19})$/.test(id) || BigInt(id) > 18446744073709551615n) return new Response(null, { status: 400 });
    await env.JOBS.getByName('push').register('push', id);
    return new Response(null, { status: 204 });
  },
};

export class PushJobScheduler extends JobScheduler {
  async register(kind, id) {
    if (kind !== 'push') throw new Error('Only push work is permitted');
    return super.register(kind, id);
  }

  async run() {
    const state = this.sql.exec('SELECT kind FROM state').toArray()[0];
    if (state && state.kind !== 'push') throw new Error('Only push work is permitted');
    return super.run();
  }

  async runAnchors() { throw new Error('Only push work is permitted'); }
}

export default {
  async scheduled(_controller, env) {
    // Recover a quiet existing queue after deployment or a missing alarm. Only
    // the private scheduled handler can bootstrap work; public health is cached.
    await env.JOBS.getByName('push').register('push', '0');
  },
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/health' && !url.search) {
        const status = await env.JOBS.getByName('push').status();
        return Response.json({ service: 'push-broker', healthy: status.failures === 0 }, { status: status.failures === 0 ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
      }
      const mapped = await pushBrokerIngressRequest(request, env);
      const response = mapped instanceof Request ? await env.PUSH_BROKER.getByName('primary').fetch(mapped) : mapped;
      await response.body?.cancel();
      return new Response(null, { status: [204, 400, 401, 404, 422, 503].includes(response.status) ? response.status : 502, headers: { 'Cache-Control': 'no-store' } });
    } catch { return new Response(null, { status: 503, headers: { 'Cache-Control': 'no-store' } }); }
  },
};
