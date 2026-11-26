import { Container } from '@cloudflare/containers';
import { brokerIngress, pushBrokerContainerEnv } from './push-broker.mjs';
import { publicHealth } from './routing.mjs';
import { registerWakeup } from './jobs.mjs';
export { ContainerProxy } from '@cloudflare/containers';
export { JobScheduler } from './jobs.mjs';

// Deployed with its own credentials, like the edge and the witnesses (§22 M4).
// This deployment holds the token-unsealing seed, the push queue's database URL
// and its own scheduler. It never holds a delivery, transparency or edge secret,
// and the backend reaches it only with the broker bearer at /internal/v1/push.
export class IsolatedPushBroker extends Container {
  defaultPort = 18088;
  sleepAfter = '5m';
  entrypoint = ['/app/push-broker'];
  envVars = pushBrokerContainerEnv(this.env);
}
IsolatedPushBroker.outboundByHost = { 'jobs.internal': (request, env) => registerWakeup(request, env, ['push']) };

export default {
  async fetch(request, env) {
    const noStore = { 'Cache-Control': 'no-store' };
    try {
      if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
        const health = await publicHealth(env, ['push']);
        return new Response(health.body, { status: health.status, headers: noStore });
      }
      const accepted = brokerIngress(request, env);
      if (accepted instanceof Response) return new Response(null, { status: accepted.status, headers: noStore });
      const response = await env.PUSH_BROKER.getByName('primary').fetch(accepted);
      return new Response(response.body, { status: response.status, headers: noStore });
    } catch {
      return new Response('unavailable', { status: 503, headers: noStore });
    }
  },
};
