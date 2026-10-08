import { Container } from '@cloudflare/containers';
import { creditIssuerContainerEnv, issuerIngress } from './credit-issuer.mjs';
export { ContainerProxy } from '@cloudflare/containers';

// Its own deployment, with its own credentials (services/credit-issuer/README.md):
// the key-wrapping and deposit seeds and its database never exist anywhere
// else, and it holds nothing of the backend's but the bearer for announcing
// its keys into the log. It needs the internet: Solana RPC, Pyth, LND and the
// directory's issuer-key route.
export class IsolatedCreditIssuer extends Container {
  defaultPort = 18092;
  sleepAfter = '10m';
  entrypoint = ['/app/credit-issuer'];
  envVars = creditIssuerContainerEnv(this.env);
}

export default {
  async fetch(request, env) {
    const noStore = { 'Cache-Control': 'no-store' };
    try {
      const accepted = issuerIngress(request, env);
      if (accepted instanceof Response) return new Response(null, { status: accepted.status, headers: noStore });
      const response = await env.CREDIT_ISSUER.getByName('primary').fetch(accepted);
      return new Response(response.body, { status: response.status, headers: noStore });
    } catch {
      return new Response('unavailable', { status: 503, headers: noStore });
    }
  },
};
