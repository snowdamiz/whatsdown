import { Container } from '@cloudflare/containers';
import { edgeContainerEnv, edgeRoute, containerRequest, sealedDeliveryRequest, creditIssuerRequest, creditDiscoveryRequest, postageDeliveryRequest } from './edge.mjs';
import { ohttpEnabled, ohttpContainerRequest, ohttpDeliveryRequest, ohttpRelayResponse, ohttpHttpFailure } from './ohttp.mjs';
export { ContainerProxy } from '@cloudflare/containers';

// Deployed with its own credentials, like an isolated witness. This Worker sees
// source connections and opaque sealed records. It holds the bearer credential
// for the delivery core and optional credit purchases: no unsealing seed, database URL,
// transparency key, or push secret ever exists in this deployment.
export class IsolatedPrivacyEdge extends Container {
  defaultPort = 18087;
  sleepAfter = '5m';
  entrypoint = ['/app/privacy-edge'];
  enableInternet = false;
  envVars = edgeContainerEnv(this.env);
}
IsolatedPrivacyEdge.outboundByHost = {
  'delivery.internal': async (request, env) => {
    if (new URL(request.url).pathname === '/internal/v1/ohttp') {
      if (!ohttpEnabled(env)) return new Response(null, { status: 404 });
      try {
        const forwarded = await ohttpDeliveryRequest(request, env);
        if (!forwarded) return new Response(null, { status: 404 });
        return await ohttpRelayResponse(await fetch(forwarded), request.signal);
      } catch (error) { return ohttpHttpFailure(error); }
    }
    const forwarded = sealedDeliveryRequest(request, env) ?? creditDiscoveryRequest(request, env) ?? postageDeliveryRequest(request, env);
    if (!forwarded) return new Response(null, { status: 404 });
    const response = await fetch(forwarded);
    if (response.status >= 300 && response.status < 400) return new Response(null, { status: 502 });
    return response;
  },
  'issuer.internal': async (request, env) => {
    const forwarded = creditIssuerRequest(request, env);
    if (!forwarded) return new Response(null, { status: 404 });
    const response = await fetch(forwarded);
    return response.status >= 300 && response.status < 400 ? new Response(null, { status: 502 }) : response;
  },
};

export default {
  async fetch(request, env) {
    const noStore = { 'Cache-Control': 'no-store' };
    if (new URL(request.url).pathname === '/v1/ohttp') {
      if (!ohttpEnabled(env)) return new Response(null, { status: 404, headers: noStore });
      try {
        const mapped = await ohttpContainerRequest(request);
        if (!mapped) return new Response(null, { status: 404, headers: noStore });
        return await ohttpRelayResponse(await env.PRIVACY_EDGE.getByName('primary').fetch(mapped), request.signal);
      } catch (error) { return ohttpHttpFailure(error); }
    }
    try {
      if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
        return new Response('ok', { status: 200, headers: noStore });
      }
      if (!edgeRoute(request)) return new Response(null, { status: 404 });
      const response = await env.PRIVACY_EDGE.getByName('primary').fetch(containerRequest(request));
      const headers = new Headers(response.headers);
      headers.set('Cache-Control', 'no-store');
      headers.set('Content-Encoding', 'identity');
      return new Response(response.body, { status: response.status, headers });
    } catch {
      return new Response('unavailable', { status: 503, headers: noStore });
    }
  },
};
