import { Witness } from './witness-container.mjs';
import { Container, switchPort } from '@cloudflare/containers';
import { objectStorage, objectStoreCore } from './storage.mjs';
import { publicRoute, publicHealth } from './routing.mjs';
import { containerRequest, edgeContainerEnv, sealedIngress } from './edge.mjs';
import { forwardPush, pushBrokerContainerEnv } from './push-broker.mjs';
import { registerWakeup } from './jobs.mjs';
export { ContainerProxy } from '@cloudflare/containers';
export { CheckpointStore } from './checkpoint.mjs';
export { JobScheduler } from './jobs.mjs';
export { NetworkJobs } from './network-jobs.mjs';
export { IngressNonces } from './ingress-nonces.mjs';
import { networkCron, networkHealth, networkRoute } from './network.mjs';

function secrets(env, names) {
  return Object.fromEntries(names.map(name => {
    if (!env[name]) throw new Error(`Missing ${name}`);
    return [name, env[name]];
  }));
}

// Optional settings pass through only when set, so the service's defaults apply.
function optional(env, names) {
  return Object.fromEntries(names.filter(name => env[name] !== undefined).map(name => [name, String(env[name])]));
}

const primary = binding => binding.getByName('primary');

export class Directory extends Container {
  defaultPort = 18086;
  requiredPorts = [18086, 18090];
  sleepAfter = '5m';
  entrypoint = ['/app/directory-delivery'];
  envVars = {
    ...secrets(this.env, ['MESSENGER_DATABASE_URL', 'MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX',
      'MESSENGER_DELIVERY_SEALING_SEED_HEX', 'MESSENGER_DELIVERY_INTERNAL_TOKEN',
      'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN']),
    // The legacy pair seeds witness-a/witness-b; the canary log lists its own
    // witnesses in MESSENGER_WITNESS_REGISTRY instead.
    ...optional(this.env, ['MESSENGER_WITNESS_A_PUBLIC_KEY_HEX', 'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
      'MESSENGER_WITNESS_REGISTRY', 'MORSE_REGISTRY_WRITES',
      'MESSENGER_TRANSPARENCY_LOG_ORIGIN', 'MESSENGER_TRANSPARENCY_PRUNING',
      'MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP',
      // Credits (protocol/credits-v1.md): the redeemed purpose, the issuer's
      // bearer for its key leaves, the object store's for redeeming, the
      // sign-up surge target.
      'MORSE_CREDIT_ISSUER_INTERNAL_TOKEN', 'MESSENGER_OBJECT_INTERNAL_TOKEN', 'MORSE_SIGNUP_SURGE_TARGET',
      // The OHTTP gateway's keys (protocol/ohttp-v1.md): the current one and,
      // while rotating, the one being retired. Without them the gateway is off.
      'MESSENGER_OHTTP_GATEWAY_KEY_ID', 'MESSENGER_OHTTP_GATEWAY_SEED_HEX',
      'MESSENGER_OHTTP_GATEWAY_PREVIOUS_KEY_ID', 'MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX']),
    MORSE_CREDITS_MODE: this.env.MORSE_CREDITS_MODE ?? 'off',
    MESSENGER_PUSH_MODE: 'broker',
    MESSENGER_PUSH_BROKER_URL: 'http://push.internal/internal/v1/push',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
  };
}
Directory.outboundByHost = {
  'jobs.internal': (request, env) => registerWakeup(request, env, ['directory', 'witness']),
  'push.internal': (request, env) => {
    // An isolated backend reaches the broker's own deployment (§22 M4).
    if (env.MORSE_ISOLATED_PUSH === '1') return forwardPush(request, env);
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/internal/v1/push') return new Response(null, { status: 404 });
    return primary(env.PUSH_BROKER).fetch(request);
  },
};

export class PrivacyEdge extends Container {
  defaultPort = 18087;
  sleepAfter = '5m';
  entrypoint = ['/app/privacy-edge'];
  enableInternet = false;
  envVars = edgeContainerEnv(this.env);
}
// Combined development deployment only. `npm run deploy` builds an isolated
// backend without this class bound; see isolated-edge.mjs.
const edgeCorePaths = new Set(['/internal/v1/envelopes/sealed', '/internal/v1/credits/redeem', '/internal/v1/mailbox/retention',
  '/internal/v1/ohttp']);
PrivacyEdge.outboundByHost = {
  'delivery.internal': (request, env) => {
    if (request.method !== 'POST' || !edgeCorePaths.has(new URL(request.url).pathname)) return new Response(null, { status: 404 });
    return primary(env.DIRECTORY).fetch(request);
  },
};

export class ObjectStore extends Container {
  defaultPort = 18089;
  sleepAfter = '5m';
  entrypoint = ['/app/object-store'];
  envVars = {
    ...secrets(this.env, ['MESSENGER_OBJECT_INTERNAL_TOKEN']),
    MESSENGER_OBJECT_DATABASE_URL: this.env.OBJECT_DATABASE_URL,
    MESSENGER_OBJECT_STORAGE_ROOT: 'http://objects.internal',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
    // Grants above 16 MiB redeem their credits at the core (credits-v1.md "Large files").
    MESSENGER_DELIVERY_INTERNAL_URL: 'http://delivery.internal',
  };
}
ObjectStore.outboundByHost = {
  'objects.internal': (request, env) => objectStorage.fetch(request, env),
  'delivery.internal': (request, env) => objectStoreCore(request, env),
  'jobs.internal': (request, env) => registerWakeup(request, env, ['objects']),
};

export class PushBroker extends Container {
  defaultPort = 18088;
  sleepAfter = '5m';
  entrypoint = ['/app/push-broker'];
  envVars = pushBrokerContainerEnv(this.env);
}
// Combined development deployment only. `npm run deploy` builds an isolated
// backend without this class bound; see isolated-push.mjs.
PushBroker.outboundByHost = { 'jobs.internal': (request, env) => registerWakeup(request, env, ['push']) };


function witnessEnvironment(env, name) {
  return {
    MESSENGER_BASE_URL: 'http://directory.internal',
    MESSENGER_WITNESS_ID: `witness-${name.toLowerCase()}`,
    MESSENGER_WITNESS_CHECKPOINT_PATH: 'http://checkpoint.internal/',
    MESSENGER_WITNESS_SIGNING_SEED_HEX: env[`MESSENGER_WITNESS_${name}_SIGNING_SEED_HEX`],
    MESSENGER_WITNESS_PUBLIC_KEY_HEX: env[`MESSENGER_WITNESS_${name}_PUBLIC_KEY_HEX`],
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: env.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX,
  };
}

export class WitnessA extends Witness { envVars = witnessEnvironment(this.env, 'A'); }
export class WitnessB extends Witness { envVars = witnessEnvironment(this.env, 'B'); }
const witnessOutbound = {
  'directory.internal': (request, env) => {
    if (!new URL(request.url).pathname.startsWith('/v1/transparency/')) return new Response(null, { status: 404 });
    return primary(env.DIRECTORY).fetch(request);
  },
  'checkpoint.internal': (request, env, ctx) => env.WITNESS_STATE.getByName(ctx.className).fetch(request),
};
WitnessA.outboundByHost = witnessOutbound;
WitnessB.outboundByHost = witnessOutbound;

export default {
  async fetch(request, env) {
    try {
      let response;
      if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
        response = await networkHealth(env, await publicHealth(env));
      } else {
        const network = await networkRoute(request, env);
        if (network) return network;
        const route = publicRoute(request, env);
        if (!route) return new Response(null, { status: 404 });
        // Containers receive only the headers a Mesh service reads; client
        // address, location, agent, and cookie headers stop here.
        if (route === 'STREAM') response = await primary(env.DIRECTORY).fetch(switchPort(containerRequest(request), 18090));
        else if (route === 'SEALED_INGRESS') response = await sealedIngress(request, env);
        else response = await primary(env[route]).fetch(containerRequest(request));
      }
      if (response.status === 101) return response;
      const headers = new Headers(response.headers);
      headers.set('Cache-Control', 'no-store');
      headers.set('Content-Encoding', 'identity');
      return new Response(response.body, { status: response.status, headers });
    } catch (error) {
      if (new URL(request.url).pathname === '/health') {
        console.error('Health check failed', String(error).replace(/\/\/[^\s/]*@/g, '//[redacted]@').slice(0, 500));
      }
      return new Response('unavailable', { status: 503, headers: { 'Cache-Control': 'no-store' } });
    }
  },

  // Crons (wrangler.jsonc): the minute's chain reads and the hourly anchor heartbeat.
  scheduled(controller, env, ctx) {
    ctx.waitUntil(networkCron(controller, env));
  },

};
