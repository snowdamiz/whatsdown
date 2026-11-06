import { publicSnapshotEnabled, publicSnapshotRoute } from './public-snapshot-worker.mjs';
export { PublicReportReader, PublicSnapshotPublisher } from './public-snapshot-worker.mjs';
import { Witness } from './witness-container.mjs';
import { Container, switchPort } from '@cloudflare/containers';
import { objectStorage, boundedBody } from './storage.mjs';
import { issuerIngressRequest } from './issuer-ingress.mjs';
import { publicRoute, publicHealth } from './routing.mjs';
import { containerRequest, edgeContainerEnv, sealedIngressRequest, creditIssuerRequest, creditAttachmentRequest, postageIngressRequest } from './edge.mjs';
import { sealedIngressClientAllowed } from './sealed-ingress-policy.mjs';
import { directoryPushUrl, forwardPushWake } from './push-broker.mjs';
import { ohttpIngressRequest, ohttpRelayResponse, ohttpHttpFailure, ohttpGatewayEnv } from './ohttp.mjs';
export { ContainerProxy } from '@cloudflare/containers';
export { CheckpointStore } from './checkpoint.mjs';
export { JobScheduler } from './jobs.mjs';

function secrets(env, names) {
  return Object.fromEntries(names.map(name => {
    if (!env[name]) throw new Error(`Missing ${name}`);
    return [name, env[name]];
  }));
}

const primary = binding => binding.getByName('primary');

async function registerWakeup(request, env, allowed) {
  const url = new URL(request.url);
  const kind = url.pathname.slice(1);
  if (request.method !== 'POST' || !allowed.includes(kind) || url.search) return new Response(null, { status: 404 });
  const body = await boundedBody(request, 20);
  if (!body?.length) return new Response(null, { status: 400 });
  await env.JOBS.getByName(kind).register(kind, new TextDecoder().decode(body));
  return new Response(null, { status: 204 });
}

export class Directory extends Container {
  defaultPort = 18086;
  requiredPorts = [18086, 18090];
  sleepAfter = '5m';
  entrypoint = ['/app/directory-delivery'];
  envVars = {
    ...ohttpGatewayEnv(this.env),
    ...secrets(this.env, ['MESSENGER_DATABASE_URL', 'MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX',
      'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX', 'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
      'MESSENGER_DELIVERY_SEALING_SEED_HEX', 'MESSENGER_DELIVERY_INTERNAL_TOKEN',
      'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN']),
    MESSENGER_PUSH_MODE: 'broker',
    MESSENGER_PUSH_BROKER_URL: directoryPushUrl(this.env),
    MESSENGER_JOBS_URL: 'http://jobs.internal',
    WITNESS_A_URL: this.env.WITNESS_A_URL ?? '',
    WITNESS_B_URL: this.env.WITNESS_B_URL ?? '',
    MORSE_COMPACT_PROOFS: this.env.MORSE_COMPACT_PROOFS ?? 'off',
    MORSE_C2SP_PUSH: this.env.MORSE_C2SP_PUSH ?? 'off',
    MORSE_TRANSPARENCY_RETENTION: this.env.MORSE_TRANSPARENCY_RETENTION ?? 'off',
    MORSE_TRANSPARENCY_PRUNE_DAILY_CAP: this.env.MORSE_TRANSPARENCY_PRUNE_DAILY_CAP ?? '1000',
    MESSENGER_PREKEY_RETENTION: this.env.MESSENGER_PREKEY_RETENTION ?? 'off',
    MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN: this.env.MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN ?? '',
    MESSENGER_CREDITS_PURPOSE: this.env.MESSENGER_CREDITS_PURPOSE ?? 'live',
    MORSE_PAID_RETENTION: this.env.MORSE_PAID_RETENTION ?? 'off',
    MORSE_PAID_SIGNUP: this.env.MORSE_PAID_SIGNUP ?? 'off',
    MORSE_PAID_INBOX_POSTAGE: this.env.MORSE_PAID_INBOX_POSTAGE ?? 'off',
    MORSE_PAID_LARGE_ATTACHMENTS: this.env.MORSE_PAID_LARGE_ATTACHMENTS ?? 'off',
    MESSENGER_ABUSE_BASE_DIFFICULTY: this.env.MESSENGER_ABUSE_BASE_DIFFICULTY ?? '16',
    MESSENGER_ABUSE_DIFFICULTY: this.env.MESSENGER_ABUSE_DIFFICULTY ?? '16',
    MESSENGER_SIGNUP_DIFFICULTY: this.env.MESSENGER_SIGNUP_DIFFICULTY ?? this.env.MESSENGER_ABUSE_DIFFICULTY ?? '16',
  };
}
Directory.outboundByHost = {
  'jobs.internal': (request, env) => registerWakeup(request, env, ['directory', 'witness']),
  'push.internal': (request, env) => {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/internal/v1/push') return new Response(null, { status: 404 });
    if (env.MORSE_ISOLATED_PUSH_BROKER !== undefined) return forwardPushWake(request, env);
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
PrivacyEdge.outboundByHost = {
  'delivery.internal': (request, env) => {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.search || !['/internal/v1/envelopes/sealed', '/v1/credits/issuer', '/v1/credits/retention', '/v1/credits/signup', '/v1/credits/signup-policy', '/v1/credits/reconcile', '/v1/credits/postage-policy', '/internal/credits/postage', '/internal/credits/postage/reconcile'].includes(url.pathname)) return new Response(null, { status: 404 });
    if (url.pathname === '/internal/v1/envelopes/sealed' && !sealedIngressClientAllowed(request, env)) return new Response(null, { status: 404 });
    return primary(env.DIRECTORY).fetch(request);
  },
  'issuer.internal': async (request, env) => {
    const forwarded = creditIssuerRequest(request, env);
    if (!forwarded) return new Response(null, { status: 404 });
    const response = await fetch(forwarded);
    return response.status >= 300 && response.status < 400 ? new Response(null, { status: 502 }) : response;
  },
};

export class ObjectStore extends Container {
  defaultPort = 18089;
  sleepAfter = '5m';
  entrypoint = ['/app/object-store'];
  envVars = {
    ...secrets(this.env, ['MESSENGER_OBJECT_INTERNAL_TOKEN']),
    ...(this.env.MORSE_PAID_LARGE_ATTACHMENTS === 'on' ? secrets(this.env, ['MESSENGER_DELIVERY_INTERNAL_TOKEN']) : {}),
    MESSENGER_OBJECT_DATABASE_URL: this.env.OBJECT_DATABASE_URL,
    MESSENGER_OBJECT_STORAGE_ROOT: 'http://objects.internal',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
    MORSE_PAID_LARGE_ATTACHMENTS: this.env.MORSE_PAID_LARGE_ATTACHMENTS ?? 'off',
    MESSENGER_OBJECT_CREDIT_CORE_URL: 'http://credit-core.internal',
    MESSENGER_OBJECT_CREDIT_SERVICE_PUBLIC_KEY_HEX: this.env.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX ?? '',
  };
}
ObjectStore.outboundByHost = {
  'credit-core.internal': (request, env) => {
    const forwarded = creditAttachmentRequest(request);
    return forwarded ? primary(env.DIRECTORY).fetch(forwarded) : new Response(null, { status: 404 });
  },
  'objects.internal': (request, env) => objectStorage.fetch(request, env),
  'jobs.internal': (request, env) => registerWakeup(request, env, ['objects']),
};

export class PushBroker extends Container {
  defaultPort = 18088;
  sleepAfter = '5m';
  entrypoint = ['/app/push-broker'];
  envVars = {
    ...secrets(this.env, ['MESSENGER_PUSH_BROKER_SEED_HEX', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN']),
    MESSENGER_PUSH_BROKER_DATABASE_URL: this.env.PUSH_DATABASE_URL,
    MESSENGER_EXPO_ACCESS_TOKEN: this.env.MESSENGER_EXPO_ACCESS_TOKEN ?? '',
    MESSENGER_JOBS_URL: 'http://jobs.internal',
  };
}
PushBroker.outboundByHost = { 'jobs.internal': (request, env) => registerWakeup(request, env, ['push']) };


function witnessEnvironment(env, name) {
  return {
    MESSENGER_BASE_URL: 'http://directory.internal',
    MESSENGER_WITNESS_ID: `witness-${name.toLowerCase()}`,
    MESSENGER_WITNESS_CHECKPOINT_PATH: 'http://checkpoint.internal/',
    MESSENGER_WITNESS_SIGNING_SEED_HEX: env[`MESSENGER_WITNESS_${name}_SIGNING_SEED_HEX`],
    MESSENGER_WITNESS_PUBLIC_KEY_HEX: env[`MESSENGER_WITNESS_${name}_PUBLIC_KEY_HEX`],
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: env.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX,
    MESSENGER_SECURITY_CONFIG: env.MESSENGER_SECURITY_CONFIG ?? '',
  };
}

export class WitnessA extends Witness { envVars = witnessEnvironment(this.env, 'A'); }
export class WitnessB extends Witness { envVars = witnessEnvironment(this.env, 'B'); }
const witnessOutbound = {
  'directory.internal': (request, env) => {
    if (!/^\/v[12]\/transparency\//.test(new URL(request.url).pathname)) return new Response(null, { status: 404 });
    return primary(env.DIRECTORY).fetch(request);
  },
  'checkpoint.internal': (request, env, ctx) => env.WITNESS_STATE.getByName(ctx.className).fetch(request),
};
WitnessA.outboundByHost = witnessOutbound;
WitnessB.outboundByHost = witnessOutbound;

export default {
  async scheduled(_controller, env) {
    const recoveries = [];
    if (publicSnapshotEnabled(env)) recoveries.push(Promise.resolve().then(() => env.PUBLIC_SNAPSHOTS.getByName('primary').schedule()));
    // Bootstrap quiet logs and recover a missing alarm without a public route
    // that can start signers. Normal work continues on the DO's 15-second alarm.
    if ((env.MORSE_ANCHOR_MODE ?? 'off') !== 'off') {
      recoveries.push(Promise.resolve().then(() => env.JOBS.getByName('anchor').register('anchor', '0')));
    }
    // A misconfigured read-only publisher must not prevent anchor recovery.
    // Keep the event alive until both attempts settle and retain failure status.
    const results = await Promise.allSettled(recoveries);
    const failed = results.find(result => result.status === 'rejected');
    if (failed) throw failed.reason;
  },

  async fetch(request, env) {
    try {
      const snapshot = await publicSnapshotRoute(request, env);
      if (snapshot) return snapshot;
      let response;
      if (request.method === 'GET' && new URL(request.url).pathname === '/health') {
        response = await publicHealth(env);
      } else {
        const route = publicRoute(request, env);
        if (!route) return new Response(null, { status: 404 });
        if (route === 'OHTTP_INGRESS') {
          try {
            const mapped = await ohttpIngressRequest(request, env);
            if (!mapped) return new Response(null, { status: 404 });
            return await ohttpRelayResponse(await primary(env.DIRECTORY).fetch(mapped), request.signal);
          } catch (error) { return ohttpHttpFailure(error); }
        }
        // Containers receive only the headers a Mesh service reads; client
        // address, location, agent, and cookie headers stop here.
        if (route === 'STREAM') response = await primary(env.DIRECTORY).fetch(switchPort(containerRequest(request), 18090));
        else if (route === 'ISSUER_INGRESS') {
          const mapped = await issuerIngressRequest(request);
          response = mapped instanceof Request ? await primary(env.DIRECTORY).fetch(mapped) : mapped ?? new Response(null, { status: 404 });
        }
        else if (route === 'SEALED_INGRESS') {
          const mapped = sealedIngressRequest(request, env);
          response = mapped ? await primary(env.DIRECTORY).fetch(mapped) : new Response(null, { status: 404 });
        }
        else if (route === 'POSTAGE_INGRESS') {
          const mapped = postageIngressRequest(request);
          response = mapped ? await primary(env.DIRECTORY).fetch(mapped) : new Response(null, { status: 404 });
        }
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

};
