import { httpsOrigin } from './witness.mjs';
import { certificatePins } from './edge.mjs';
import { ingressPublicKeys } from './ingress-signature.mjs';
import { latestMeshRelease } from '../../scripts/mesh-release.mjs';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// A release deploys the commit its verification ran against (the release job
// sets MESH_LANG_REVISION); every other build uses the latest Mesh release.
export async function meshRevision(env, latestRelease = async () => (await latestMeshRelease()).revision) {
  return env.MESH_LANG_REVISION || latestRelease();
}

export function compilerConfig(config, revision) {
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('Mesh revision must be a full commit SHA');
  return { ...config, containers: config.containers.map(container => ({
    ...container,
    image_vars: { ...container.image_vars, MESH_LANG_REVISION: revision },
  })) };
}

export function isolatedConfig(config, env) {
  const a = httpsOrigin(env.WITNESS_A_URL);
  const b = httpsOrigin(env.WITNESS_B_URL);
  if (a === b) throw new Error('Witness origins must be distinct');
  // Witnesses, the privacy edge and the push broker each run under their own
  // deployment. A backend that could also see source connections would defeat
  // sealed delivery; one holding the broker's unsealing key would join
  // mailboxes to push tokens (§22 M4).
  const separate = x => x.startsWith('Witness') || x === 'PrivacyEdge' || x === 'PushBroker';
  return { ...config,
    vars: { ...config.vars, MORSE_ISOLATED_WITNESSES: '1', MORSE_ISOLATED_EDGE: '1', MORSE_ISOLATED_PUSH: '1',
      WITNESS_A_URL: a, WITNESS_B_URL: b, MORSE_PUSH_BROKER_URL: httpsOrigin(env.MORSE_PUSH_BROKER_URL), ...ingressPins(env) },
    ...ingressRoute(env),
    containers: config.containers.filter(x => !separate(x.class_name)),
    durable_objects: { bindings: config.durable_objects.bindings.filter(x => !x.name.startsWith('WITNESS') && !['PRIVACY_EDGE', 'PUSH_BROKER'].includes(x.name)) },
  };
}

// §22 M2: the edge's credentials, pinned on the backend (comma-separated while
// rotating): its signing public keys, and/or its client certificate's
// fingerprints and optionally issuer DN. The edge's private key is never here.
function ingressPins(env) {
  const signature = env.MORSE_EDGE_INGRESS_PUBLIC_KEY
    ? { MORSE_EDGE_INGRESS_PUBLIC_KEY: ingressPublicKeys(env.MORSE_EDGE_INGRESS_PUBLIC_KEY).join(',') } : {};
  if (!env.MORSE_INGRESS_CLIENT_CERT_SHA256) {
    if (env.MORSE_INGRESS_CLIENT_CERT_ISSUER) throw new Error('MORSE_INGRESS_CLIENT_CERT_ISSUER needs MORSE_INGRESS_CLIENT_CERT_SHA256');
    return signature;
  }
  return { ...signature, MORSE_INGRESS_CLIENT_CERT_SHA256: certificatePins(env.MORSE_INGRESS_CLIENT_CERT_SHA256).join(','),
    ...(env.MORSE_INGRESS_CLIENT_CERT_ISSUER ? { MORSE_INGRESS_CLIENT_CERT_ISSUER: env.MORSE_INGRESS_CLIENT_CERT_ISSUER } : {}) };
}

// Client certificate verification is a zone setting, so the sealed ingress gets
// a custom domain on the backend's zone (workers.dev can't verify certificates).
function ingressRoute(env) {
  const host = env.MORSE_INGRESS_HOSTNAME;
  if (!host) return {};
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) throw new Error('Expected an ingress hostname');
  return { routes: [{ pattern: host, custom_domain: true }] };
}

// The canary log (plan §11.3): a second backend with its own Worker, database,
// service key, log origin and log account (morse-canary). Its witnesses T1-T3
// run in pull mode on other hosts, so it binds none; release builds never pin it.
export function canaryConfig(config) {
  const separate = x => x.startsWith('Witness') || x === 'PrivacyEdge';
  return { ...config, name: 'morse-backend-canary',
    vars: { ...config.vars, MORSE_LOG_ID: 'morse-canary', MESSENGER_TRANSPARENCY_LOG_ORIGIN: 'morseapp.io/log/canary',
      MORSE_ISOLATED_WITNESSES: '1', MORSE_ISOLATED_EDGE: '1' },
    r2_buckets: [{ binding: 'OBJECTS', bucket_name: 'morse-canary-encrypted-objects' }],
    containers: config.containers.filter(x => !separate(x.class_name)),
    durable_objects: { bindings: config.durable_objects.bindings.filter(x => !x.name.startsWith('WITNESS') && x.name !== 'PRIVACY_EDGE') },
  };
}

export function edgeConfig(config, env) {
  const certificate = env.MORSE_EDGE_CLIENT_CERT_ID;
  if (certificate && !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(certificate)) {
    throw new Error('Expected the mTLS certificate ID from wrangler mtls-certificate upload');
  }
  return {
    ...(certificate ? { mtls_certificates: [{ binding: 'DELIVERY_CLIENT_CERT', certificate_id: certificate }] } : {}),
    name: 'morse-privacy-edge', main: 'isolated-edge.mjs',
    compatibility_date: config.compatibility_date, compatibility_flags: ['nodejs_compat'],
    workers_dev: true, preview_urls: false, observability: { enabled: false },
    vars: { MORSE_DELIVERY_URL: httpsOrigin(env.MORSE_DELIVERY_URL),
      ...(env.MORSE_CREDIT_ISSUER_URL ? { MORSE_CREDIT_ISSUER_URL: httpsOrigin(env.MORSE_CREDIT_ISSUER_URL) } : {}) },
    durable_objects: { bindings: [{ name: 'PRIVACY_EDGE', class_name: 'IsolatedPrivacyEdge' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['IsolatedPrivacyEdge'] }],
    containers: [{ ...config.containers.find(x => x.class_name === 'PrivacyEdge'), class_name: 'IsolatedPrivacyEdge' }],
  };
}

// §22 M4: the broker and its token-unsealing key in a deployment of their own,
// with their own scheduler. The backend reaches it only at /internal/v1/push.
export function pushBrokerConfig(config) {
  return {
    name: 'morse-push-broker', main: 'isolated-push.mjs',
    compatibility_date: config.compatibility_date, compatibility_flags: ['nodejs_compat'],
    workers_dev: true, preview_urls: false, observability: { enabled: false },
    durable_objects: { bindings: [
      { name: 'PUSH_BROKER', class_name: 'IsolatedPushBroker' },
      { name: 'JOBS', class_name: 'JobScheduler' },
    ] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['IsolatedPushBroker', 'JobScheduler'] }],
    containers: [{ ...config.containers.find(x => x.class_name === 'PushBroker'), class_name: 'IsolatedPushBroker' }],
  };
}

// The credit issuer in a deployment of its own (services/credit-issuer): its
// seeds and database never reach the backend, and the backend's never reach it.
export function creditIssuerConfig(config) {
  const base = config.containers.find(x => x.class_name === 'PushBroker');
  return {
    name: 'morse-credit-issuer', main: 'isolated-credit-issuer.mjs',
    compatibility_date: config.compatibility_date, compatibility_flags: ['nodejs_compat'],
    workers_dev: true, preview_urls: false, observability: { enabled: false },
    durable_objects: { bindings: [{ name: 'CREDIT_ISSUER', class_name: 'IsolatedCreditIssuer' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['IsolatedCreditIssuer'] }],
    containers: [{ ...base, class_name: 'IsolatedCreditIssuer' }],
  };
}

export function witnessConfig(config, name, env) {
  if (!['a', 'b'].includes(name)) throw new Error('Expected witness a or b');
  return {
    name: `morse-witness-${name}`, main: 'isolated-witness.mjs',
    compatibility_date: config.compatibility_date, compatibility_flags: ['nodejs_compat'],
    workers_dev: true, preview_urls: false, observability: { enabled: false },
    vars: { MESSENGER_WITNESS_ID: `witness-${name}`, MORSE_DIRECTORY_URL: httpsOrigin(env.MORSE_DIRECTORY_URL) },
    durable_objects: { bindings: [
      { name: 'WITNESS', class_name: 'IsolatedWitness' },
      { name: 'WITNESS_STATE', class_name: 'CheckpointStore' },
    ] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['IsolatedWitness', 'CheckpointStore'] }],
    containers: [{ ...config.containers.find(x => x.class_name === 'WitnessA'), class_name: 'IsolatedWitness' }],
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const revision = await meshRevision(process.env);
  let config = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
  const mode = process.argv[2];
  if (mode === '--isolated') config = isolatedConfig(config, process.env);
  else if (mode === '--witness-a' || mode === '--witness-b') config = witnessConfig(config, mode.at(-1), process.env);
  else if (mode === '--edge') config = edgeConfig(config, process.env);
  else if (mode === '--push-broker') config = pushBrokerConfig(config);
  else if (mode === '--credit-issuer') config = creditIssuerConfig(config);
  else if (mode === '--canary') config = canaryConfig(config);
  else if (mode) throw new Error('Unknown deployment mode');
  writeFileSync(new URL('./wrangler.build.json', import.meta.url), JSON.stringify(compilerConfig(config, revision), null, 2) + '\n');
  console.log(`Building all services with Mesh ${revision}`);
}
