// Permission-denial and account-isolation checks for the separated deployments
// (§22 M1), with read-only Cloudflare API calls:
//
//   MORSE_ISOLATION_<ID>_ACCOUNT_ID=… (all five) MORSE_ISOLATION_<ID>_TOKEN=… node isolation-check.mjs
//
// for ID in BACKEND, EDGE, PUSH_BROKER, WITNESS_A, WITNESS_B. Account IDs aren't
// secret; tokens are, so each credential holder runs this with only their own
// token and every deployment with a token is checked. Its token must reach
// exactly its own account, Worker, containers and stores, which hold only its
// own secrets and bindings, and be refused every other deployment's. Tokens are
// never printed. Exit status 1 unless every check passes.
import { fileURLToPath } from 'node:url';
import { certificatePins } from './edge.mjs';
import { ingressPublicKeys } from './ingress-signature.mjs';

const api = 'https://api.cloudflare.com/client/v4';
const witnessSecrets = ['MESSENGER_WITNESS_SIGNING_SEED_HEX', 'MESSENGER_WITNESS_PUBLIC_KEY_HEX',
  'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX', 'WITNESS_INVOKE_TOKEN', 'WITNESS_INITIAL_CHECKPOINT_HEX'];
const witnessBindings = ['WITNESS', 'WITNESS_STATE', 'MESSENGER_WITNESS_ID', 'MORSE_DIRECTORY_URL', 'WITNESS_INITIAL_CHECKPOINT_HEX'];

// secrets/bindings: allowlists (secret_text bindings are checked as secrets).
// The backend's own set grows with features, so it lists what it must NOT hold.
export const deployments = [
  { id: 'backend', script: 'morse-backend', buckets: ['morse-encrypted-objects'],
    forbiddenSecrets: ['MESSENGER_PUSH_BROKER_SEED_HEX', 'PUSH_DATABASE_URL', 'MESSENGER_EXPO_ACCESS_TOKEN',
      'MESSENGER_WITNESS_A_SIGNING_SEED_HEX', 'MESSENGER_WITNESS_B_SIGNING_SEED_HEX', 'MESSENGER_WITNESS_SIGNING_SEED_HEX', 'WITNESS_INVOKE_TOKEN',
      'MORSE_EDGE_INGRESS_SIGNING_KEY'],
    forbiddenBindings: ['PUSH_BROKER', 'PRIVACY_EDGE', 'WITNESS_A', 'WITNESS_B', 'DELIVERY_CLIENT_CERT', 'MORSE_EDGE_INGRESS_SIGNING_KEY'],
    // The combined topology's containers, left behind if not deleted at cutover.
    forbiddenContainers: ['pushbroker', 'privacyedge', 'witnessa', 'witnessb'].map(x => `morse-backend-${x}`),
    // Either pin: the edge's signing public keys or its certificate fingerprints.
    m2: ['M2 ingress pin', bindings => [['MORSE_EDGE_INGRESS_PUBLIC_KEY', ingressPublicKeys], ['MORSE_INGRESS_CLIENT_CERT_SHA256', certificatePins]]
      .some(([name, parse]) => {
        const pin = bindings.find(x => x.name === name && x.type === 'plain_text');
        try { return Boolean(pin && parse(pin.text)); } catch { return false; }
      })] },
  { id: 'edge', script: 'morse-privacy-edge', secrets: ['MESSENGER_DELIVERY_INTERNAL_TOKEN', 'MORSE_EDGE_INGRESS_SIGNING_KEY'],
    bindings: ['PRIVACY_EDGE', 'DELIVERY_CLIENT_CERT', 'MORSE_DELIVERY_URL'],
    m2: ['M2 edge credential', (bindings, secrets) => secrets.includes('MORSE_EDGE_INGRESS_SIGNING_KEY')
      || bindings.some(x => x.name === 'DELIVERY_CLIENT_CERT' && x.type === 'mtls_certificate')] },
  { id: 'push-broker', script: 'morse-push-broker',
    secrets: ['MESSENGER_PUSH_BROKER_SEED_HEX', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'PUSH_DATABASE_URL',
      'MESSENGER_EXPO_ACCESS_TOKEN', 'MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX'],
    bindings: ['PUSH_BROKER', 'JOBS'] },
  { id: 'witness-a', script: 'morse-witness-a', secrets: witnessSecrets, bindings: witnessBindings },
  { id: 'witness-b', script: 'morse-witness-b', secrets: witnessSecrets, bindings: witnessBindings },
];

const envName = id => `MORSE_ISOLATION_${id.toUpperCase().replace('-', '_')}`;

function credentials(env) {
  const all = deployments.map(deployment => {
    const account = env[`${envName(deployment.id)}_ACCOUNT_ID`];
    if (!/^[a-f0-9]{32}$/.test(account ?? '')) throw new Error(`Set ${envName(deployment.id)}_ACCOUNT_ID to the 32-hex account ID`);
    return { ...deployment, account, token: env[`${envName(deployment.id)}_TOKEN`] || null };
  });
  if (!all.some(x => x.token)) throw new Error('Set at least one MORSE_ISOLATION_<ID>_TOKEN (your own deployment\'s)');
  return all;
}

async function get(fetcher, token, path) {
  try {
    const response = await fetcher(`${api}${path}`, {
      method: 'GET', headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(30_000) });
    const body = await response.json().catch(() => null);
    return { status: response.status, result: body?.result };
  } catch {
    return { status: 0 };
  }
}

const names = (list, key = 'name') => (Array.isArray(list) ? list : []).map(x => x[key]);
const listed = (response, pick) => response.status === 200 ? pick(response.result) : null;
const containerOf = (name, deployment) => name === deployment.script || name.startsWith(`${deployment.script}-`);

// The probes each token must be refused in another deployment's account.
const probes = other => [
  `/accounts/${other.account}/workers/scripts`, `/accounts/${other.account}/workers/scripts/${other.script}/settings`,
  `/accounts/${other.account}/workers/scripts/${other.script}/secrets`, `/accounts/${other.account}/containers/applications`,
  `/accounts/${other.account}/r2/buckets`,
];

async function checkDeployment(d, all, fetcher) {
  const results = [];
  const result = (check, ok, detail) => results.push({ deployment: d.id, check, ok, detail });
  const others = all.filter(x => x !== d);
  const at = path => get(fetcher, d.token, `/accounts/${d.account}${path}`);

  const accounts = listed(await get(fetcher, d.token, '/accounts'), x => names(x, 'id'));
  result('reaches only its own account', accounts?.length === 1 && accounts[0] === d.account,
    accounts ? `token reaches ${accounts.length} account(s)` : 'account listing refused');

  const scripts = listed(await at('/workers/scripts'), x => names(x, 'id'));
  result('own Worker', Boolean(scripts?.includes(d.script)), scripts ? `${d.script} ${scripts.includes(d.script) ? 'present' : 'missing'}` : 'script listing refused');
  const foreign = (scripts ?? []).filter(name => others.some(x => x.script === name));
  result('only its own Workers', scripts !== null && !foreign.length, foreign.length ? `also holds ${foreign.join(', ')}` : 'no other deployment\'s Worker');

  const secrets = listed(await at(`/workers/scripts/${d.script}/secrets`), x => names(x));
  const badSecrets = (secrets ?? []).filter(name => d.secrets ? !d.secrets.includes(name) : d.forbiddenSecrets.includes(name));
  result('secrets', secrets !== null && !badSecrets.length, secrets ? (badSecrets.length ? `must not hold ${badSecrets.join(', ')}` : `${secrets.length} allowed`) : 'secret listing refused');

  const bindings = listed(await at(`/workers/scripts/${d.script}/settings`), x => x?.bindings ?? []);
  const badBindings = (bindings ?? []).filter(x => x.type !== 'secret_text').filter(x => d.bindings
    ? !d.bindings.includes(x.name) : d.forbiddenBindings.includes(x.name) || x.type === 'mtls_certificate').map(x => x.name);
  result('bindings', bindings !== null && !badBindings.length, bindings ? (badBindings.length ? `must not bind ${badBindings.join(', ')}` : 'allowed') : 'settings refused');
  if (d.m2) result(d.m2[0], Boolean(bindings && secrets && d.m2[1](bindings, secrets)), 'required before the S1 gate opens');

  const containers = listed(await at('/containers/applications'), x => names(x));
  const badContainers = (containers ?? []).filter(name => others.some(x => containerOf(name, x)) || d.forbiddenContainers?.includes(name));
  result('containers', containers !== null && !badContainers.length, containers ? (badContainers.length ? `must not hold ${badContainers.join(', ')}` : `${containers.length} own`) : 'container listing refused');

  const buckets = listed(await at('/r2/buckets'), x => names(x?.buckets));
  const badBuckets = (buckets ?? []).filter(name => others.some(x => x.buckets?.includes(name)));
  result('stores', buckets !== null && !badBuckets.length, buckets ? (badBuckets.length ? `holds ${badBuckets.join(', ')}` : 'no other deployment\'s bucket') : 'bucket listing refused');

  for (const other of others) {
    if (other.account === d.account) {
      result(`denied ${other.id}`, false, 'shares its account');
      continue;
    }
    const statuses = await Promise.all(probes(other).map(async path => (await get(fetcher, d.token, path)).status));
    // Only an explicit refusal counts; a 5xx, 429 or network error proves nothing.
    const reached = statuses.filter(status => ![401, 403, 404].includes(status));
    result(`denied ${other.id}`, !reached.length, reached.length ? `answered ${reached.join(', ')}` : 'refused');
  }
  return results;
}

export async function isolationCheck(env, fetcher = fetch) {
  const all = credentials(env);
  return (await Promise.all(all.filter(d => d.token).map(d => checkDeployment(d, all, fetcher)))).flat();
}

export function report(results) {
  const lines = results.map(x => `${x.ok ? 'PASS' : 'FAIL'} ${x.deployment}: ${x.check} (${x.detail})`);
  const checked = new Set(results.map(x => x.deployment));
  lines.push(`checked: ${[...checked].join(', ')}; not checked here: ${deployments.map(x => x.id).filter(x => !checked.has(x)).join(', ') || 'none'}`);
  const failed = results.filter(x => !x.ok).length;
  lines.push(failed ? `${failed} check(s) failed: the edge/core split is not verified.`
    : 'Every check run here passed. The split is verified only when every holder\'s run passes; the S1 gate also needs the rest of S1 (README, "Cutover to separate accounts").');
  return lines.join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const results = await isolationCheck(process.env);
    console.log(report(results));
    process.exitCode = results.every(x => x.ok) ? 0 : 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
