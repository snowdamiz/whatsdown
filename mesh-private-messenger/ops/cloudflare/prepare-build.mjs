import { httpsOrigin } from './witness.mjs';
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
  // Witnesses and the privacy edge each run under their own deployment. A
  // backend that could also see source connections would defeat sealed delivery.
  const separate = x => x.startsWith('Witness') || x === 'PrivacyEdge';
  return { ...config,
    vars: { ...config.vars, MORSE_ISOLATED_WITNESSES: '1', MORSE_ISOLATED_EDGE: '1', WITNESS_A_URL: a, WITNESS_B_URL: b },
    containers: config.containers.filter(x => !separate(x.class_name)),
    durable_objects: { bindings: config.durable_objects.bindings.filter(x => !x.name.startsWith('WITNESS') && x.name !== 'PRIVACY_EDGE') },
  };
}

export function edgeConfig(config, env) {
  return {
    name: 'morse-privacy-edge', main: 'isolated-edge.mjs',
    compatibility_date: config.compatibility_date, compatibility_flags: ['nodejs_compat'],
    workers_dev: true, preview_urls: false, observability: { enabled: false },
    vars: { MORSE_DELIVERY_URL: httpsOrigin(env.MORSE_DELIVERY_URL) },
    durable_objects: { bindings: [{ name: 'PRIVACY_EDGE', class_name: 'IsolatedPrivacyEdge' }] },
    migrations: [{ tag: 'v1', new_sqlite_classes: ['IsolatedPrivacyEdge'] }],
    containers: [{ ...config.containers.find(x => x.class_name === 'PrivacyEdge'), class_name: 'IsolatedPrivacyEdge' }],
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
  else if (mode) throw new Error('Unknown deployment mode');
  writeFileSync(new URL('./wrangler.build.json', import.meta.url), JSON.stringify(compilerConfig(config, revision), null, 2) + '\n');
  console.log(`Building all services with Mesh ${revision}`);
}
