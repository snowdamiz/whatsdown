import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, createReadStream, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function validateEnvironment(env) {
  if (!/^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$/.test(env.MORSE_SERVICES_IMAGE ?? '')) throw new Error('Services image must be pinned by digest');
  for (const field of ['MORSE_REVISION', 'MESH_LANG_REVISION']) {
    if (!/^[a-f0-9]{40}$/.test(env[field] ?? '')) throw new Error(`${field} must be a full commit SHA`);
  }
  if (!/^(0|[1-9][0-9]{0,11})$/.test(env.SOURCE_DATE_EPOCH ?? '')) throw new Error('SOURCE_DATE_EPOCH must be an explicit Unix timestamp');
}
export function packageArguments(env, outputDirectory) {
  validateEnvironment(env);
  if (/[\r\n,]/.test(outputDirectory)) throw new Error('Invalid output path');
  return ['buildx', 'build', '--platform', 'linux/amd64', '--provenance=false', '--sbom=false',
    ...['MORSE_SERVICES_IMAGE', 'MORSE_REVISION', 'MESH_LANG_REVISION', 'SOURCE_DATE_EPOCH'].flatMap(field => ['--build-arg', `${field}=${env[field]}`]),
    '--file', fileURLToPath(new URL('./Dockerfile', import.meta.url)),
    '--output', `type=oci,dest=${join(outputDirectory, 'witness.oci.tar')},rewrite-timestamp=true`,
    fileURLToPath(new URL('.', import.meta.url))];
}
export function relayArchiveArguments(env) {
  validateEnvironment(env);
  return ['run', '--rm', '--platform', 'linux/amd64', '--read-only', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
    '--user=65532:65532', '--entrypoint', '/bin/tar', env.MORSE_SERVICES_IMAGE,
    '--format=ustar', '--sort=name', '--owner=0', '--group=0', '--numeric-owner',
    `--mtime=@${env.SOURCE_DATE_EPOCH}`, '-C', '/app', '-cf', '-', 'morse-relay', 'morse-fork-verifier'];
}
export function verifyImageRevisions(labels, env) {
  if (labels?.['org.opencontainers.image.revision'] !== env.MORSE_REVISION ||
      labels?.['org.morse.mesh-revision'] !== env.MESH_LANG_REVISION) throw new Error('Services image does not match the verified Morse and Mesh revisions');
}
export function verifyServicesImage(env, run = execFileSync) {
  validateEnvironment(env);
  const labels = JSON.parse(run('docker', ['image', 'inspect', '--platform', 'linux/amd64',
    '--format', '{{json .Config.Labels}}', env.MORSE_SERVICES_IMAGE], { encoding: 'utf8' }));
  verifyImageRevisions(labels, env);
}
async function digest(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const env = process.env;
  const directory = resolve(process.argv[2] ?? '.morse/witness-package');
  const args = packageArguments(env, directory);
  if (existsSync(directory) && readdirSync(directory).length) throw new Error('Use an empty output directory');
  execFileSync('docker', ['pull', '--platform', 'linux/amd64', env.MORSE_SERVICES_IMAGE], { stdio: 'inherit' });
  verifyServicesImage(env);
  mkdirSync(directory, { recursive: true });
  const buildx = execFileSync('docker', ['buildx', 'version'], { encoding: 'utf8' }).trim();
  execFileSync('docker', args, { stdio: 'inherit' });
  // Extract reviewed bytes from the already verified image, never from an
  // unrelated local checkout. The container runs only tar, with no network or
  // wallet mount. A missing relay payload fails packaging before checksums.
  const archive = openSync(join(directory, 'relay.tar'), 'wx', 0o644);
  try {
    execFileSync('docker', relayArchiveArguments(env), { stdio: ['ignore', archive, 'inherit'] });
    fsyncSync(archive);
  } finally { closeSync(archive); }
  writeFileSync(join(directory, 'inputs.json'), JSON.stringify({ services_image: env.MORSE_SERVICES_IMAGE,
    morse_revision: env.MORSE_REVISION, mesh_revision: env.MESH_LANG_REVISION,
    source_date_epoch: env.SOURCE_DATE_EPOCH, buildx }, null, 2) + '\n', { flag: 'wx' });
  const sums = await Promise.all(['witness.oci.tar', 'relay.tar', 'inputs.json'].map(async name => `${await digest(join(directory, name))}  ${name}`));
  writeFileSync(join(directory, 'SHA256SUMS'), sums.join('\n') + '\n', { flag: 'wx' });
  console.log(`Witness package written to ${directory}`);
}
