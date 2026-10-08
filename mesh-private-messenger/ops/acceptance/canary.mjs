// Runs the canary device (canary-device/, a Mesh program on the real mobile
// core) with `meshc test` and reads the JSON lines it appends as it goes.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HELPER_DIR = fileURLToPath(new URL('./canary-device/', import.meta.url));
const INHERITED = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'USER'];

const parse = text => text.split('\n').filter(Boolean).flatMap(line => {
  try { return [JSON.parse(line)]; } catch { return []; }
});

// role: check | watch | create. The helper sees only its own settings, never
// the secrets other checks hold. {lines(), done, stop()}: done resolves with
// every line once the helper exits; stop() asks a watch to finish.
export function canaryProcess({ role, directory, frame, workdir, accounts, env = {}, meshc = 'meshc', command = [meshc, 'test', HELPER_DIR],
  timeoutMs = 30 * 60_000 }) {
  const tag = `${role}-${randomBytes(6).toString('hex')}`;
  const out = join(workdir, `canary-${tag}.jsonl`);
  const stopFile = join(workdir, `canary-${tag}.stop`);
  mkdirSync(workdir, { recursive: true });
  writeFileSync(out, '');
  const childEnv = Object.fromEntries(INHERITED.filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
  Object.assign(childEnv, {
    MORSE_CANARY_ROLE: role, MORSE_CANARY_DIRECTORY: directory, MORSE_CANARY_CONFIG: frame, MORSE_CANARY_OUT: out,
    MORSE_CANARY_WORKDIR: workdir, MORSE_CANARY_STOP: stopFile, ...(accounts ? { MORSE_CANARY_ACCOUNTS: accounts } : {}), ...env,
  });
  const child = spawn(command[0], command.slice(1), { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output = (output + chunk).slice(-4000); });
  child.stderr.on('data', chunk => { output = (output + chunk).slice(-4000); });
  const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
  const lines = () => existsSync(out) ? parse(readFileSync(out, 'utf8')) : [];
  const done = new Promise(resolve => {
    const finish = error => {
      clearTimeout(timer);
      const found = lines();
      resolve(found.length ? found : [{ kind: 'error', error: `${error ? error.message : 'the canary device wrote nothing'}: ${output.trim().slice(-600)}` }]);
    };
    child.on('error', finish);
    child.on('close', () => finish(null));
  });
  return { lines, done, stop: () => { writeFileSync(stopFile, ''); return done; } };
}
