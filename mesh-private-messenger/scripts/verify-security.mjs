import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { arch, platform, release } from 'node:os';

const root = fileURLToPath(new URL('../..', import.meta.url));
const mesh = join(root, 'mesh-lang');
const product = join(root, 'mesh-private-messenger');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (cwd, ...args) => {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(result.stderr);
  return result.stdout.trim();
};

export const describeTree = cwd => ({ commit: git(cwd, 'rev-parse', 'HEAD'), clean: git(cwd, 'status', '--porcelain') === '',
    diffSha256: hash(git(cwd, 'diff', '--binary', 'HEAD')),
    untracked: Object.fromEntries(git(cwd, 'ls-files', '--others', '--exclude-standard', '-z').split('\0').filter(Boolean).map(name => [name, hash(readFileSync(join(cwd, name)))])) });

export function unchangedSources(before, roots) {
  const after = Object.fromEntries(Object.entries(roots).map(([name, path]) => [name, describeTree(path)]));
  return { id: 'source-consistency', properties: ['C8'], status: JSON.stringify(before) === JSON.stringify(after) ? 'pass' : 'fail', after };
}

export function runCheck(directory, { id, properties, command, args, cwd = root, env = process.env, timeout = 1_800_000 }) {
  const start = Date.now();
  const result = spawnSync(command, args, { cwd, env, timeout, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  const output = (result.stdout ?? '') + (result.stderr ?? '') + (result.error?.message ?? '');
  writeFileSync(join(directory, `${id}.log`), output);
  return { id, properties, command: [command, ...args], cwd, status: result.status === 0 && !result.error ? 'pass' : 'fail',
    exitCode: result.status, signal: result.signal, durationMs: Date.now() - start, log: `${id}.log`, logSha256: hash(output) };
}

function main() {
  const extended = process.argv.includes('--extended');
  const directory = resolve(process.argv.slice(2).find(value => value !== '--extended') ?? join(root, '.security-evidence', new Date().toISOString().replaceAll(':', '-')));
  mkdirSync(directory, { recursive: true });
  const manifest = { schema: 1, startedAt: new Date().toISOString(), morse: describeTree(root), mesh: describeTree(mesh),
    host: { platform: platform(), os: release(), arch: arch(), node: process.version },
    campaign: { extended, groupSeeds: extended ? 1000 : 4, groupOperationsPerSeed: 198 },
    enabledSuites: [1, 2, 3], versions: { direct: 1, groupCommit: 2, groupMessage: 4, groupSnapshot: 2, groupTransport: 1 },
    locks: {}, artifacts: {}, tools: {}, results: [], releaseReady: false };
  for (const tool of ['rustc', 'cargo', 'clang', 'python3']) manifest.tools[tool] = spawnSync(tool, ['--version'], { encoding: 'utf8' }).stdout?.trim() ?? 'unavailable';
  for (const name of ['mesh-lang/target/debug/meshc', 'mesh-lang/target/debug/libmesh_rt.a', 'mesh-private-messenger/apps/desktop/src-tauri/native/libmessenger_mobile.dylib']) {
    const path = join(root, name);
    if (existsSync(path)) manifest.artifacts[name] = { sha256: hash(readFileSync(path)), note: 'Local artifact; signing and release provenance require separate evidence' };
  }
  for (const name of ['mesh-lang/Cargo.lock', 'mesh-private-messenger/apps/mobile/package-lock.json',
    'mesh-private-messenger/apps/desktop/package-lock.json', 'mesh-private-messenger/apps/desktop/src-tauri/Cargo.lock',
    'mesh-private-messenger/ops/cloudflare/package-lock.json']) manifest.locks[name] = hash(readFileSync(join(root, name)));
  const save = () => writeFileSync(join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  const compiler = process.env.MESHC ?? join(mesh, 'target/debug/meshc');
  const env = { ...process.env, MESHC: compiler, MESSENGER_CAMPAIGN_SEEDS: extended ? '1000' : '4',
    // RFC 7748 synthetic fixture; never a production key.
    MESSENGER_DELIVERY_SEALING_SEED_HEX: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a' };
  const checks = [
    ['protocol', ['C1', 'C2', 'C3', 'C4', 'C7'], compiler, ['test', join(product, 'packages/messenger-protocol/tests')]],
    ['mobile-core', ['C2', 'C4', 'C5', 'C7'], compiler, ['test', join(product, 'packages/mobile-core/tests')]],
    ['cli-interop', ['C1', 'C2'], compiler, ['test', join(product, 'tests/interoperability')]],
    ['model', ['C3', 'C4'], 'python3', [join(product, 'protocol/group-schedule-model.py')]],
    ['release-regressions', ['C3', 'C8'], process.execPath, ['--test', join(product, 'scripts/group-oracle.test.mjs'), join(product, 'scripts/privacy-leaks.test.mjs'), join(product, 'scripts/group-mutation.test.mjs'), join(product, 'scripts/direct-security.test.mjs'), join(product, 'scripts/release-verification.test.mjs'), join(product, 'scripts/verify-security.test.mjs')]],
    ['mobile', ['C1', 'C5', 'C7', 'C8'], 'npm', ['test', '--prefix', join(product, 'apps/mobile')]],
    ['mobile-types', ['C8'], 'npm', ['run', 'typecheck', '--prefix', join(product, 'apps/mobile')]],
    ['cloudflare', ['C1', 'C2', 'C5', 'C6', 'C7'], 'npm', ['test', '--prefix', join(product, 'ops/cloudflare')]],
    ['desktop', ['C1', 'C5', 'C7'], 'npm', ['test', '--prefix', join(product, 'apps/desktop')]],
  ];
  for (const [id, properties, command, args] of checks) {
    if (id === 'desktop' && !['darwin', 'win32'].includes(platform())) {
      manifest.results.push({ id, properties, status: 'not-run', reason: 'Desktop targets macOS and Windows' });
    } else if (id === 'cloudflare' && !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL) {
      manifest.results.push({ id, properties, status: 'not-run', reason: 'A disposable PostgreSQL test URL is required for the live lane' });
    } else {
      if (id === 'cloudflare') {
        const database = new URL(process.env.MESSENGER_STORAGE_TEST_DATABASE_URL);
        if (!['127.0.0.1', 'localhost'].includes(database.hostname) || !/test|security/.test(database.pathname)) throw new Error('Use a disposable local test database');
      }
      const result = runCheck(directory, { id, properties, command, args, env });
      manifest.results.push(result);
      console.log(`${id}: ${result.status} (${Math.round(result.durationMs / 1000)}s)`);
    }
    save();
  }
  // These are explicit evidence gaps, not successful substitutes or audit gates.
  for (const id of ['ios-device', 'android-device', 'macos-keystore-lifecycle', 'windows-keystore-lifecycle',
    'ota-native-rejection', 'windows-signing', 'full-crash-restore-matrix', 'extended-fuzz-and-mutations',
    'witness-permission-isolation', 'outbox-revocation-requeue', 'cross-epoch-queue-migration']) {
    manifest.results.push({ id, status: 'not-run', reason: 'Requires the remaining implementation/platform campaign in the security plan' });
  }
  manifest.results.push(unchangedSources({ morse: manifest.morse, mesh: manifest.mesh }, { morse: root, mesh }));
  manifest.finishedAt = new Date().toISOString();
  save();
  console.log(`Evidence: ${join(directory, 'manifest.json')}; full release acceptance remains incomplete.`);
  process.exitCode = manifest.results.some(result => result.status === 'fail') ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
