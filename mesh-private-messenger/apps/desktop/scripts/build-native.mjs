import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, copyFileSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { desktopConfig } from './config.mjs';
import securityConfig from '../../mobile/plugins/security-config.cjs';

const root = fileURLToPath(new URL('../../../..', import.meta.url));
const native = fileURLToPath(new URL('../src-tauri/native/', import.meta.url));
const config = desktopConfig(process.env, process.argv.includes('--development'));
if (config.securityFrame) {
  const { setId, profile, k, n } = securityConfig.witnessSet(config.securityFrame);
  console.log(`Witness set_id ${setId}, ${profile}, ${k} of ${n}.`);
}
if (!['darwin', 'win32'].includes(process.platform)) throw new Error('Desktop native builds require macOS or Windows');
const extension = process.platform === 'win32' ? 'dll' : 'dylib';
const compiler = process.env.MESHC ?? join(root, 'mesh-lang', 'target', 'debug', process.platform === 'win32' ? 'meshc.exe' : 'meshc');
const minimumMacOS = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url))).bundle.macOS.minimumSystemVersion;
const env = process.platform === 'darwin' ? { ...process.env, MACOSX_DEPLOYMENT_TARGET: minimumMacOS } : process.env;
// --release builds the Mesh runtime in release and links it at -O2. Without it meshc links
// the runtime of its own profile (debug for a debug compiler) at -O0: crypto about ten times slower.
const release = process.argv.includes('--release');
if (release) {
  const cargo = spawnSync('cargo', ['build', '--locked', '--release', '-p', 'mesh-rt', '--lib',
    '--manifest-path', join(root, 'mesh-lang', 'Cargo.toml')], { stdio: 'inherit', env });
  if (cargo.error) throw cargo.error;
  if (cargo.status !== 0) throw new Error(`Mesh runtime build failed (${cargo.status})`);
}
const runtime = join(resolve(process.env.CARGO_TARGET_DIR ?? join(root, 'mesh-lang', 'target')), 'release',
  process.platform === 'win32' ? 'mesh_rt.lib' : 'libmesh_rt.a');
const temp = mkdtempSync(join(tmpdir(), 'morse-desktop-'));
try {
  const library = join(temp, `libmessenger_mobile.${extension}`);
  const result = spawnSync(resolve(compiler), ['build', join(root, 'mesh-private-messenger/packages/mobile-core'),
    '--artifact', 'cdylib', ...(release ? ['--opt-level', '2'] : []), '--output', library],
    { stdio: 'inherit', env: release ? { ...env, MESH_RT_LIB_PATH: runtime } : env });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Mesh native build failed (${result.status})`);
  if (process.platform === 'darwin') {
    const version = spawnSync('otool', ['-l', library], { encoding: 'utf8' });
    if (version.status !== 0 || !version.stdout.split('\n').some(line => line.trim() === `minos ${minimumMacOS}`)) {
      throw new Error(`Mesh library must target macOS ${minimumMacOS}, matching the app`);
    }
  }
  mkdirSync(native, { recursive: true });
  copyFileSync(library, join(native, `libmessenger_mobile.${extension}`));
  writeFileSync(join(native, 'config.json'), JSON.stringify(config, null, 2) + '\n');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
