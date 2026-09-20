import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, copyFileSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { desktopConfig } from './config.mjs';

const root = fileURLToPath(new URL('../../../..', import.meta.url));
const native = fileURLToPath(new URL('../src-tauri/native/', import.meta.url));
const config = desktopConfig(process.env, process.argv.includes('--development'));
if (!['darwin', 'win32'].includes(process.platform)) throw new Error('Desktop native builds require macOS or Windows');
const extension = process.platform === 'win32' ? 'dll' : 'dylib';
const compiler = process.env.MESHC ?? join(root, 'mesh-lang', 'target', 'debug', process.platform === 'win32' ? 'meshc.exe' : 'meshc');
const minimumMacOS = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url))).bundle.macOS.minimumSystemVersion;
const env = process.platform === 'darwin' ? { ...process.env, MACOSX_DEPLOYMENT_TARGET: minimumMacOS } : process.env;
const temp = mkdtempSync(join(tmpdir(), 'morse-desktop-'));
try {
  const library = join(temp, `libmessenger_mobile.${extension}`);
  const result = spawnSync(resolve(compiler), ['build', join(root, 'mesh-private-messenger/packages/mobile-core'),
    '--artifact', 'cdylib', '--output', library], { stdio: 'inherit', env });
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
