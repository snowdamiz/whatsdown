import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// The library lives in Resources, so Tauri does not sign it as nested framework code.
// Hardened runtime requires it to carry the same Developer ID as the application.
if (process.platform === 'darwin' && process.env.APPLE_SIGNING_IDENTITY) {
  const library = fileURLToPath(new URL('../src-tauri/native/libmessenger_mobile.dylib', import.meta.url));
  const result = spawnSync('codesign', ['--force', '--timestamp', '--options', 'runtime',
    '--sign', process.env.APPLE_SIGNING_IDENTITY, library], { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Mesh library signing failed');
}
