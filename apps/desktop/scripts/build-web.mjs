import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const config = JSON.parse(readFileSync(new URL('../src-tauri/native/config.json', import.meta.url), 'utf8'));
const mobile = fileURLToPath(new URL('../../mobile/', import.meta.url));
const cli = fileURLToPath(new URL('../../mobile/node_modules/expo/bin/cli', import.meta.url));
// Metro inlines build flags; cached development transforms must not reach a release.
const result = spawnSync(process.execPath, [cli, 'export', '--clear', '--platform', 'web', '--output-dir', '../desktop/dist'], {
  cwd: mobile, stdio: 'inherit',
  env: { ...process.env, EXPO_PUBLIC_DESKTOP_DEVELOPMENT: String(config.development), EXPO_PUBLIC_MESSENGER_BASE_URL: config.baseUrl,
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: config.edgeUrl, EXPO_PUBLIC_MESSENGER_STREAM_URL: config.streamUrl,
    EXPO_PUBLIC_MESSENGER_OBJECT_URL: config.objectUrl },
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
