import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { desktopConfig } from '../../apps/desktop/scripts/config.mjs';

// Only public settings are exported. In particular, provisioning secrets and
// arbitrary MESSENGER_* variables must never make their way into this file.
const PIN_FIELDS = [
  'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX', 'MESSENGER_DELIVERY_PUBLIC_KEY_HEX',
  'MESSENGER_ABUSE_DIFFICULTY', 'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX', 'MESSENGER_WITNESS_SET_JSON',
  'MESSENGER_WITNESS_THRESHOLD', 'MESSENGER_ANCHOR_RING_ADDRESS',
  'MESSENGER_ANCHOR_RPC_URLS', 'MESSENGER_CREDIT_ISSUER_ORIGIN',
  'MESSENGER_TRANSPARENCY_LOG_VERSION', 'MESSENGER_LEGACY_WITNESS_SET_JSON',
  'MESSENGER_LEGACY_WITNESS_THRESHOLD',
  'MESSENGER_ANCHOR_PROGRAM_ADDRESS', 'MESSENGER_ANCHOR_LOG_NAME',
  'MESSENGER_RELAY_URLS', 'MESSENGER_SLASH_MINT_ADDRESS',
  'MESSENGER_MINIMUM_SESSION_SUITE',
];

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function clientEnvironment(environment) {
  const config = desktopConfig(environment);
  const values = {
    EXPO_PUBLIC_MESSENGER_BASE_URL: config.baseUrl,
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: config.edgeUrl,
    EXPO_PUBLIC_MESSENGER_STREAM_URL: config.streamUrl,
    EXPO_PUBLIC_MESSENGER_OBJECT_URL: config.objectUrl,
    MESSENGER_BASE_URL: config.baseUrl,
    MESSENGER_SECURITY_CONFIG: config.securityFrame,
  };
  for (const name of PIN_FIELDS) {
    if (environment[name] !== undefined) values[name] = environment[name];
  }
  return '# Generated public client configuration; contains no private keys.\n' +
    Object.entries(values).map(([name, value]) => `export ${name}=${shellQuote(value)}`).join('\n') + '\n';
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Validate everything before creating or replacing the output.
  const content = clientEnvironment(process.env);
  const path = resolve(process.argv[2] ?? fileURLToPath(new URL('../../../.morse/cloudflare/client.env', import.meta.url)));
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, { mode: 0o600 });
  console.log(`Wrote public client configuration to ${path}`);
}
