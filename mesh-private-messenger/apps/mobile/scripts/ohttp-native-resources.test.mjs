import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { AndroidConfig, compileModsAsync, withAndroidManifest } = require('@expo/config-plugins');
const plugin = require('../plugins/with-mesh-push-config.cjs');
const iosKey = 'MeshMessengerOhttpConfig';
const androidKey = 'app.morse.mesh.OHTTP_CONFIG';
const network = {
  EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
  EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
  EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'https://objects.example',
  EXPO_PUBLIC_MESSENGER_STREAM_URL: 'wss://stream.example/v1/mailbox/stream',
};
const security = {
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: '22'.repeat(32),
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '33'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '44'.repeat(32),
  MESSENGER_ABUSE_DIFFICULTY: '8',
};
const key = { key_id: 37, public_key: '31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550', not_before_ms: '2000', not_after_ms: '18446744073709551615' };
const digest = value => createHash('sha256').update(value).digest('hex');
const json = keys => JSON.stringify({ schema_version: 1, mode: 'required', revision: '3', keys });
async function inspect(environment, seed = false) {
  let config = plugin({ name: 'Morse fixture', slug: 'morse-resource-fixture', ios: { bundleIdentifier: 'app.morse.resource.fixture', infoPlist: seed ? { [iosKey]: 'stale' } : {} }, android: { package: 'app.morse.resource.fixture' } }, environment);
  if (seed) config = withAndroidManifest(config, current => {
    AndroidConfig.Manifest.addMetaDataItemToMainApplication(AndroidConfig.Manifest.getMainApplicationOrThrow(current.modResults), androidKey, 'stale');
    return current;
  });
  return compileModsAsync(config, { projectRoot: resolve(dirname(fileURLToPath(import.meta.url)), '..'), introspect: true, platforms: ['ios', 'android'], ignoreExistingNativeFiles: true });
}
const android = config => AndroidConfig.Manifest.getMainApplicationMetaDataValue(config._internal.modResults.android.manifest, androidKey);

test('configured builds bundle explicit off bound to the exact existing native frames', async () => {
  const config = await inspect({ ...network, ...security });
  const fields = ['1', digest(config.ios.infoPlist.MeshMessengerNetworkConfig), digest(config.ios.infoPlist.MeshMessengerSecurityConfig), '1', 'off', '0'];
  const expected = fields.join('\n');
  assert.equal(config.ios.infoPlist[iosKey], expected);
  assert.equal(android(config), expected);
  assert.ok(Buffer.byteLength(expected) <= 600);
});

test('required release input reaches both native resources unchanged and retains overlap order', async () => {
  const second = { ...key, key_id: 255, public_key: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' };
  const config = await inspect({ ...network, ...security, MESSENGER_OHTTP_CONFIG: json([key, second]) });
  const encoded = entry => `${entry.not_before_ms} ${entry.not_after_ms} ${Buffer.from(entry.key_id.toString(16).padStart(2, '0') + '0020' + entry.public_key + '000400010003', 'hex').toString('base64')}`;
  const expected = ['1', digest(config.ios.infoPlist.MeshMessengerNetworkConfig), digest(config.ios.infoPlist.MeshMessengerSecurityConfig), '3', 'required', '2', encoded(key), encoded(second)].join('\n');
  assert.equal(config.ios.infoPlist[iosKey], expected);
  assert.equal(android(config), expected);
});

test('wholly unconfigured builds remove stale OHTTP resources; public JS inputs cannot configure them', async () => {
  const absent = await inspect({ EXPO_PUBLIC_MESSENGER_OHTTP_CONFIG: json([key]) }, true);
  assert.equal(Object.hasOwn(absent.ios.infoPlist, iosKey), false);
  assert.equal(android(absent), null);
  const off = await inspect({ ...network, ...security, EXPO_PUBLIC_MESSENGER_OHTTP_CONFIG: json([key]) });
  assert.equal(off.ios.infoPlist[iosKey].split('\n')[4], 'off');
});

test('partial parent configuration and explicit config without both parents fail closed', async () => {
  for (const environment of [network, security, { EAS_BUILD_PROFILE: 'development' }, { MESSENGER_OHTTP_CONFIG: json([key]) }]) {
    await assert.rejects(inspect(environment), /OHTTP/);
  }
});

test('invalid explicit OHTTP release inputs cannot be silently omitted from generated resources', async () => {
  for (const input of ['{', ' '.repeat(4097), json([key, key]), JSON.stringify({ schema_version: 1, mode: 'fallback', revision: '1', keys: [] })]) {
    await assert.rejects(inspect({ ...network, ...security, MESSENGER_OHTTP_CONFIG: input }));
  }
});
