import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { createFingerprintAsync } from '@expo/fingerprint';

const require = createRequire(import.meta.url);

test('a fresh checkout links the personal EAS project and authenticates OTA updates', async () => {
  const { spawnSync } = await import('node:child_process');
  const result = spawnSync(process.execPath, ['--input-type=module', '-e',
    "import config from './app.config.js'; console.log(JSON.stringify(config.expo))"], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8',
    env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !['EXPO_PROJECT_ID', 'MORSE_OTA_CERTIFICATE'].includes(name))),
  });
  assert.equal(result.status, 0, result.stderr);
  const config = JSON.parse(result.stdout);
  assert.equal(config.owner, '120356aa-user');
  assert.equal(config.extra.eas.projectId, 'f41ebb5b-47f4-4c55-8f02-aab6bfeb96a8');
  assert.equal(config.updates.url, `https://u.expo.dev/${config.extra.eas.projectId}`);
  assert.equal(config.updates.enabled, true);
  const { X509Certificate } = await import('node:crypto');
  const { readFileSync } = await import('node:fs');
  const certificate = new X509Certificate(readFileSync(new URL(`../${config.updates.codeSigningCertificate}`, import.meta.url)));
  assert.equal(certificate.publicKey.asymmetricKeyType, 'rsa');
  assert.ok(Date.parse(certificate.validTo) > Date.now());
});

test('OTA compatibility follows native sources, toolchain and pins, not JS or archives', async () => {
  const previousKey = process.env.MESSENGER_DELIVERY_PUBLIC_KEY_HEX;
  const previousMesh = process.env.MESH_LANG_REVISION;
  // The Mesh commit comes from the build environment: a release passes the
  // one its verification used, so it is a pin like the service keys.
  process.env.MESH_LANG_REVISION = '1'.repeat(40);
  let config = require('../fingerprint.config.cjs');
  const root = mkdtempSync(path.join(tmpdir(), 'morse-runtime-'));
  const app = path.join(root, 'mesh-private-messenger/apps/mobile');
  const core = path.join(root, 'mesh-private-messenger/packages/mobile-core');
  try {
    mkdirSync(app, { recursive: true });
    mkdirSync(core, { recursive: true });
    mkdirSync(path.join(root, 'mesh-private-messenger/packages/messenger-protocol'), { recursive: true });
    mkdirSync(path.join(root, 'mesh-private-messenger/scripts'), { recursive: true });
    writeFileSync(path.join(root, 'mesh-private-messenger/scripts/eas-build-native.sh'), 'compiler v1');
    writeFileSync(path.join(root, 'mesh-private-messenger/scripts/build-mobile-native.sh'), 'builder v1');
    mkdirSync(path.join(app, 'modules/mesh-messenger'), { recursive: true });
    writeFileSync(path.join(app, 'package.json'), '{"name":"runtime-test"}');
    writeFileSync(path.join(core, 'main.mpl'), 'native v1');
    writeFileSync(path.join(app, 'modules/mesh-messenger/module.swift'), 'bridge v1');
    const fingerprint = () => createFingerprintAsync(app, {
      ...config, platforms: [], useRNCoreAutolinkingFromExpo: true, silent: true,
    });
    const original = await fingerprint();
    writeFileSync(path.join(app, 'App.tsx'), 'UI v2');
    mkdirSync(path.join(app, 'modules/mesh-messenger/native/ios'), { recursive: true });
    writeFileSync(path.join(app, 'modules/mesh-messenger/native/ios/library.a'), 'build output');
    assert.equal((await fingerprint()).hash, original.hash);
    writeFileSync(path.join(core, 'main.mpl'), 'native v2');
    assert.notEqual((await fingerprint()).hash, original.hash);
    writeFileSync(path.join(core, 'main.mpl'), 'native v1');
    writeFileSync(path.join(app, 'modules/mesh-messenger/module.swift'), 'bridge v2');
    assert.notEqual((await fingerprint()).hash, original.hash);
    writeFileSync(path.join(app, 'modules/mesh-messenger/module.swift'), 'bridge v1');
    writeFileSync(path.join(root, 'mesh-private-messenger/scripts/eas-build-native.sh'), 'compiler v2');
    assert.notEqual((await fingerprint()).hash, original.hash);
    writeFileSync(path.join(root, 'mesh-private-messenger/scripts/eas-build-native.sh'), 'compiler v1');
    for (const [name, value] of [['MESH_LANG_REVISION', '2'.repeat(40)], ['MESSENGER_DELIVERY_PUBLIC_KEY_HEX', 'ab'.repeat(32)]]) {
      process.env[name] = value;
      delete require.cache[require.resolve('../fingerprint.config.cjs')];
      config = require('../fingerprint.config.cjs');
      assert.notEqual((await fingerprint()).hash, original.hash, name);
    }
  } finally {
    if (previousKey === undefined) delete process.env.MESSENGER_DELIVERY_PUBLIC_KEY_HEX;
    else process.env.MESSENGER_DELIVERY_PUBLIC_KEY_HEX = previousKey;
    if (previousMesh === undefined) delete process.env.MESH_LANG_REVISION;
    else process.env.MESH_LANG_REVISION = previousMesh;
    delete require.cache[require.resolve('../fingerprint.config.cjs')];
    rmSync(root, { recursive: true, force: true });
  }
});
