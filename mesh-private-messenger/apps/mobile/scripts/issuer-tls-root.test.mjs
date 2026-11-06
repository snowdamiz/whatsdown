import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
const require = createRequire(import.meta.url);
const directory = mkdtempSync(join(tmpdir(), 'morse-issuer-roots-'));
process.on('exit', () => rmSync(directory, { recursive: true, force: true }));
execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
  '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'root.pem'), '-subj', '/CN=Morse local test CA',
  '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' });
const path = join(directory, 'root.pem');
const pem = readFileSync(path);
const origin = 'https://issuer.example:8443';
const env = { MESSENGER_CREDIT_ISSUER_ORIGIN: origin, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: path };
test('issuer TLS resource is explicit, exact-origin and build-only', () => {
  const resource = require('../plugins/issuer-tls-root.cjs');
  assert.equal(resource({}), null);
  const wire = resource(env);
  assert.equal(wire[0], 1);
  assert.equal(wire.readUInt16BE(1), origin.length);
  assert.equal(wire.subarray(3, 3 + origin.length).toString(), origin);
  assert.equal(wire.readUInt32BE(3 + origin.length), pem.length);
  assert.deepEqual(wire.subarray(7 + origin.length), pem);
  for (const invalid of [undefined, '-', 'http://localhost:8443', `${origin}/`, 'https://ISSUER.example',
    'https://user@issuer.example', `${origin}?x=1`, 'https://issuer.example:443']) {
    assert.throws(() => resource({ ...env, MESSENGER_CREDIT_ISSUER_ORIGIN: invalid }));
  }
  assert.throws(() => resource({ ...env, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: join(directory, 'missing') }));
  for (const data of [Buffer.alloc(0), Buffer.alloc(65537, 32), Buffer.from('not PEM'),
    readFileSync(join(directory, 'key.pem')), Buffer.concat([pem, Buffer.from('trailing')]),
    Buffer.concat(Array(9).fill(pem))]) {
    const bad = join(directory, 'bad.pem'); writeFileSync(bad, data);
    assert.throws(() => resource({ ...env, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: bad }));
  }
  const eight = join(directory, 'eight.pem'); writeFileSync(eight, Buffer.concat(Array(8).fill(pem)));
  assert.ok(resource({ ...env, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: eight }));
});
test('Android asset writer removes stale roots when unconfigured and bounds exact bytes', () => {
  const resource = require('../plugins/issuer-tls-root.cjs');
  const target = join(directory, 'android');
  resource.writeAndroid(target, env);
  assert.deepEqual(readFileSync(join(target, 'app/src/main/assets/morse-issuer-tls-root-v1.bin')), resource(env));
  resource.writeAndroid(target, {});
  assert.throws(() => readFileSync(join(target, 'app/src/main/assets/morse-issuer-tls-root-v1.bin')));
});
test('signed mobile plist and desktop JSON carry the identical resource; no public selector is added', async () => {
  const resource = require('../plugins/issuer-tls-root.cjs');
  const withMeshPushConfig = require('../plugins/with-mesh-push-config.cjs');
  const { compileModsAsync } = require('@expo/config-plugins');
  const { desktopConfig } = await import('../../desktop/scripts/config.mjs');
  const pins = JSON.stringify([{ id: 'outside', publicKey: '01'.repeat(32), operator: 'Outside' }]);
  const build = { ...env, MESSENGER_WITNESS_SET_JSON: pins, MESSENGER_WITNESS_THRESHOLD: '1',
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32), MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '22'.repeat(32),
    MESSENGER_ABUSE_DIFFICULTY: '16', EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example' };
  const base = { name: 'Morse', slug: 'morse', ios: { bundleIdentifier: 'app.morse.test' }, android: { package: 'app.morse.test' } };
  const config = await compileModsAsync(withMeshPushConfig(base, build), {
    projectRoot: new URL('..', import.meta.url).pathname, introspect: true, platforms: ['ios', 'android'], ignoreExistingNativeFiles: true,
  });
  assert.equal(config.ios.infoPlist.MeshMessengerIssuerTLSRoot, resource(build).toString('base64'));
  assert.equal(desktopConfig(build).issuerTlsRoot, config.ios.infoPlist.MeshMessengerIssuerTLSRoot);
  const absent = desktopConfig({ ...build, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: undefined });
  assert.equal(absent.issuerTlsRoot, '');
  const withoutRoot = { ...build, MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE: undefined };
  const stale = { name: 'Morse', slug: 'morse', ios: { bundleIdentifier: 'app.morse.test', infoPlist: { MeshMessengerIssuerTLSRoot: 'stale-native-root' } }, android: { package: 'app.morse.test' } };
  const cleared = await compileModsAsync(withMeshPushConfig(stale, withoutRoot), {
    projectRoot: new URL('..', import.meta.url).pathname, introspect: true, platforms: ['ios', 'android'], ignoreExistingNativeFiles: true,
  });
  assert.equal(cleared.ios.infoPlist.MeshMessengerIssuerTLSRoot, undefined);
});
