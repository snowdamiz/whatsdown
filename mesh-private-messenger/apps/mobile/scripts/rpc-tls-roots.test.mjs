import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import securityConfig from '../plugins/security-config.cjs';

const require = createRequire(import.meta.url);
const directory = mkdtempSync(join(tmpdir(), 'morse-rpc-roots-'));
process.on('exit', () => rmSync(directory, { recursive: true, force: true }));
for (const [name, ca] of [['root', 'TRUE'], ['leaf', 'FALSE']]) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', join(directory, `${name}.key`), '-out', join(directory, `${name}.pem`), '-subj', `/CN=Local RPC ${name}`,
    '-days', '2', '-addext', `basicConstraints=critical,CA:${ca}`], { stdio: 'ignore' });
}
const pem = readFileSync(join(directory, 'root.pem'));
const origins = ['https://a.example:8443', 'https://b.example', 'https://c.example'];
const env = {
  MESSENGER_WITNESS_SET_JSON: JSON.stringify([{ id: 'outside', publicKey: '01'.repeat(32), operator: 'Outside' }]),
  MESSENGER_WITNESS_THRESHOLD: '1', MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '22'.repeat(32), MESSENGER_ABUSE_DIFFICULTY: '16',
  MESSENGER_ANCHOR_RING_ADDRESS: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(origins.map(origin => `${origin}/rpc?release=1`)),
  EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
  EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
};
const manifest = () => ({ version: 1, origins: origins.map((origin, index) => ({ origin, pemFile: index ? null : 'root.pem' })) });
const manifestFile = join(directory, 'roots.json');
function build(document = manifest(), overrides = {}) {
  writeFileSync(manifestFile, JSON.stringify(document));
  const buildEnv = { ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile, ...overrides };
  return require('../plugins/rpc-tls-roots.cjs')(buildEnv, securityConfig(buildEnv));
}
function rows(frame) {
  const result = [];
  let offset = 34;
  for (let index = 0; index < frame[1]; index++) {
    const originLength = frame.readUInt16BE(offset); offset += 2;
    const origin = frame.subarray(offset, offset + originLength).toString('ascii'); offset += originLength;
    const pemLength = frame.readUInt32BE(offset); offset += 4;
    result.push({ origin, pem: frame.subarray(offset, offset + pemLength) }); offset += pemLength;
  }
  assert.equal(offset, frame.length, 'resource has no trailing bytes');
  return result;
}

test('unset roots omit the resource; a set manifest binds complete sorted origins and explicit WebPKI', () => {
  const resource = require('../plugins/rpc-tls-roots.cjs');
  assert.equal(resource({}, undefined), null);
  const document = manifest(); document.origins.reverse();
  const wire = build(document);
  assert.deepEqual([...wire.subarray(0, 2)], [1, 3]);
  assert.deepEqual(wire.subarray(2, 34), createHash('sha256').update(securityConfig(env)).digest());
  assert.deepEqual(rows(wire), origins.map((origin, index) => ({ origin, pem: index ? Buffer.alloc(0) : pem })));
  assert.deepEqual(build(), wire, 'manifest row order does not change resource bytes');
  assert.ok(wire.length <= 82002);
  assert.ok(wire.toString('base64').length <= 109336);
});

test('every canonical security byte, including RPC path and suite floor, is bound', () => {
  const old = build();
  const pathChanged = build(manifest(), { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(origins.map(origin => `${origin}/different`)) });
  const floorChanged = build(manifest(), { MESSENGER_MINIMUM_SESSION_SUITE: '2' });
  for (const next of [pathChanged, floorChanged]) {
    assert.notDeepEqual(next.subarray(2, 34), old.subarray(2, 34));
    assert.deepEqual(rows(next), rows(old));
  }
  const resource = require('../plugins/rpc-tls-roots.cjs');
  assert.throws(() => resource({ ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile }, 'arbitrary pins'));
  assert.throws(() => build(manifest(), { MESSENGER_ANCHOR_RPC_URLS: '[]', MESSENGER_ANCHOR_RING_ADDRESS: '-' }));
});

test('manifest schema is exact and complete, with at least one explicit root', () => {
  for (const invalid of [null, [], {}, { ...manifest(), version: 2 }, { ...manifest(), extra: true },
    { version: 1, origins: manifest().origins.slice(1) }, { version: 1, origins: [] },
    { version: 1, origins: [...manifest().origins, manifest().origins[0]] },
    { version: 1, origins: manifest().origins.map(row => ({ ...row, pemFile: null })) },
    { version: 1, origins: manifest().origins.map(row => ({ origin: row.origin })) },
    { version: 1, origins: manifest().origins.map(row => ({ ...row, pemFile: '' })) },
    { version: 1, origins: manifest().origins.map(row => ({ ...row, unknown: true })) }]) {
    assert.throws(() => build(invalid), JSON.stringify(invalid));
  }
});

test('origin matching rejects lookalikes, noncanonical spelling, ports and URL syntax', () => {
  for (const origin of ['https://unknown.example', 'https://a.example', 'https://a.example:8444',
    'https://a.example:8443.evil.example', 'https://b.example:443', 'https://B.example',
    'https://b.example/', 'https://b.example?x=1', 'https://b.example#x', 'https://user@b.example',
    'https://b.example\\path', 'http://b.example', 'https://bücher.example', ' https://b.example',
    'https://b%2eexample', `https://${'b'.repeat(2048)}.example`]) {
    const document = manifest(); document.origins[1].origin = origin;
    assert.throws(() => build(document), origin);
  }
});

test('manifest and PEM files must be bounded regular readable files', () => {
  const resource = require('../plugins/rpc-tls-roots.cjs');
  for (const file of ['', join(directory, 'missing.json'), directory]) {
    assert.throws(() => resource({ ...env, MORSE_RPC_TLS_ROOTS_FILE: file }, securityConfig(env)));
  }
  for (const data of [Buffer.alloc(0), Buffer.from('{'), Buffer.alloc(65537, 32), Buffer.from([0xff])]) {
    writeFileSync(manifestFile, data);
    assert.throws(() => resource({ ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile }, securityConfig(env)));
  }
  writeFileSync(manifestFile, JSON.stringify(manifest())); chmodSync(manifestFile, 0);
  try {
    assert.throws(() => resource({ ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile }, securityConfig(env)));
  } finally { chmodSync(manifestFile, 0o600); }
  for (const file of ['missing.pem', '.', 'leaf.pem', 'root.key']) {
    const document = manifest(); document.origins[0].pemFile = file;
    assert.throws(() => build(document), file);
  }
  const unreadable = join(directory, 'unreadable.pem'); writeFileSync(unreadable, pem); chmodSync(unreadable, 0);
  try {
    const document = manifest(); document.origins[0].pemFile = 'unreadable.pem';
    assert.throws(() => build(document));
  } finally { chmodSync(unreadable, 0o600); }
});

test('all rows validate PEM CA contents, certificate count and the aggregate byte budget', () => {
  for (const data of [Buffer.alloc(0), Buffer.alloc(65537, 32), Buffer.from('not PEM'),
    Buffer.concat([pem, Buffer.from('trailing')]), Buffer.concat(Array(9).fill(pem)),
    Buffer.from(pem.toString().replace(/\n/, '\n!')), Buffer.concat([pem, Buffer.from([0xff])])]) {
    writeFileSync(join(directory, 'bad.pem'), data);
    const document = manifest(); document.origins[2].pemFile = 'bad.pem';
    assert.throws(() => build(document));
  }
  writeFileSync(join(directory, 'full.pem'), Buffer.concat([pem, Buffer.alloc(65536 - pem.length, 32)]));
  const document = manifest(); document.origins[0].pemFile = 'full.pem';
  assert.equal(rows(build(document))[0].pem.length, 65536, 'exact aggregate limit passes');
  document.origins[1].pemFile = 'root.pem';
  assert.throws(() => build(document), 'repeated bundles count towards aggregate');
});

test('eight configured origins are complete and manifest-relative PEM paths ignore cwd', () => {
  const all = Array.from({ length: 8 }, (_, index) => `https://rpc${index}.example`);
  const document = { version: 1, origins: all.map((origin, index) => ({ origin, pemFile: index ? null : 'root.pem' })) };
  assert.equal(build(document, { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(all) })[1], 8);
  document.origins.push({ origin: 'https://rpc8.example', pemFile: null });
  assert.throws(() => build(document, { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify([...all, 'https://rpc8.example']) }));
});

test('Android writes exact binary and removes stale resources only when roots are unset', () => {
  const resource = require('../plugins/rpc-tls-roots.cjs');
  const wire = build();
  const buildEnv = { ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile };
  const target = join(directory, 'android');
  const asset = join(target, 'app/src/main/assets/morse-rpc-tls-roots-v1.bin');
  resource.writeAndroid(target, buildEnv, securityConfig(buildEnv));
  assert.deepEqual(readFileSync(asset), wire);
  assert.throws(() => resource.writeAndroid(target, { ...buildEnv, MORSE_RPC_TLS_ROOTS_FILE: '' }, securityConfig(buildEnv)));
  assert.deepEqual(readFileSync(asset), wire, 'failed build never substitutes absence');
  resource.writeAndroid(target, env, securityConfig(env));
  assert.equal(existsSync(asset), false);
});

test('native plist and desktop config carry identical bytes, clear stale roots and avoid Expo extra', async () => {
  const resource = require('../plugins/rpc-tls-roots.cjs');
  const wire = build();
  const buildEnv = { ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile };
  const withMeshPushConfig = require('../plugins/with-mesh-push-config.cjs');
  const { compileModsAsync } = require('@expo/config-plugins');
  const { desktopConfig } = await import('../../desktop/scripts/config.mjs');
  const base = () => ({ name: 'Morse', slug: 'morse', extra: { marker: 'public' },
    ios: { bundleIdentifier: 'app.morse.test', infoPlist: { MeshMessengerRpcTLSRoots: 'stale' } },
    android: { package: 'app.morse.test' } });
  const options = { projectRoot: new URL('..', import.meta.url).pathname, introspect: true,
    platforms: ['ios', 'android'], ignoreExistingNativeFiles: true };
  const config = await compileModsAsync(withMeshPushConfig(base(), buildEnv), options);
  assert.equal(config.ios.infoPlist.MeshMessengerRpcTLSRoots, wire.toString('base64'));
  assert.equal(desktopConfig(buildEnv).rpcTlsRoots, wire.toString('base64'));
  assert.deepEqual(config.extra, { marker: 'public' });
  assert.equal(JSON.stringify(config.android).includes(wire.toString('base64')), false, 'Android roots live only in binary asset');
  const cleared = await compileModsAsync(withMeshPushConfig(base(), env), options);
  assert.equal(cleared.ios.infoPlist.MeshMessengerRpcTLSRoots, undefined);
  assert.equal(Object.hasOwn(desktopConfig(env), 'rpcTlsRoots'), false);
});

test('Expo public config evaluation exposes neither the build manifest path nor root bytes', () => {
  const wire = build();
  const project = mkdtempSync(join(directory, 'public-'));
  const buildEnv = { ...env, MORSE_RPC_TLS_ROOTS_FILE: manifestFile };
  const plugin = require.resolve('../plugins/with-mesh-push-config.cjs');
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'rpc-tls-public-proof', version: '1.0.0' }));
  writeFileSync(join(project, 'app.config.js'), `module.exports = () => require(${JSON.stringify(plugin)})({
    name: 'Morse', slug: 'morse', sdkVersion: '58.0.0', extra: { marker: 'public' },
    ios: { bundleIdentifier: 'app.morse.test' }, android: { package: 'app.morse.test' }
  }, ${JSON.stringify(buildEnv)});`);
  const { getConfig } = require('@expo/config');
  const publicConfig = getConfig(project, { isPublicConfig: true }).exp;
  assert.deepEqual(publicConfig.extra, { marker: 'public' });
  const serialized = JSON.stringify(publicConfig);
  for (const privateValue of [manifestFile, 'MORSE_RPC_TLS_ROOTS_FILE', 'MeshMessengerRpcTLSRoots', wire.toString('base64'), pem.toString()]) {
    assert.equal(serialized.includes(privateValue), false);
  }
});
