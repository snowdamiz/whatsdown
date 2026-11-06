import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { publicRoute } from './routing.mjs';
import { edgeConfig, isolatedConfig } from './prepare-build.mjs';
import { edgeContainerEnv } from './edge.mjs';

const token = 'owned-ohttp-hop-credential-'.repeat(3);
const enabled = { MORSE_OHTTP: 'on', MORSE_ISOLATED_EDGE: '1' };
const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const isolation = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://broker.test' };
const gatewayPins = { MESSENGER_OHTTP_CORE_ORIGIN: 'https://core.test',
  MESSENGER_OHTTP_KEY_CONFIG_HEX: '00291100208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a000400010003' };
const request = (path = '/v1/ohttp', headers = {}, body = new Uint8Array(55).fill(7)) => new Request('https://edge.test' + path, {
  method: 'POST', body, headers: { 'content-type': 'message/ohttp-req', cookie: 'private',
    authorization: 'Bearer caller-must-drop', 'CF-Connecting-IP': '198.51.100.1', ...headers },
});
const ingress = (path = '/v1/ingress/ohttp', headers = {}) => new Request('https://core.test' + path, {
  method: 'POST', body: new Uint8Array(55).fill(7), headers: { 'content-type': 'message/ohttp-req', authorization: `Bearer ${token}`, ...headers },
});

test('OHTTP routing is explicit, isolated, exact and preserves the independent certificate gate', () => {
  assert.equal(publicRoute(ingress(), enabled), 'OHTTP_INGRESS');
  for (const env of [{}, { MORSE_OHTTP: 'on' }, { ...enabled, MORSE_OHTTP: 'off' }, { ...enabled, MORSE_OHTTP: 'ON' }]) {
    assert.equal(publicRoute(ingress(), env), null);
  }
  for (const path of ['/v1/ohttp', '/internal/v1/ohttp', '/v1/ingress/ohttp/', '/v1/ingress/%6fhttp', '/v1/ingress/ohttp?x=1', '/v1/ingress/ohttp#x']) {
    assert.equal(publicRoute(ingress(path), enabled), null, path);
  }
  assert.equal(publicRoute(new Request('https://core.test/v1/ingress/ohttp'), enabled), null);
  const fingerprint = 'ab'.repeat(32);
  const policy = { ...enabled, MORSE_SEALED_INGRESS_MTLS: 'required',
    MORSE_SEALED_INGRESS_ORIGIN: 'https://core.test', MORSE_EDGE_CLIENT_CERT_SHA256: fingerprint };
  assert.equal(publicRoute(ingress(undefined, { 'CF-Cert-Verified': 'SUCCESS', 'CF-Cert-Fingerprint-Sha256': fingerprint }), policy), null);
  const verified = ingress();
  Object.defineProperty(verified, 'cf', { value: { tlsClientAuth: { certPresented: '1', certVerified: 'SUCCESS', certRevoked: '0', certFingerprintSHA256: fingerprint } } });
  assert.equal(publicRoute(verified, policy), 'OHTTP_INGRESS');
});

test('deployment configuration preserves an explicit OHTTP switch without adding gateway secrets to the edge', () => {
  assert.equal(edgeConfig(original, { MORSE_DELIVERY_URL: 'https://core.test' }).vars.MORSE_OHTTP, undefined);
  for (const value of ['off', 'on']) {
    assert.equal(edgeConfig(original, { MORSE_DELIVERY_URL: 'https://core.test', MORSE_OHTTP: value }).vars.MORSE_OHTTP, value);
    assert.equal(isolatedConfig(original, { ...isolation, ...gatewayPins, MORSE_OHTTP: value }).vars.MORSE_OHTTP, value);
    const container = edgeContainerEnv({ MESSENGER_DELIVERY_INTERNAL_TOKEN: token, MORSE_OHTTP: value,
      MESSENGER_OHTTP_PRIVATE_KEY_HEX: 'must-not-reach-edge' });
    assert.equal(container.MORSE_OHTTP, value);
    assert.equal(container.MESSENGER_OHTTP_PRIVATE_KEY_HEX, undefined);
  }
  for (const value of ['', 'ON', true, ' on ']) {
    assert.throws(() => edgeConfig(original, { MORSE_DELIVERY_URL: 'https://core.test', MORSE_OHTTP: value }), /OHTTP/);
    assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_OHTTP: value }), /OHTTP/);
  }
});

// Exercise production Worker entrypoints and outbound dispatch. Only the host
// base classes and remote container/network endpoints are fixtures; this does
// not prove real TLS, Mesh decryption or deployed Cloudflare isolation.
const workers = (async () => {
  const output = await build({ stdin: { resolveDir: fileURLToPath(new URL('.', import.meta.url)), contents: `
    export { default as edge, IsolatedPrivacyEdge } from './isolated-edge.mjs';
    export { default as core, Directory } from './worker.mjs';
  ` }, bundle: true, write: false, platform: 'node', format: 'esm', conditions: ['workerd'],
  plugins: [{ name: 'owned-container-base', setup(builder) {
    builder.onResolve({ filter: /^(@cloudflare\/containers|cloudflare:workers)$/ }, args => ({ path: args.path, namespace: 'owned-host' }));
    builder.onLoad({ filter: /.*/, namespace: 'owned-host' }, () => ({ contents: `
      export class Container { constructor(ctx,env) { this.ctx=ctx; this.env=env; } }
      export class DurableObject extends Container {}
      export class ContainerProxy extends Container {}
      export const switchPort = value => value;
    `, loader: 'js' }));
  } }], });
  return import('data:text/javascript;base64,' + Buffer.from(output.outputFiles[0].text).toString('base64'));
})();

test('gateway pins and protected key slots reach only the configured core container', async () => {
  const { Directory } = await workers;
  const baseline = Object.fromEntries(['MESSENGER_DATABASE_URL','MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX',
    'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX','MESSENGER_WITNESS_B_PUBLIC_KEY_HEX','MESSENGER_DELIVERY_SEALING_SEED_HEX',
    'MESSENGER_DELIVERY_INTERNAL_TOKEN','MESSENGER_PUSH_BROKER_INTERNAL_TOKEN'].map(name => [name,'owned-fixture']));
  const configured = { ...baseline, ...gatewayPins, MORSE_OHTTP: 'on',
    MESSENGER_OHTTP_PRIVATE_KEY_0_HEX: '11'.repeat(32), MESSENGER_OHTTP_PRIVATE_KEY_1_HEX: '22'.repeat(32) };
  const values = new Directory({}, configured).envVars;
  for (const name of ['MORSE_OHTTP', ...Object.keys(gatewayPins), 'MESSENGER_OHTTP_PRIVATE_KEY_0_HEX', 'MESSENGER_OHTTP_PRIVATE_KEY_1_HEX']) {
    assert.equal(values[name], configured[name]);
  }
  for (const input of [baseline, { ...configured, MORSE_OHTTP: 'off' }]) {
    const off = new Directory({}, input).envVars;
    assert.equal(off.MORSE_OHTTP ?? 'off', 'off');
    for (const name of Object.keys(configured).filter(name => name.startsWith('MESSENGER_OHTTP_'))) assert.equal(off[name], undefined);
  }
  for (const name of ['MESSENGER_OHTTP_PRIVATE_KEY_0_HEX', 'MESSENGER_OHTTP_KEY_CONFIG_HEX', 'MESSENGER_OHTTP_CORE_ORIGIN']) {
    assert.throws(() => new Directory({}, { ...configured, [name]: '' }), /OHTTP/);
  }
  const deployed = isolatedConfig(original, { ...isolation, ...configured }).vars;
  for (const [name, value] of Object.entries(gatewayPins)) assert.equal(deployed[name], value);
  assert.equal(deployed.MESSENGER_OHTTP_PRIVATE_KEY_0_HEX, undefined);
  assert.equal(deployed.MESSENGER_OHTTP_PRIVATE_KEY_1_HEX, undefined);
  for (const value of ['', 'http://core.test', 'https://core.test/', 'https://core.test/path']) {
    assert.throws(() => isolatedConfig(original, { ...isolation, ...configured, MESSENGER_OHTTP_CORE_ORIGIN: value }), /OHTTP/);
  }
  const edge = edgeContainerEnv(configured);
  const edgeBuild = edgeConfig(original, { ...configured, MORSE_DELIVERY_URL: 'https://core.test' }).vars;
  for (const name of Object.keys(configured).filter(name => name.startsWith('MESSENGER_OHTTP_'))) {
    assert.equal(edge[name], undefined);
    assert.equal(edgeBuild[name], undefined);
  }
});

test('actual Worker dispatch carries only ciphertext and server-owned credentials over every OHTTP hop', async t => {
  const { edge, core, IsolatedPrivacyEdge } = await workers;
  const seen = [];
  const capture = async (where, value) => seen.push({ where, path: new URL(value.url).pathname,
    headers: Object.fromEntries(value.headers), body: [...new Uint8Array(await value.clone().arrayBuffer())] });
  const coreEnv = { ...enabled, DIRECTORY: { getByName() { return { async fetch(value) {
    await capture('directory', value);
    // The real Mesh adapter authenticates this credential independently.
    if (value.headers.get('authorization') !== `Bearer ${token}`) return new Response(null, { status: 401 });
    return new Response(new Uint8Array(48).fill(9), { headers: { 'content-type': 'message/ohttp-res', 'cache-control': 'no-store', 'set-cookie': 'must-drop', 'x-account': 'must-drop' } });
  } }; } } };
  t.mock.method(globalThis, 'fetch', async value => { await capture('network', value); return core.fetch(value, coreEnv); });
  const edgeEnv = { MORSE_OHTTP: 'on', MORSE_DELIVERY_URL: 'https://core.test', MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    PRIVACY_EDGE: { getByName() { return { async fetch(value) {
      await capture('edge-container', value);
      return IsolatedPrivacyEdge.outboundByHost['delivery.internal'](new Request('http://delivery.internal/internal/v1/ohttp', {
        method: 'POST', body: await value.arrayBuffer(), headers: { 'content-type': 'message/ohttp-req', authorization: 'Bearer container-must-not-select-credential', cookie: 'drop' },
      }), edgeEnv);
    } }; } } };
  const response = await edge.fetch(request(), edgeEnv);
  assert.equal(response.status, 200);
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], Array(48).fill(9));
  assert.deepEqual(Object.fromEntries(response.headers), { 'cache-control': 'no-store', 'content-type': 'message/ohttp-res' });
  assert.deepEqual(seen.map(x => [x.where, x.path]), [['edge-container', '/v1/ohttp'], ['network', '/v1/ingress/ohttp'], ['directory', '/internal/v1/ohttp']]);
  for (const [index, item] of seen.entries()) {
    assert.deepEqual(item.body, Array(55).fill(7));
    assert.deepEqual(item.headers, { accept: 'message/ohttp-res', 'cache-control': 'no-store', 'content-type': 'message/ohttp-req',
      ...(index ? { authorization: `Bearer ${token}` } : {}) });
  }
});

test('Worker refusal and failure paths return empty responses and never fall back to direct dispatch', async t => {
  const { edge, core, IsolatedPrivacyEdge } = await workers;
  let calls = 0;
  const binding = { getByName() { return { async fetch() { calls++; throw new Error('private gateway detail'); } }; } };
  for (const env of [{}, { MORSE_OHTTP: 'off' }, { MORSE_OHTTP: 'ON' }]) {
    const response = await edge.fetch(request(), { ...env, PRIVACY_EDGE: binding });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), '');
  }
  for (const [input, status] of [[request(undefined, { 'content-type': 'application/json' }), 415],
    [request(undefined, {}, new Uint8Array(54)), 400], [request('/v1/ohttp?target=x'), 404], [request(), 503]]) {
    const response = await edge.fetch(input, { MORSE_OHTTP: 'on', PRIVACY_EDGE: binding });
    assert.equal(response.status, status);
    assert.equal(await response.text(), '');
  }
  assert.equal(calls, 1, 'only admitted ciphertext reaches the edge container');
  calls = 0;
  for (const input of [ingress(undefined, { authorization: 'wrong' }), ingress(undefined, { 'content-encoding': 'gzip' })]) {
    const response = await core.fetch(input, { ...enabled, DIRECTORY: binding });
    assert.ok([401, 415].includes(response.status));
    assert.equal(await response.text(), '');
  }
  assert.equal(calls, 0);
  t.mock.method(globalThis, 'fetch', async () => { calls++; throw new Error('private network detail'); });
  const value = () => new Request('http://delivery.internal/internal/v1/ohttp', { method: 'POST', body: new Uint8Array(55), headers: { 'content-type': 'message/ohttp-req' } });
  const off = await IsolatedPrivacyEdge.outboundByHost['delivery.internal'](value(), { MORSE_OHTTP: 'off' });
  assert.equal(off.status, 404);
  assert.equal(calls, 0);
  const failed = await IsolatedPrivacyEdge.outboundByHost['delivery.internal'](value(), {
    MORSE_OHTTP: 'on', MORSE_DELIVERY_URL: 'https://core.test', MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
  });
  assert.equal(failed.status, 503);
  assert.equal(await failed.text(), '');
  assert.equal(calls, 1);
});
