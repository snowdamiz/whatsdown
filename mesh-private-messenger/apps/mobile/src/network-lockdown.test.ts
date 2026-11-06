import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { installNetworkLockdown } from './network-lockdown.ts';

const networkConstructors = ['XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection'];

function realm() {
  const calls: string[] = [];
  const target: Record<string, any> = { navigator: { sendBeacon: () => { calls.push('beacon'); return true; } } };
  target.fetch = async () => { calls.push('fetch'); return 'sent'; };
  for (const name of networkConstructors) target[name] = function () { calls.push(name); };
  return { target, calls };
}

test('fetch rejects asynchronously and all direct JS transports fail without entering originals', async () => {
  const { target, calls } = realm();
  installNetworkLockdown(target);
  let result: Promise<unknown> | undefined;
  assert.doesNotThrow(() => { result = target.fetch('https://not-an-owned-service.invalid/private'); });
  await assert.rejects(result!, /^Error: native_network_required$/);
  for (const name of networkConstructors) assert.throws(() => new target[name]('secret'), /^Error: native_network_required$/, name);
  assert.throws(() => target.navigator.sendBeacon('secret', 'private'), /^Error: native_network_required$/);
  assert.deepEqual(calls, []);
});

test('network globals and RN/Expo backup names cannot be restored, deleted or redefined', async () => {
  const { target, calls } = realm();
  for (const name of ['originalfetch', 'originalFetch', ...networkConstructors.map(name => `original${name}`)]) {
    Object.defineProperty(target, name, { configurable: true, get() { calls.push(`get:${name}`); return target.fetch; } });
  }
  installNetworkLockdown(target);
  installNetworkLockdown(target);
  for (const name of ['fetch', ...networkConstructors, 'originalfetch', 'originalFetch', ...networkConstructors.map(name => `original${name}`)]) {
    assert.equal(Reflect.set(target, name, () => calls.push('restored')), false, name);
    assert.equal(Reflect.deleteProperty(target, name), false, name);
    assert.throws(() => Object.defineProperty(target, name, { value: () => calls.push('restored') }), TypeError, name);
  }
  await assert.rejects(target.originalfetch(), /native_network_required/);
  await assert.rejects(target.originalFetch(), /native_network_required/);
  assert.deepEqual(calls, [], 'Replacing lazy aliases must not evaluate getters that could restore the original globals');
});

test('unreplaceable network capabilities abort startup instead of silently retaining transport', () => {
  const { target, calls } = realm();
  Object.defineProperty(target, 'fetch', { value: target.fetch, configurable: false });
  assert.throws(() => installNetworkLockdown(target), /^Error: network_lockdown_failed$/);
  assert.deepEqual(calls, []);
});


const mobile = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(import.meta.url);
const babel = require('@babel/core');
const flow = require('@babel/plugin-transform-flow-strip-types');
const typescript = require('@babel/plugin-transform-typescript');
const commonjs = require('@babel/plugin-transform-modules-commonjs');

function loadModule(path: string, context: vm.Context, kind: 'flow' | 'ts', dependencies: Record<string, unknown> = {}) {
  const source = readFileSync(path, 'utf8');
  const code = babel.transformSync(source, { filename: path, babelrc: false, configFile: false,
    plugins: [kind === 'flow' ? flow : typescript, commonjs] }).code;
  const module = { exports: {} as Record<string, any> };
  const wrapper = vm.runInContext(`(function(require,module,exports){${code}\n})`, context);
  wrapper((name: string) => {
    if (!(name in dependencies)) throw Error(`Unexpected test dependency ${name}`);
    return dependencies[name];
  }, module, module.exports);
  return module.exports;
}

test('installed React Native and Expo lazy polyfills cannot reopen locked capabilities', async () => {
  const { target, calls } = realm();
  Object.assign(target, { __DEV__: true, console: { error() {} } });
  target.global = target;
  const context = vm.createContext(target);
  const lazy = loadModule(`${mobile}/node_modules/react-native/Libraries/Utilities/defineLazyObjectProperty.js`, context, 'flow');
  const rn = loadModule(`${mobile}/node_modules/react-native/Libraries/Utilities/PolyfillFunctions.js`, context, 'flow', { './defineLazyObjectProperty': lazy });
  const expo = loadModule(`${mobile}/node_modules/expo/src/winter/installGlobal.ts`, context, 'ts');
  const transport = () => { calls.push('restored'); };
  rn.polyfillGlobal('fetch', () => transport);
  rn.polyfillGlobal('XMLHttpRequest', () => transport);
  rn.polyfillGlobal('WebSocket', () => transport);
  expo.installGlobal('fetch', () => transport);
  installNetworkLockdown(target);
  rn.polyfillGlobal('fetch', () => transport);
  rn.polyfillGlobal('XMLHttpRequest', () => transport);
  expo.installGlobal('fetch', () => transport);
  await assert.rejects(target.fetch(), /native_network_required/);
  await assert.rejects(target.originalfetch(), /native_network_required/);
  await assert.rejects(target.originalFetch(), /native_network_required/);
  assert.throws(() => new target.XMLHttpRequest(), /native_network_required/);
  assert.deepEqual(calls, []);
});

