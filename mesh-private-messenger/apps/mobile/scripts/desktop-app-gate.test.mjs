import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import test from 'node:test';
const require = createRequire(import.meta.url);
const React = require('react'), { create, act } = require('react-test-renderer'), ts = require('typescript');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const generated = readFileSync(new URL('../modules/mesh-messenger/generated/libmessenger_mobile.ts', import.meta.url), 'utf8');
const names = [...generated.matchAll(/^export const (\w+) =/gm)].map(row => row[1]);
const native = 'export const isLegacyDesktopBridge=false;' + [...names, 'invokeWallet', 'openNativeCreditPayment', 'primePushToken', 'clearPushToken', 'onPushRegistrationChanged'].map(name => `export const ${name}=()=>{throw Error("global_native_called")};`).join('');
registerHooks({ load(url, context, next) {
  if (url.startsWith('file:') && /\.tsx?$/.test(url)) return { shortCircuit: true, format: 'module', source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), { fileName: new URL(url).pathname, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText };
  return next(url, context);
}, resolve(specifier, context, next) {
  const sources = {
    '../modules/mesh-messenger': native,
    './storage': 'export const databasePath="/legacy/database";',
    'expo-file-system': 'export class File {constructor(){throw Error("global_file_called")}};export const Paths={};',
    'expo-notifications': 'export const setNotificationHandler=()=>{throw Error("global_notifications_called")};',
    'react-native': 'export const Platform={OS:"web"};',
    'expo-image-picker': 'export const launchImageLibraryAsync=()=>{throw Error("global_picker_called")};',
    'expo-image-manipulator': 'export const ImageManipulator={};export const SaveFormat={JPEG:"jpeg"};',
  };
  if (sources[specifier] !== undefined) return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(sources[specifier]) };
  if ((specifier.startsWith('./') || specifier.startsWith('../')) && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    for (const extension of ['.web.ts', '.web.tsx', '.ts', '.tsx']) { const candidate = new URL(specifier + extension, context.parentURL); if (existsSync(candidate)) return next(candidate.href, context); }
  }
  return next(specifier, context);
} });
const { DesktopAppGate } = await import('../src/DesktopAppGate.tsx');
const tick = () => new Promise(resolve => setImmediate(resolve));
const owner = '00000000-0000-4000-8000-000000000001';
async function fixture(t, options = {}) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const calls = [], received = [], order = [], registrations = [], outstanding = [];
  let deliver = () => {}, renderer, active = true, publicCommits = 0;
  const state = { generation: 1, revision: 1, phase: options.phase ?? 'disabled', policy: 'disabled', foreground: true,
    renderError: false, async activate() {}, async remove() {} };
  const snapshot = () => ({ version: 1, owner, revision: String(state.revision), state: { epoch: owner + '/' + state.generation, phase: state.phase, policy: state.policy, capability: 'available', foreground: state.foreground } });
  function emit(changes) { Object.assign(state, changes); state.revision++; deliver(snapshot()); }
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __MORSE_DOCUMENT__: '00000000-0000-4000-8000-000000000001', __TAURI_INTERNALS__: { transformCallback() { return 1; }, async invoke(name, body, options) {
      calls.push({ name, body, options });
      if (name === 'plugin:event|listen') return registrations.shift() ?? 42;
      if (name === 'plugin:event|unlisten') { await state.remove(); order.push('unlisten'); return; }
      if (name === 'database_path') return '/captured/db';
      if (name === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
      if (name === 'app_lock_file_cleanup') return null;
      throw Error('unexpected_' + name);
    } }, __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener() {} },
  } });
  const transport = {
    async listen(callback) { deliver = callback; return () => { deliver = () => {}; }; },
    async command(name, body, headers) {
      calls.push({ name, body, headers });
      if (name === 'app_lock_bind' || name === 'app_lock_state') return snapshot();
      if (name === 'app_lock_activate') {
        order.push('activate:' + publicCommits);
        await state.activate(); emit({ phase: 'activated' }); return null;
      }
      if (name === 'app_lock_release') { order.push('release'); return null; }
      throw Error('unexpected_' + name);
    },
    privatePort(_owner, epoch) { return {
      async check() { if (epoch !== snapshot().state.epoch || state.phase !== 'activated') throw Error('stale_epoch'); },
      async invoke(symbol) { calls.push({ name: symbol, epoch }); return Uint8Array.of(state.generation); },
      async invokeWallet() { return new Uint8Array(); }, async copyProtectedText() {},
    }; },
  };
  function PublicShell() { React.useLayoutEffect(() => { publicCommits++; order.push('public:' + publicCommits); }, []); return React.createElement('public-shell'); }
  function PrivateApp({ services }) { if (state.renderError) throw Error('private_render_failed'); React.useLayoutEffect(() => { received.push(services); }, [services]); return React.createElement('private-app', { services }); }
  function element(key = 'one', selectedTransport = transport) { return React.createElement(DesktopAppGate, { key, transport: selectedTransport, pending: React.createElement(PublicShell), failed: React.createElement('failure') }, services => React.createElement(PrivateApp, { services })); }
  async function mount() { await act(async () => { renderer = create(element()); await tick(); }); await act(async () => { await tick(); }); }
  async function unmount() { if (active && renderer) { active = false; await act(async () => { renderer.unmount(); await tick(); }); } }
  t.after(async () => { for (const pending of outstanding) pending.resolve(); await unmount(); await tick(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { state, calls, received, order, registrations, outstanding, transport, emit, mount, unmount, element,
    privateCount: () => renderer.root.findAllByType('private-app').length,
    publicCount: () => renderer.root.findAllByType('public-shell').length,
    replaceTransport: async next => { await act(async () => { renderer.update(element('one', next)); await tick(); }); },
    update: async key => { await act(async () => { renderer.update(element(key)); await tick(); }); await act(async () => { await tick(); }); },
  };
}
test('the public shell commits before native activation and only scoped app services reach the child', async t => {
  const f = await fixture(t); await f.mount();
  assert.equal(f.privateCount(), 1); assert.equal(f.received.length, 1);
  assert.ok(f.order.indexOf('public:1') < f.order.indexOf('activate:1'));
  assert.equal(f.received[0].databasePath, '/captured/db');
  assert.deepEqual(await f.received[0].load_profile_export(Uint8Array.of(1)), Uint8Array.of(1));
});
test('native relock removes the private React tree and refuses its captured services', async t => {
  const f = await fixture(t); await f.mount(); const old = f.received[0];
  await act(async () => { f.emit({ phase: 'locked', generation: 2 }); await tick(); });
  assert.equal(f.privateCount(), 0); assert.equal(f.publicCount(), 1);
  await assert.rejects(old.load_profile_export(Uint8Array.of(1)), /stale_epoch/);
});
test('rapid relock and authorization commit a new public shell before uncovering a fresh tree', async t => {
  const f = await fixture(t); await f.mount(); const old = f.received[0];
  await act(async () => { f.emit({ phase: 'locked', generation: 2 }); f.emit({ phase: 'awaiting_activation', generation: 3 }); await tick(); });
  await act(async () => { await tick(); });
  assert.equal(f.privateCount(), 1); assert.equal(f.received.length, 2);
  assert.deepEqual(f.order.filter(value => value.startsWith('activate:')), ['activate:1', 'activate:2']);
  await assert.rejects(old.load_profile_export(Uint8Array.of(1)), /stale_epoch/);
  assert.deepEqual(await f.received[1].load_profile_export(Uint8Array.of(1)), Uint8Array.of(3));
});
test('an active-state observation does not reconstruct the same private service tree', async t => {
  const f = await fixture(t); await f.mount();
  await act(async () => { f.emit({ foreground: true }); await tick(); });
  assert.equal(f.received.length, 1); assert.equal(f.calls.filter(call => call.name === 'database_path').length, 1);
});
test('unmount retires services immediately but releases the native owner after async event cleanup', async t => {
  const f = await fixture(t); await f.mount(); const old = f.received[0], removal = Promise.withResolvers();
  f.outstanding.push(removal); f.state.remove = () => removal.promise;
  await f.unmount();
  try { await assert.rejects(old.load_profile_export(Uint8Array.of(1)), /stale_epoch/); assert.equal(f.order.includes('release'), false); }
  finally { removal.resolve(); await tick(); }
  assert.equal(f.order.at(-1), 'release');
});
test('failed activation retries only on a fresh native observation', async t => {
  const f = await fixture(t); let attempts = 0;
  f.state.activate = async () => { if (++attempts === 1) throw Error('inactive'); };
  await f.mount(); assert.equal(attempts, 1); assert.equal(f.privateCount(), 0);
  await act(async () => { f.emit({ foreground: true }); await tick(); }); await act(async () => { await tick(); });
  assert.equal(attempts, 2); assert.equal(f.privateCount(), 1);
});

test('a new transport cannot render the previous native owner while its binding is pending', async t => {
  const f = await fixture(t); await f.mount(); const wait = Promise.withResolvers(); f.outstanding.push(wait);
  const next = { ...f.transport, async command(name, ...args) { if (name === 'app_lock_bind') await wait.promise; return f.transport.command(name, ...args); } };
  await f.replaceTransport(next);
  try { assert.equal(f.privateCount(), 0); assert.equal(f.publicCount(), 1); }
  finally { await act(async () => { wait.resolve(); await tick(); }); }
});
test('a private render failure retires the native owner and removes the private React tree', async t => {
  const f = await fixture(t); await f.mount(); f.state.renderError = true;
  await f.update('one'); await tick(); assert.equal(f.privateCount(), 0); assert.ok(f.order.includes('release'));
});
test('a focus observation during a pending failed activation waits and then retries once', async t => {
  const f = await fixture(t), wait = Promise.withResolvers(); f.outstanding.push(wait); let attempts = 0;
  f.state.activate = async () => { if (++attempts === 1) await wait.promise; };
  await f.mount(); assert.equal(attempts, 1);
  await act(async () => { f.emit({ foreground: true }); await tick(); }); assert.equal(attempts, 1);
  await act(async () => { wait.reject(Error('inactive')); await tick(); }); await act(async () => { await tick(); });
  assert.equal(attempts, 2); assert.equal(f.privateCount(), 1);
});
test('unmount during service construction cleans both late native event subscriptions', async t => {
  const f = await fixture(t, { phase: 'activated' }), first = Promise.withResolvers(), second = Promise.withResolvers();
  f.outstanding.push(first, second); f.registrations.push(first.promise, second.promise);
  await f.mount(); assert.equal(f.received.length, 0); await f.unmount();
  first.resolve(44); second.resolve(45); await tick(); await tick();
  assert.equal(f.received.length, 0); assert.equal(f.calls.filter(call => call.name === 'plugin:event|unlisten').length, 2);
});
