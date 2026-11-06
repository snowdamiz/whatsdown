import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
const require = createRequire(import.meta.url);
const React = require('react'), { create, act } = require('react-test-renderer'), ts = require('typescript');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const generated = readFileSync(new URL('../modules/mesh-messenger/generated/libmessenger_mobile.ts', import.meta.url), 'utf8');
const names = [...generated.matchAll(/^export const (\w+) =/gm)].map(row => row[1]);
const native = 'export const isLegacyDesktopBridge=false;' + [...names, 'invokeWallet', 'openNativeCreditPayment', 'primePushToken', 'clearPushToken', 'onPushRegistrationChanged'].map(name => `export const ${name}=()=>{throw Error("global_native_called")};`).join('');
const reactPath = pathToFileURL(require.resolve('react')).href;
registerHooks({ load(url, context, next) {
  if (url.startsWith('file:') && /\.tsx?$/.test(url)) return { shortCircuit: true, format: 'module', source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), { fileName: new URL(url).pathname, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText };
  return next(url, context);
}, resolve(specifier, context, next) {
  if (specifier === 'react' && context.parentURL?.startsWith('data:')) return next(reactPath, context);
  const sources = {
    './App': 'import React from "react";export default function App(props){return React.createElement("root-private-app",props)}',
    './StartupScreen': 'import React from "react";export function StartupScreen(props){return React.createElement("root-public",props)}',
    './DesktopUpdates': 'export function DesktopUpdates(){return null}',
    './language': 'export function LanguageProvider(p){return p.children}export const useI18n=()=>({t:v=>v});',
    './theme': 'import React from "react";export const WindowsChromeContext=React.createContext(false);export function AppearanceProvider(p){React.useState(p.load);return p.children}export const useTheme=()=>({scheme:"dark",colors:{danger:"red",canvas:"black"}});',
    './ui': 'export const chrome={header:48};export function IconButton(){return null}',
    './scrollbars': 'export function installScrollbars(){return()=>{}}',
    './transport.web': 'export const isDevelopmentBuild=()=>true;',

    '../modules/mesh-messenger': native,
    './storage': 'export const databasePath="/legacy/database";',
    'expo-file-system': 'export class File {constructor(){throw Error("global_file_called")}};export const Paths={};',
    'expo-notifications': 'export const setNotificationHandler=()=>{throw Error("global_notifications_called")};',
    'react-native': 'export const Platform={OS:"web"};export const View="view";export const Clipboard={setString(){throw Error("global_clipboard_called")}};',
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
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { userAgent: 'MacIntel' } });
Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement(){return{}}, head:{appendChild(){}}, documentElement:{dataset:{} } } });
const { default: Root } = await import('../src/Root.web.tsx');
const tick = () => new Promise(resolve => setImmediate(resolve));
const owner = '00000000-0000-4000-8000-000000000001';
async function fixture(t, options = {}) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const calls = [], received = [], order = [], registrations = [], outstanding = [];
  let deliver = () => {}, renderer, active = true, publicCommits = 0; const callbacks = []; let transport;
  const state = { generation: 1, revision: 1, phase: options.phase ?? 'disabled', policy: 'disabled', foreground: true,
    renderError: false, async activate() {}, async remove() {} };
  const snapshot = () => ({ version: 1, owner, revision: String(state.revision), state: { epoch: owner + '/' + state.generation, phase: state.phase, policy: state.policy, capability: 'available', foreground: state.foreground } });
  function emit(changes) { Object.assign(state, changes); state.revision++; deliver(snapshot()); }
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __MORSE_DOCUMENT__: '00000000-0000-4000-8000-000000000001', __TAURI_INTERNALS__: { transformCallback(callback) { callbacks.push(callback); return callbacks.length; }, async invoke(name, body, options) {
      calls.push({ name, body, options });
      if (name === 'plugin:event|listen') { if (body.event === 'app-lock-changed') deliver = payload => callbacks[body.handler - 1]({event:body.event,id:42,payload}); return registrations.shift() ?? 42; }
      if (name === 'plugin:event|unlisten') { await state.remove(); order.push('unlisten'); return; }
      if (name === 'appearance') return 'dark';
      if (name === 'app_lock_check') { if (state.phase !== 'activated' || options.headers['X-Morse-Lock-Epoch'] !== snapshot().state.epoch) throw Error('stale_epoch'); return null; }
      if (name === 'mesh_invoke') return [state.generation];
      if (['app_lock_bind','app_lock_state','app_lock_activate','app_lock_release'].includes(name)) return transport.command(name,body,options?.headers);
      if (name === 'database_path') return '/captured/db';
      if (name === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
      if (name === 'app_lock_file_cleanup') return null;
      throw Error('unexpected_' + name);
    } }, __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener() {} },
  } });
  transport = {
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
  async function mount() { await act(async () => { renderer = create(React.createElement(Root)); await tick(); }); await act(async () => { await tick(); }); }
  async function unmount() { if (active && renderer) { active = false; await act(async () => { renderer.unmount(); await tick(); }); } }
  t.after(async () => { for (const pending of outstanding) pending.resolve(); await unmount(); await tick(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { state, calls, received, order, registrations, outstanding, transport, emit, mount, unmount, element,
    rootApp: () => renderer.root.findByType('root-private-app'),
    rootPrivateCount: () => renderer.root.findAllByType('root-private-app').length,
    privateCount: () => renderer.root.findAllByType('private-app').length,
    publicCount: () => renderer.root.findAllByType('public-shell').length,
    replaceTransport: async next => { await act(async () => { renderer.update(element('one', next)); await tick(); }); },
    update: async key => { await act(async () => { renderer.update(element(key)); await tick(); }); await act(async () => { await tick(); }); },
  };
}
test('macOS Root constructs the scoped native app without unscoped database discovery', async t => {
  const f = await fixture(t); await f.mount(); await act(async () => { await tick(); });
  const services = f.rootApp().props.services;
  assert.equal(services.supportsAppLock, true); assert.equal(services.databasePath, '/captured/db');
  assert.ok(f.calls.some(call => call.name === 'app_lock_bind'));
  assert.ok(f.calls.filter(call => call.name === 'database_path').every(call => call.options?.headers?.['X-Morse-Lock-Owner'] === owner));
});
test('macOS Root unmounts the app on native relock and preserves the public startup surface', async t => {
  const f = await fixture(t); await f.mount(); await act(async () => { await tick(); });
  await act(async () => { f.emit({phase:'locked',generation:2}); await tick(); });
  assert.equal(f.rootPrivateCount(), 0);
});
test('account erasure constructs a fresh owner and retires previous app operations', async t => {
  const f = await fixture(t); await f.mount(); await act(async () => { await tick(); });
  const before = f.rootApp().props;
  await act(async () => { before.onAccountErased('removed'); await tick(); }); await act(async () => { await tick(); });
  const after = f.rootApp().props;
  assert.notEqual(before.services, after.services); assert.equal(after.notice, 'removed');
  await assert.rejects(async () => before.services.load_profile_export(Uint8Array.of(1)), /stale_epoch/);
  assert.ok(f.calls.filter(call => call.name === 'app_lock_bind').length >= 2);
});
