import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
import React from 'react';
import TestRenderer, { act } from 'react-test-renderer';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const tick = () => new Promise(resolve => setImmediate(resolve));
async function fixture() {
  let state = { page: 'native-page-1', epoch: 'native-session-1', databasePath: '/owned/db' };
  const subscribers = new Set();
  const services = [], released = [];
  const window = { addEventListener() {}, removeEventListener() {} };
  const context = vm.createContext({ console, navigator: { userAgent: 'Mac' }, window,
    document: { createElement: () => ({}), head: { appendChild() {} }, documentElement: { dataset: {} } } });
  const mocks = {
    react: React,
    'react-native': { View: 'View' },
    './App': { default: props => React.createElement('PrivateApp', props) },
    './DesktopUpdates': { DesktopUpdates: () => null },
    './StartupScreen': { StartupScreen: props => React.createElement('Startup', props) },
    './appearance': { palettes: { dark: {}, light: {} } },
    './appearance-store.web': { loadAppearance: async () => 'system', saveAppearance() {} },
    './desktop-layout': { SCROLLBAR_WIDTH: 8 }, './scrollbars': { installScrollbars: () => () => {} },
    './storage.web': { setDatabasePath() {} },
    './theme': { AppearanceProvider: ({ children }) => children, WindowsChromeContext: React.createContext(false), useTheme: () => ({ scheme: 'dark' }) },
    './tokens': { control: {}, cubicBezier() {}, duration: {}, easing: {}, radius: {}, space: [] },
    './transport.web': { isDevelopmentBuild: () => true }, './i18n': { t: s => s },
    './language': { LanguageProvider: ({ children }) => children, useI18n: () => ({ t: s => s }) },
    './ui': { chrome: {}, IconButton: () => null },
    '@tauri-apps/api/core': { invoke: async name => { if (name === 'database_path') return '/legacy/db'; throw Error(name); } },
    '@tauri-apps/api/window': { getCurrentWindow: () => ({}) },
    './desktop-connection': { subscribeDesktopSession: listener => { subscribers.add(listener); listener(state); return () => subscribers.delete(listener); },
      mountDesktopSession: async () => {}, retireDesktopSession: async value => { released.push(value.epoch); } },
    './app-lock-services.web': { createDesktopAppServices: captured => {
      const value = { captured, dispose() { released.push(captured?.epoch); } }; services.push(value); return value;
    } },
  };
  const root = new vm.SourceTextModule(ts.transpileModule(readFileSync(new URL('../src/Root.web.tsx', import.meta.url), 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX },
  }).outputText, { context });
  mocks['react/jsx-runtime'] = await import('react/jsx-runtime');
  await root.link(async name => {
    const mock = mocks[name]; if (!mock) throw Error(`Unexpected import: ${name}`);
    return new vm.SyntheticModule(Object.keys(mock), function () { for (const [key, value] of Object.entries(mock)) this.setExport(key, value); }, { context });
  });
  await root.evaluate();
  return { Root: root.namespace.default, services, released,
    publish(value) { state = value; for (const receive of subscribers) receive(value); } };
}

test('actual desktop root constructs no private services before native admission', async () => {
  const f = await fixture();
  assert.equal(f.services.length, 0, 'module evaluation must not create private services');
  f.publish(null);
  let tree; await act(async () => { tree = TestRenderer.create(React.createElement(f.Root)); await tick(); });
  assert.equal(tree.root.findAllByType('PrivateApp').length, 0);
  await act(async () => tree.unmount());
});

test('actual desktop root retires the old tree before mounting the next captured native session', async () => {
  const f = await fixture(); let tree;
  await act(async () => { tree = TestRenderer.create(React.createElement(f.Root)); await tick(); });
  assert.equal(tree.root.findByType('PrivateApp').props.services.captured.epoch, 'native-session-1');
  await act(async () => { f.publish(null); await tick(); });
  assert.equal(tree.root.findAllByType('PrivateApp').length, 0);
  assert(f.released.includes('native-session-1'));
  await act(async () => { f.publish({ page: 'native-page-2', epoch: 'native-session-2', databasePath: '/owned/new.db' }); await tick(); });
  assert.equal(tree.root.findByType('PrivateApp').props.services.captured.epoch, 'native-session-2');
  await act(async () => tree.unmount());
});
