import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const babel = require('@babel/core');
const commonjs = require('@babel/plugin-transform-modules-commonjs');
const filename = new URL('../index.ts', import.meta.url);

test('Expo initializes before lockdown, then background tasks and App evaluate with network already locked', () => {
  const events = [];
  let locked = false;
  let expo = false;
  const native = { registerRootComponent: () => { assert.equal(locked, true); events.push('registered'); } };
  const dependencies = {
    expo: () => { if (!expo) events.push('expo'); expo = true; return native; },
    './src/network-lockdown-bootstrap': () => { assert.equal(expo, true); locked = true; events.push('locked'); return {}; },
    './src/background-notifications': () => { assert.equal(locked, true, 'Headless/background import must not run before lockdown'); events.push('background'); return {}; },
    './src/Root': () => { assert.equal(locked, true, 'App imports must not run before lockdown'); events.push('app'); return { default: () => {} }; },
  };
  const source = babel.transformSync(readFileSync(filename, 'utf8'), { filename: 'index.ts', babelrc: false, configFile: false, plugins: [commonjs] }).code;
  const seen = new Map();
  vm.runInNewContext(`(function(require){${source}\n})`)((name) => {
    assert.ok(name in dependencies, name);
    if (!seen.has(name)) seen.set(name, dependencies[name]());
    return seen.get(name);
  });
  assert.deepEqual(events, ['expo', 'locked', 'background', 'app', 'registered']);
});
