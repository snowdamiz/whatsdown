import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseBindings, generate } from './generate-scoped-bindings.mjs';

const fixture = name => readFileSync(new URL('./fixtures/scoped-bindings/' + name, import.meta.url), 'utf8');
const source = fixture('mobile.ts'), abi = JSON.parse(fixture('mobile.abi.json'));
const mixed = fixture('mixed.ts'), mixedAbi = JSON.parse(fixture('mixed.abi.json'));
const clone = value => structuredClone(value);

test('actual ABI175 emits the same164 app operations with11 backups excluded', () => {
  assert.equal(parseBindings(source, abi).length, 175);
  const output = generate(source, abi);
  assert.equal(output.split('\n').slice(1).join('\n'), fixture('scoped.ts').split('\n').slice(1).join('\n'));
  assert.equal((output.match(/=> client.invoke/g) ?? []).length, 164);
  assert.doesNotMatch(output, /mesh_messenger_backup_/);
});

test('actual public compiler mixed emission omits the native-only operation', () => {
  assert.deepEqual(parseBindings(mixed, mixedAbi), [{ alias: 'public_echo', symbol: 'audience_public' }]);
});

test('native-only rows cannot enter the scoped JavaScript surface', () => {
  const leaked = mixed + "export const native_echo = (request: Uint8Array): Promise<Uint8Array> => native.invoke('audience_native', request);\n";
  assert.throws(() => parseBindings(leaked, mixedAbi), /native_binding_exposed/);
});

test('ABI pairs are exact and complete and generated JavaScript has no extra code', () => {
  for (const changed of [
    mixed.replace('public_echo', 'other_echo'),
    mixed.replace('audience_public', 'audience_other'),
    mixed.replace(/^export const.*\n/gm, ''),
    mixed + mixed.match(/^export const.*\n/gm)[0],
    mixed + "native.invoke('audience_native', new Uint8Array());\n",
  ]) assert.throws(() => parseBindings(changed, mixedAbi), /binding_/);
});

test('duplicate ABI identities and unknown audiences refuse before generation', () => {
  for (const change of [
    value => value.exports.push(clone(value.exports[0])),
    value => { value.exports[1].meshFunction = value.exports[0].meshFunction; },
    value => { value.exports[1].symbol = value.exports[0].symbol; },
    value => { value.exports[1].bindingAudience = 'browser'; },
    value => { value.abiVersion = 2; },
    value => { value.exports[0].request = 'string'; },
    value => { value.exports[0].maxOutputBytes = -1; },
  ]) { const broken = clone(mixedAbi); change(broken); assert.throws(() => parseBindings(mixed, broken), /binding_abi/); }
});

test('native-only modules admit the compiler empty-module form and no callable rows', () => {
  const nativeOnly = clone(mixedAbi); nativeOnly.exports = nativeOnly.exports.filter(row => row.bindingAudience === 'native');
  assert.deepEqual(parseBindings('// No JavaScript bindings were requested.\nexport {};\n', nativeOnly), []);
  assert.throws(() => parseBindings(mixed, nativeOnly), /binding_/);
});

test('app generator requires the complete explicit backup exclusions', () => {
  const broken = clone(abi); broken.exports = broken.exports.filter(row => row.symbol !== 'mesh_messenger_backup_create');
  const changed = source.replace(/^export const backup_create_export.*\n/gm, '');
  assert.throws(() => generate(changed, broken), /binding_app_policy/);
});


test('ABI frame bounds follow the public compiler1..64MiB contract', () => {
  for (const field of ['maxInputBytes', 'maxOutputBytes']) {
    for (const value of [0, 67_108_865]) {
      const broken = clone(mixedAbi); broken.exports[0][field] = value;
      assert.throws(() => parseBindings(mixed, broken), /binding_abi/);
    }
    for (const value of [1, 67_108_864]) {
      const boundary = clone(mixedAbi); boundary.exports[0][field] = value;
      assert.deepEqual(parseBindings(mixed, boundary), [{ alias: 'public_echo', symbol: 'audience_public' }]);
    }
  }
});


test('actual Morse native176 preserves the164 operation facade and rejects view-once JavaScript exposure', () => {
  const actual = JSON.parse(fixture('native-mobile.abi.json'));
  assert.equal(actual.exports.length, 176);
  assert.equal(parseBindings(source, actual).length, 175);
  assert.equal(generate(source, actual), generate(source, abi));
  assert.doesNotMatch(generate(source, actual), /view_once_consume/);
  const leaked = source + "export const view_once_consume_native_export = (request: Uint8Array): Promise<Uint8Array> => native.invoke('mesh_messenger_view_once_consume', request);\n";
  assert.throws(() => generate(leaked, actual), /native_binding_exposed/);
});
