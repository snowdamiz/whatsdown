import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { nativeSourceInventory, requireReviewedInventory, applicationNetworkViolations, validateApplicationSources } from './native-network-inventory.mjs';

test('a new native connection or changed native code requires inventory review', () => {
  const root = mkdtempSync(join(tmpdir(), 'morse-network-inventory-'));
  try {
    mkdirSync(join(root, 'ios'));
    writeFileSync(join(root, 'ios/Local.swift'), 'func local() {}\n');
    const reviewed = { packages: [{ name: 'existing', ...nativeSourceInventory(root) }] };
    requireReviewedInventory(reviewed, reviewed);
    writeFileSync(join(root, 'ios/Remote.swift'), 'let session = URLSession.shared\n');
    const current = { packages: [{ name: 'existing', ...nativeSourceInventory(root) }] };
    assert.deepEqual(current.packages[0].connectionSites, ['ios/Remote.swift']);
    assert.throws(() => requireReviewedInventory(current, reviewed), /native_network_inventory_changed/);
  } finally { rmSync(root, { recursive: true }); }
});

test('a newly linked module or changed dependency pin cannot pass an old inventory', () => {
  const reviewed = { packages: [{ name: 'reviewed', version: '1' }], controls: { lock: 'first' } };
  assert.throws(() => requireReviewedInventory({ ...reviewed, packages: [...reviewed.packages, { name: 'new-module', version: '1' }] }, reviewed), /native_network_inventory_changed/);
  assert.throws(() => requireReviewedInventory({ ...reviewed, controls: { lock: 'second' } }, reviewed), /native_network_inventory_changed/);
});

test('application source cannot reintroduce raw transports, native HTTP imports or filesystem network APIs', () => {
  for (const source of [
    'fetch(url)', 'const send = globalThis.fetch; send(url)', 'const xhr = new XMLHttpRequest()',
    'const socket = new WebSocket(url)', 'globalThis["fetch"](url)',
    'navigator.sendBeacon(url, body)', 'File.downloadFileAsync(url, destination)',
    'import { fetch as send } from "expo/fetch"; send(url)',
    'import { NativeModules } from "react-native"; NativeModules.Networking.sendRequest()',
    'import { requireNativeModule } from "expo-modules-core"; requireNativeModule("ExpoFetch")',
    'const raw = require("react-native/Libraries/Network/RCTNetworking");',
    'import { downloadAsync } from "expo-file-system/legacy"; downloadAsync(url, path)',
  ]) assert.ok(applicationNetworkViolations(source).length > 0, source);
  assert.deepEqual(applicationNetworkViolations('type Socket = Pick<WebSocket, "onclose">; const note = "fetch"; // fetch(url)\n'), []);
});

test('a new nested application module cannot bypass the source boundary gate', () => {
  const root = mkdtempSync(join(tmpdir(), 'morse-network-source-'));
  try {
    mkdirSync(join(root, 'screens'));
    writeFileSync(join(root, 'screens/Remote.tsx'), 'export const load = () => fetch("https://blocked.invalid");');
    assert.throws(() => validateApplicationSources(root), /application_network_capability/);
  } finally { rmSync(root, { recursive: true }); }
});


const jsiPublic = 'apple/Sources/ExpoModulesJSI-Cxx/include/Public/NativeState.h';
const jsiSwift = 'apple/Sources/ExpoModulesJSI/Runtime.swift';
const product = 'apple/Products/ExpoModulesJSI.xcframework/ios-arm64_x86_64-simulator/ExpoModulesJSI.framework/Headers/';
const derivedHeaders = [
  'apple/.DerivedData/Build/Intermediates.noindex/GeneratedModuleMaps-iphonesimulator/ExpoModulesJSI-Swift.h',
  'apple/.DerivedData/Build/Intermediates.noindex/ExpoModulesJSI.build/Release-iphonesimulator/ExpoModulesJSI-t.build/Objects-normal/arm64/ExpoModulesJSI-Swift.h',
  'apple/.DerivedData/Build/Intermediates.noindex/ExpoModulesJSI.build/Release-iphonesimulator/ExpoModulesJSI-t.build/Objects-normal/x86_64/ExpoModulesJSI-Swift.h',
];
const producerInputs = [
  'apple/scripts/build-xcframework.sh', 'apple/scripts/generate-modulemap.sh',
  'apple/scripts/create-stub-xcframework.sh', 'apple/scripts/xcframework-helpers.sh',
  'apple/scripts/unexported-swift-runtime-symbols.txt', 'apple/APINotes/jsi.apinotes',
];
function put(root, path, value) {
  mkdirSync(join(root, path, '..'), { recursive: true });
  writeFileSync(join(root, path), value);
}
function vendorFixture(name) {
  const root = mkdtempSync(join(tmpdir(), 'morse-vendor-source-'));
  if (name === 'expo-modules-jsi') {
    put(root, jsiPublic, 'struct NativeState {};\n');
    put(root, jsiSwift, 'func authored() {}\n');
    for (const path of producerInputs) put(root, path, `authored producer ${path}\n`);
  } else put(root, 'vendor/bspatch/bspatch.c', 'int authored_patch(void) { return 0; }\n');
  return { root, inventory: () => nativeSourceInventory(root, [], { packageName: name }),
    close: () => rmSync(root, { recursive: true, force: true }) };
}
function generatedJSI(root) {
  for (const path of [...derivedHeaders, product + 'ExpoModulesJSI-Swift.h']) put(root, path, '// compiler-generated SDK A\n');
  put(root, product + 'NativeState.h', readFileSync(join(root, jsiPublic)));
}

test('the six actual Expo Pod/build output paths do not change the authored source inventory', () => {
  const jsi = vendorFixture('expo-modules-jsi'), updates = vendorFixture('expo-updates');
  try {
    const beforeJSI = jsi.inventory(), beforeUpdates = updates.inventory();
    generatedJSI(jsi.root);
    put(updates.root, 'ios/EXUpdates/BSPatch/bspatch.c', readFileSync(join(updates.root, 'vendor/bspatch/bspatch.c')));
    assert.deepEqual(jsi.inventory(), beforeJSI, 'three DerivedData headers plus two staged headers must normalize');
    assert.deepEqual(updates.inventory(), beforeUpdates, 'Pod evaluation copies an already inventoried BSPatch source');
  } finally { jsi.close(); updates.close(); }
});

test('generated Swift header caches are optional across platforms and compiler versions', () => {
  const f = vendorFixture('expo-modules-jsi');
  try {
    const before = f.inventory();
    generatedJSI(f.root);
    rmSync(join(f.root, 'apple/.DerivedData'), { recursive: true });
    put(f.root, product + 'ExpoModulesJSI-Swift.h', '// compiler-generated SDK B\n');
    put(f.root, 'apple/Products/ExpoModulesJSI.xcframework/macos-arm64_x86_64/ExpoModulesJSI.framework/Versions/A/Headers/ExpoModulesJSI-Swift.h', '// compiler-generated macOS SDK\n');
    put(f.root, 'apple/Products/ExpoModulesJSI.xcframework/macos-arm64_x86_64/ExpoModulesJSI.framework/Versions/A/Headers/NativeState.h', readFileSync(join(f.root, jsiPublic)));
    assert.deepEqual(f.inventory(), before, 'cached generated headers need not retain DerivedData or share SDK-specific bytes');
  } finally { f.close(); }
});

test('a changed compiled authored copy or its missing canonical source is refused', () => {
  for (const [name, source, copy] of [
    ['expo-modules-jsi', jsiPublic, product + 'NativeState.h'],
    ['expo-updates', 'vendor/bspatch/bspatch.c', 'ios/EXUpdates/BSPatch/bspatch.c'],
  ]) {
    const f = vendorFixture(name);
    try {
      const authored = readFileSync(join(f.root, source));
      put(f.root, copy, authored); f.inventory();
      put(f.root, copy, '// altered compiled source\n');
      assert.throws(f.inventory, /native_network_inventory_copy_mismatch/, `${name} compiled copy mutation cannot be hidden`);
      put(f.root, copy, authored); rmSync(join(f.root, source));
      assert.throws(f.inventory, /native_network_inventory_copy_mismatch/, `${name} missing canonical source cannot authorize exclusion`);
    } finally { f.close(); }
  }
});

test('authored sources and matching regenerated copies still require review', () => {
  for (const [name, source, copy] of [
    ['expo-modules-jsi', jsiPublic, product + 'NativeState.h'],
    ['expo-updates', 'vendor/bspatch/bspatch.c', 'ios/EXUpdates/BSPatch/bspatch.c'],
  ]) {
    const f = vendorFixture(name);
    try {
      const before = f.inventory();
      put(f.root, source, '// changed authored source\n');
      put(f.root, copy, readFileSync(join(f.root, source)));
      assert.throws(() => requireReviewedInventory(f.inventory(), before), /native_network_inventory_changed/);
    } finally { f.close(); }
  }
  const f = vendorFixture('expo-modules-jsi');
  try {
    const before = f.inventory(); put(f.root, jsiSwift, 'func changedAuthored() {}\n');
    assert.throws(() => requireReviewedInventory(f.inventory(), before), /native_network_inventory_changed/);
  } finally { f.close(); }
});

test('every production generator script API note and visibility input requires review', () => {
  const f = vendorFixture('expo-modules-jsi');
  try {
    const before = f.inventory();
    for (const path of producerInputs) {
      const previous = readFileSync(join(f.root, path));
      put(f.root, path, `changed producer ${path}\n`);
      assert.throws(() => requireReviewedInventory(f.inventory(), before), /native_network_inventory_changed/, path);
      put(f.root, path, previous);
    }
  } finally { f.close(); }
});

test('normalization never hides unrelated package or authored output-like source paths', () => {
  const f = vendorFixture('expo-modules-jsi');
  try {
    for (const path of ['apple/Products/Other/Headers/Authored.h', 'apple/Headers/Authored.h', 'apple/.generated/Authored.swift']) {
      const before = f.inventory(); put(f.root, path, 'int authored;\n');
      assert.throws(() => requireReviewedInventory(f.inventory(), before), /native_network_inventory_changed/, path);
    }
    const legacy = nativeSourceInventory(f.root, ['native']);
    const local = nativeSourceInventory(f.root, [], { packageName: 'mesh-messenger' });
    const unrelated = nativeSourceInventory(f.root, [], { packageName: 'unrelated' });
    put(f.root, product + 'ExpoModulesJSI-Swift.h', '// output-shaped but not classified as vendor\n');
    for (const [before, collect] of [
      [legacy, () => nativeSourceInventory(f.root, ['native'])],
      [local, () => nativeSourceInventory(f.root, [], { packageName: 'mesh-messenger' })],
      [unrelated, () => nativeSourceInventory(f.root, [], { packageName: 'unrelated' })],
    ]) assert.throws(() => requireReviewedInventory(collect(), before), /native_network_inventory_changed/);
    put(f.root, product + 'Unexpected.h', 'int unexpected;\n');
    assert.throws(f.inventory, /native_network_inventory_copy_mismatch/, 'an unrecognized staged public source cannot be silently omitted');
  } finally { f.close(); }
});

test('all four local generated native bindings stay inventoried with the existing two-argument behavior', () => {
  const root = mkdtempSync(join(tmpdir(), 'morse-local-generated-'));
  const paths = ['generated/libmessenger_mobile.h', 'generated/libmessenger_mobile.jni.c',
    'generated/libmessenger_mobile.swift', 'generated/libmessenger_mobile.kt'];
  try {
    for (const path of paths) put(root, path, '// authored native binding\n');
    put(root, 'native/ignored.h', '// separately qualified native archive header\n');
    const before = nativeSourceInventory(root, ['native']);
    assert.equal(before.sources, 4);
    for (const path of paths) {
      put(root, path, '// changed native binding\n');
      assert.throws(() => requireReviewedInventory(nativeSourceInventory(root, ['native']), before), /native_network_inventory_changed/, path);
      put(root, path, '// authored native binding\n');
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('recognized copied sources and their canonical inputs must be regular files', () => {
  for (const [name, source, copy] of [
    ['expo-modules-jsi', jsiPublic, product + 'NativeState.h'],
    ['expo-updates', 'vendor/bspatch/bspatch.c', 'ios/EXUpdates/BSPatch/bspatch.c'],
  ]) {
    for (const variant of ['copy-symlink', 'copy-directory', 'canonical-symlink']) {
      const f = vendorFixture(name);
      try {
        const bytes = readFileSync(join(f.root, source));
        put(f.root, copy, bytes); f.inventory();
        const replaced = variant === 'canonical-symlink' ? source : copy;
        rmSync(join(f.root, replaced));
        if (variant === 'copy-directory') mkdirSync(join(f.root, replaced));
        else {
          put(f.root, 'outside-native-source.txt', '// altered compiled bytes\n');
          symlinkSync(join(f.root, 'outside-native-source.txt'), join(f.root, replaced));
        }
        assert.throws(f.inventory, /native_network_inventory_copy_mismatch/, `${name} ${variant} cannot bypass copied-source equality`);
      } finally { f.close(); }
    }
  }
});
