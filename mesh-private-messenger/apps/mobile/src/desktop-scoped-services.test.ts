import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test, { type TestContext } from 'node:test';
import ts from 'typescript';
import { bindDesktopOwner } from './desktop-owner-client.ts';
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const generated = readFileSync(new URL('../modules/mesh-messenger/generated/libmessenger_mobile.ts', import.meta.url), 'utf8');
const exports = [...generated.matchAll(/^export const (\w+) =/gm)].map(row => row[1]);
const nativeSource = 'export const isLegacyDesktopBridge=false;' + [...exports, 'invokeWallet', 'openNativeCreditPayment', 'primePushToken', 'clearPushToken', 'onPushRegistrationChanged']
  .map(name => `export const ${name}=()=>{throw Error("global_native_called")};`).join('');
registerHooks({ load(url, context, next) {
  if (url.startsWith('file:') && url.endsWith('.ts')) return {
    shortCircuit: true, format: 'module',
    source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
    } }).outputText,
  };
  return next(url, context);
}, resolve(specifier, context, next) {
  const sources: Record<string, string> = {
    '../modules/mesh-messenger': nativeSource,
    './storage': 'export const databasePath="/legacy/database";',
    'expo-file-system': 'export class File {constructor(){throw Error("global_file_called")}};export const Paths={};',
    'expo-notifications': 'export const setNotificationHandler=()=>{throw Error("global_notifications_called")};',
    'react-native': 'export const Platform={OS:"ios"};',
    'expo-image-picker': 'export const launchImageLibraryAsync=()=>{throw Error("global_picker_called")};',
    'expo-image-manipulator': 'export const ImageManipulator={};export const SaveFormat={JPEG:"jpeg"};',
  };
  const source = sources[specifier];
  if (source !== undefined) return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(source) };
  if ((specifier.startsWith('./') || specifier.startsWith('../')) && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    for (const extension of ['.web.ts', '.ts']) {
      const candidate = new URL(`${specifier}${extension}`, context.parentURL);
      if (existsSync(candidate)) return next(candidate.href, context);
    }
  }
  return next(specifier, context);
} });
const { createScopedDesktopAppServices } = await import('./desktop-scoped-services.ts');
const owner = '00000000-0000-4000-8000-000000000001';
async function fixture(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const calls: { name: string; body: unknown; options: unknown }[] = [];
  const native: { symbol: string; request: Uint8Array }[] = [];
  const registrations: Promise<number>[] = [];
  const state = { generation: 1, revision: 1, async remove(): Promise<void> {},
    file(operation: string): unknown { throw Error('unexpected_file_' + operation); } };
  const snapshot = () => ({ version: 1, owner, revision: String(state.revision), state: {
    epoch: owner + '/' + state.generation, phase: 'activated', policy: 'disabled', capability: 'available', foreground: true,
  } });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __TAURI_INTERNALS__: { transformCallback() { return 1; }, async invoke(name: string, body: unknown, options: unknown) {
      calls.push({ name, body, options });
      if (name === 'plugin:event|listen') return registrations.shift() ?? 42;
      if (name === 'plugin:event|unlisten') return state.remove();
      if (name === 'database_path') return '/captured/db';
      if (name === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
      if (name === 'app_lock_file_cleanup') return null;
      if (name === 'app_lock_file') {
        assert(options !== null && typeof options === 'object' && 'headers' in options);
        const headers = options.headers;
        assert(headers !== null && typeof headers === 'object' && 'X-Morse-File-Operation' in headers);
        const operation = headers['X-Morse-File-Operation']; assert.equal(typeof operation, 'string');
        if (typeof operation !== 'string') throw Error('invalid_operation');
        return state.file(operation);
      }
      throw Error('unexpected_' + name);
    } }, __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener() {} },
  } });
  let update = (_payload: unknown) => {};
  const client = await bindDesktopOwner({
    async listen(receive) { update = receive; return () => {}; },
    async command(name) { return name === 'app_lock_bind' || name === 'app_lock_state' ? snapshot() : null; },
    privatePort() { return { async check() {}, async invoke(symbol, request) { native.push({ symbol, request }); return Uint8Array.of(9); },
      async invokeWallet() { return Uint8Array.of(8); }, async copyProtectedText() {} }; },
  }, { signal: new AbortController().signal, onSnapshot() {}, onRetired() {} });
  t.after(async () => { await client.close(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { client, state, calls, native, registrations, replace() { state.generation++; state.revision++; update(snapshot()); } };
}
test('the constructed desktop app uses captured scoped services and exposes no private transport', async t => {
  const f = await fixture(t), owned = await createScopedDesktopAppServices(f.client);
  try {
    assert.equal(owned.services.databasePath, '/captured/db');
    assert.equal(owned.services.supportsAppLock, true); assert.equal(owned.services.appLockEnabled, false);
    assert.equal(owned.services.backups.kind, 'available');
    for (const key of ['invoke', 'runPrivate', 'assertCurrent', 'onDispose', 'receive', 'close', 'windowAction', 'protectedFile']) assert.equal(key in owned.services, false, key);
    assert.deepEqual(await owned.services.load_profile_export(Uint8Array.of(1)), Uint8Array.of(9));
    assert.equal(f.native[0]?.symbol, 'mesh_messenger_load_profile');
    assert.equal(f.calls.filter(call => call.name === 'plugin:event|listen').length, 2);
    assert.deepEqual(f.calls.find(call => call.name === 'database_path')?.options, { headers: { 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': owner + '/1' } });
  } finally { await owned.close(); }
});
test('desktop app teardown stops admission immediately and awaits native subscription removal', async t => {
  const f = await fixture(t), owned = await createScopedDesktopAppServices(f.client), removal = Promise.withResolvers<void>();
  f.state.remove = () => removal.promise;
  let closed = false; const closing = owned.close().then(value => { closed = true; return value; });
  await tick();
  try { assert.equal(closed, false); await assert.rejects(owned.services.load_profile_export(Uint8Array.of(1)), /stale_epoch/); }
  finally { removal.resolve(); await closing; }
  assert.equal(f.calls.filter(call => call.name === 'plugin:event|unlisten').length, 2);
});
test('a generation change while obtaining the session cannot pair new authority with old headers', async t => {
  const f = await fixture(t);
  const client = { ...f.client, async makeSession() { f.replace(); return f.client.makeSession(); } };
  const outcome = await createScopedDesktopAppServices(client).then(async owned => { await owned.close(); return 'published'; }, () => 'refused');
  assert.equal(outcome, 'refused'); assert.equal(f.calls.filter(call => call.name === 'database_path').length, 0);
});
test('a failed event registration disposes the new private service session and drains partial setup', async t => {
  const f = await fixture(t); let supplied: Awaited<ReturnType<typeof f.client.makeSession>> | undefined;
  const client = { ...f.client, async makeSession() { supplied = await f.client.makeSession(); return supplied; } };
  const late = Promise.withResolvers<number>(); f.registrations.push(Promise.reject(Error('registration_failed')), late.promise);
  const pending = createScopedDesktopAppServices(client); const outcome = pending.then(() => 'published', () => 'refused');
  await tick(); late.resolve(43); assert.equal(await outcome, 'refused');
  assert.ok(supplied); assert.throws(supplied.assertCurrent, /stale_epoch/);
  assert.equal(f.calls.filter(call => call.name === 'plugin:event|unlisten').length, 1);
});

test('backup capability is tied to the actual desktop factory session and retired with it', async t => {
  const f = await fixture(t), owned = await createScopedDesktopAppServices(f.client);
  try {
    const backups = owned.services.backups;
    assert.equal(backups.kind, 'available');
    if (backups.kind !== 'available') throw Error('desktop_backups_not_connected');
    assert.equal(backups.scope.epoch, owner + '/1');
    assert.throws(() => { f.replace(); backups.scope.assertActive(); }, /stale_epoch/);
    const before = f.calls.filter(call => call.name === 'app_lock_file').length;
    await assert.rejects(async () => backups.files.prepareBackupDestination(), /stale_epoch/);
    assert.equal(f.calls.filter(call => call.name === 'app_lock_file').length, before, 'retired backup selection must not reach a new native picker');
  } finally { await owned.close(); }
});

test('constructed desktop backup uses native choice and export with a full native epoch', async t => {
  const f = await fixture(t), owned = await createScopedDesktopAppServices(f.client);
  const operations: string[] = [];
  f.state.file = operation => {
    operations.push(operation);
    if (operation === 'pendingChoice') return { version: 1, choiceId: owner, requestId: owner };
    if (operation === 'beginExport') return { version: 1, handle: owner };
    if (operation === 'writeExport' || operation === 'commitExport') return null;
    throw Error('unexpected_' + operation);
  };
  try {
    const backup = owned.services.backups; if (backup.kind !== 'available') throw Error('backup_unavailable');
    const sink = await backup.files.chooseBackupDestination(3, `backup-export/${backup.scope.epoch}/1`);
    assert(sink); await sink.write(0, Uint8Array.of(1, 2, 3)); await sink.finish();
    assert.deepEqual(operations, ['pendingChoice', 'beginExport', 'writeExport', 'commitExport']);
    for (const call of f.calls.filter(call => call.name === 'app_lock_file')) {
      assert(call.options !== null && typeof call.options === 'object' && 'headers' in call.options);
      const headers = call.options.headers; assert(headers !== null && typeof headers === 'object' && 'X-Morse-Lock-Epoch' in headers);
      assert.equal(headers['X-Morse-Lock-Epoch'], owner + '/1');
    }
  } finally { await owned.close(); }
});
