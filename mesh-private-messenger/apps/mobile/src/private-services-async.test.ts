import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { createAppLockSession, type AppLockNativePort } from './app-lock.ts';
import { Reader, utf8, vectors, decodeUtf8 } from './codec.ts';

registerHooks({ resolve(specifier, context, next) {
  if (context.parentURL?.endsWith('/src/wallet.ts')) {
    if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(
      'export const isLegacyDesktopBridge=false; export const invokeWallet=()=>{throw Error("global_wallet_called")};') };
    if (specifier === './credits') return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(
      'export const creditPacket=()=>{throw Error("unexpected_payment_packet")};') };
  }
  if (context.parentURL?.endsWith('/src/sealed-journals.ts') || context.parentURL?.endsWith('/src/sealed-preferences.ts') || context.parentURL?.endsWith('/src/read-state-store.ts')) {
    if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(
      'export const isLegacyDesktopBridge=false; export const journal_load_bound_export=()=>{throw Error("global_bridge_called")}; export const journal_save_bound_export=journal_load_bound_export;') };
    if (specifier === './storage') return { shortCircuit: true, url: 'data:text/javascript,export const databasePath="/legacy/db";' };
  }
  if (specifier === 'expo-file-system') return { shortCircuit: true, url: 'data:text/javascript,export class File { constructor(){throw Error("legacy_file_called");} };export const Paths={};' };
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createJournalServices } = await import('./sealed-journals.ts');
const { createPreferenceServices } = await import('./sealed-preferences.ts');
const { createWalletServices } = await import('./wallet.ts');
const { createReadStateServices } = await import('./read-state-store.ts');
const profile = vectors(utf8('author'), new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), new Uint8Array());
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function deferred<T>() {
  let resolve: (value: T) => void = () => { throw Error('resolver_not_initialized'); };
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function fixture() {
  const records = new Map<string, Uint8Array>();
  const paths: string[] = [];
  const state = { gate: Promise.resolve(), writes: 0, checks: 0 };
  const scope = createDesktopPrivateSession({
    async check() { state.checks++; await state.gate; },
    async invoke(symbol, request) {
      const packet = new Reader(request); const path = decodeUtf8(packet.vector(4096));
      packet.vector(40000); const label = decodeUtf8(packet.vector(4096)); paths.push(path);
      if (symbol === 'load') { packet.finish(); return (records.get(label) ?? new Uint8Array()).slice(); }
      const bytes = packet.vector(100000); packet.finish(); records.set(label, bytes.slice()); state.writes++;
      return new Uint8Array();
    },
    async invokeWallet() { throw Error('unexpected_wallet'); },
    async copyProtectedText() { throw Error('unexpected_clipboard'); },
  });
  const deps = { ...scope, databasePath: '/captured/db',
    journal_load_bound_export: (request: Uint8Array) => scope.invoke('load', request),
    journal_save_bound_export: (request: Uint8Array) => scope.invoke('save', request) };
  return { scope, state, records, paths, deps };
}

test('an unchanged cached journal save waits for native authority even when it needs no write', async () => {
  const f = fixture(); const journal = createJournalServices(f.deps).journalsFor(profile);
  const value = { 'chat/authored': ['seen'] }; await journal.save('read-state', value);
  const writes = f.state.writes; const gate = deferred<void>(); f.state.gate = gate.promise;
  let settled = false;
  const saving = journal.save('read-state', value).then(() => { settled = true; });
  await tick(); const settledWhileNativePending = settled; gate.resolve(); await saving;
  assert.equal(f.state.writes, writes);
  assert.equal(settledWhileNativePending, false);
  f.scope.dispose();
});

test('journal and preference requests retain the captured database path instead of global startup state', async () => {
  const f = fixture(); const journals = createJournalServices(f.deps), preferences = createPreferenceServices(f.deps);
  await journals.journalsFor(profile).save('notification-state', { 'chat/authored': ['notice'] });
  await preferences.saveSealedPreference(profile, 'notification-preview', 'none');
  assert(f.paths.length > 0); assert(f.paths.every(path => path === '/captured/db'));
  f.scope.dispose();
});

test('preference callbacks wait for the enclosing native authority check before reading legacy clear state', async () => {
  const f = fixture();
  const gate = deferred<void>(); let checks = 0, legacyRead = 0;
  // Only the outer helper check waits; native export checks stay available.
  const original = f.deps.assertActive;
  const deps = { ...f.deps, assertActive: async () => { checks++; if (checks === 1) await gate.promise; else await original(); },
    runPrivate: async <T>(operation: () => Promise<T>): Promise<T> => { checks++; await gate.promise; return f.scope.runPrivate(operation); } };
  const held = createPreferenceServices(deps);
  const reading = held.loadSealedPreference(profile, 'read-receipts', { read() { legacyRead++; return 'off'; }, remove() {} });
  await tick(); const before = legacyRead; gate.resolve(); assert.equal(await reading, 'off');
  assert.equal(before, 0); assert.equal(legacyRead, 1); assert(checks > 0);
  f.scope.dispose();
});

test('mobile private-operation rejection after native retirement exposes only stale authority', async () => {
  const gate = deferred<void>(); let active = true;
  const unused = () => { throw Error('unexpected_native_call'); };
  const native: AppLockNativePort = {
    getAppLockState: unused, authenticateAppLock: unused, cancelAppLockAuthentication: unused,
    lockApp: unused, setAppLockEnabled: unused, activateAppLockScope: unused,
    checkAppLockScope() { if (!active) throw Error('stale_epoch'); },
    consumeAppLockInboxIntent: unused, invokeScoped: unused, walletScoped: unused,
    primePushTokenScoped: unused, clearPushTokenScoped: unused, openCreditPaymentScoped: unused,
    protectedFile: unused, publishMessageNotice: unused, publishEncryptedWakeup: unused,
    copyProtectedText: unused, readLegacyPreference: unused, removeLegacyPreference: unused,
    forgetLegacyPreferences: unused, addListener: unused,
  };
  const scope = createAppLockSession(native, 'd355922a-069b-4c7b-ab9f-cecfefb8db4c');
  const pending = scope.runPrivate(async () => { await gate.promise; throw Error('private_account_detail'); });
  const refused = assert.rejects(pending, /stale_epoch/); active = false; gate.resolve(); await refused;
  scope.dispose();
});

test('wallet display conversion cannot run before its enclosing asynchronous authority check settles', async () => {
  const gate = deferred<void>(); let checks = 0, walletCalls = 0, published = false;
  const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
  const scope = createDesktopPrivateSession({
    async check() { checks++; if (checks === 1) await gate.promise; },
    invoke: unused, copyProtectedText: unused,
    async invokeWallet() { walletCalls++; return new Uint8Array(32); },
  });
  const wallet = createWalletServices(scope);
  const reading = wallet.walletAddressText().then(value => { published = true; return value; });
  await tick(); const callsBeforeAuthority = walletCalls, publishedBeforeAuthority = published;
  gate.resolve(); assert.equal(await reading, '1'.repeat(32));
  assert.equal(callsBeforeAuthority, 0); assert.equal(publishedBeforeAuthority, false);
  scope.dispose();
});


test('parsed read-state waits for its outer asynchronous native check', async () => {
  const f = fixture(); const gate = deferred<void>();
  const dependencies = { ...f.deps, ...createJournalServices(f.deps), ...createPreferenceServices(f.deps),
    assertActive: async () => { await gate.promise; },
    runPrivate: async <T>(operation: () => Promise<T>): Promise<T> => { await gate.promise; return f.scope.runPrivate(operation); },
    readLegacyPreference: () => null, removeLegacyPreference() {}, forgetLegacyPreferences() {},
  };
  const service = createReadStateServices(dependencies);
  let published = false;
  const reading = service.loadReadState(profile).then(value => { published = true; return value; });
  await tick(); const earlyReads = f.paths.length, earlyPublication = published;
  gate.resolve(); assert.deepEqual(await reading, {}); await tick(); f.scope.dispose();
  assert.equal(earlyReads, 0); assert.equal(earlyPublication, false);
});

test('preference erasure waits for native authority before its cleanup effect', async () => {
  const f = fixture(); let cleanups = 0;
  const service = createReadStateServices({ ...f.deps, ...createJournalServices(f.deps), ...createPreferenceServices(f.deps),
    readLegacyPreference: () => null, removeLegacyPreference() {}, forgetLegacyPreferences() { cleanups++; },
  });
  const gate = deferred<void>(); f.state.gate = gate.promise;
  const cleaning = Promise.resolve(service.forgetPreferences('01'.repeat(32)));
  await tick(); const early = cleanups; gate.resolve(); await cleaning; await tick(); f.scope.dispose();
  assert.equal(early, 0); assert.equal(cleanups, 1);
});

test('preference erasure waits for the captured native cleanup promise to finish', async () => {
  const f = fixture(); const gate = deferred<void>(); let started = false, settled = false;
  const service = createReadStateServices({ ...f.deps, ...createJournalServices(f.deps), ...createPreferenceServices(f.deps),
    readLegacyPreference: () => null, removeLegacyPreference() {},
    async forgetLegacyPreferences() { started = true; await gate.promise; },
  });
  const cleaning = service.forgetPreferences('01'.repeat(32)).then(() => { settled = true; });
  await tick(); const early = settled; const entered = started; gate.resolve(); await cleaning; f.scope.dispose();
  assert.equal(entered, true); assert.equal(early, false); assert.equal(settled, true);
});

test('legacy preference migration preserves an asynchronous disabled choice and awaits removal', async () => {
  const f = fixture(); const readGate = deferred<string | null>(); const removeGate = deferred<void>();
  let settled = false, removals = 0;
  const service = createReadStateServices({ ...f.deps, ...createJournalServices(f.deps), ...createPreferenceServices(f.deps),
    readLegacyPreference: () => readGate.promise,
    async removeLegacyPreference() { removals++; await removeGate.promise; }, forgetLegacyPreferences() {},
  });
  const reading = service.loadReadReceipts(profile).then(value => { settled = true; return value; });
  await tick(); const earlyWrites = f.state.writes; readGate.resolve('off'); await tick(); const earlyFinish = settled;
  removeGate.resolve(); const result = await reading; f.scope.dispose();
  assert.equal(earlyWrites, 0); assert.equal(earlyFinish, false); assert.equal(removals, 1); assert.equal(result, false);
  assert.equal(decodeUtf8(f.records.get('preferences/read-receipts')!), 'off');
});

test('an existing sealed preference waits for asynchronous legacy cleanup before publication', async () => {
  const f = fixture(); const gate = deferred<void>(); let settled = false;
  f.records.set('preferences/read-receipts', utf8('off'));
  const service = createReadStateServices({ ...f.deps, ...createJournalServices(f.deps), ...createPreferenceServices(f.deps),
    readLegacyPreference: () => { throw Error('sealed_copy_must_win'); }, removeLegacyPreference: () => gate.promise, forgetLegacyPreferences() {},
  });
  const reading = service.loadReadReceipts(profile).then(value => { settled = true; return value; });
  await tick(); const earlyFinish = settled; gate.resolve(); assert.equal(await reading, false); f.scope.dispose();
  assert.equal(earlyFinish, false);
});
