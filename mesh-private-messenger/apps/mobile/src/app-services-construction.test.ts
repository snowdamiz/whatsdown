import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import ts from 'typescript';
import { createAppLockSession, type AppLockNativePort } from './app-lock.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';

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
    'expo-notifications': 'export const setNotificationHandler=()=>{};',
    'react-native': 'export const Platform={OS:"ios"};',
    'expo-image-picker': 'export const launchImageLibraryAsync=()=>{throw Error("global_picker_called")};',
    'expo-image-manipulator': 'export const ImageManipulator={};export const SaveFormat={JPEG:"jpeg"};',
  };
  const source = sources[specifier];
  if (source !== undefined) return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(source) };
  if ((specifier.startsWith('./') || specifier.startsWith('../')) && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAppServices } = await import('./app-lock-services.ts');
const { assembleAppServices } = await import('./app-services.ts');
const epoch = '00000000-0000-4000-8000-000000000001';
function fixture(marker: number) {
  const calls: { symbol: string; epoch: string; bytes: Uint8Array }[] = [];
  const forgotten: string[] = [];
  const unused = async (): Promise<never> => { throw Error('unexpected_native_operation'); };
  const native: AppLockNativePort = {
    getAppLockState: unused, authenticateAppLock: unused, setAppLockEnabled: unused,
    cancelAppLockAuthentication: unused, lockApp: unused, activateAppLockScope: unused,
    checkAppLockScope(expected) { assert.equal(expected, epoch); },
    consumeAppLockInboxIntent: () => false,
    async invokeScoped(symbol, bytes, expected) { calls.push({ symbol, epoch: expected, bytes: bytes.slice() }); return Uint8Array.of(marker); },
    walletScoped: unused, primePushTokenScoped: unused, clearPushTokenScoped: unused, openCreditPaymentScoped: unused,
    publishMessageNotice: unused, publishEncryptedWakeup: unused, copyProtectedText: unused,
    readLegacyPreference: () => null, removeLegacyPreference() {}, forgetLegacyPreferences(account) { forgotten.push(account); },
    addListener: () => ({ remove() {} }),
    async protectedFile() { return JSON.stringify({ version: 1 }); },
  };
  const scope = createAppLockSession(native, epoch);
  return { scope, calls, forgotten, services: createAppServices(scope, native, false) };
}

function desktopFixture(admission: Promise<void> = Promise.resolve()) {
  const mobile = fixture(1), operations = mobile.services;
  const calls: { symbol: string; bytes: Uint8Array }[] = [];
  const scope = createDesktopPrivateSession({
    check: () => admission,
    async invoke(symbol, bytes) { calls.push({ symbol, bytes: bytes.slice() }); return Uint8Array.of(9); },
    async invokeWallet() { throw Error('unexpected_wallet'); },
    async copyProtectedText() { throw Error('unexpected_clipboard'); },
  });
  const services = assembleAppServices({ scope, databasePath: '/owned/desktop.db',
    backups: { kind: 'unavailable' }, controls: { supportsAppLock: false, appLockEnabled: false },
    createPlatform: () => ({
      ranges: { openAttachmentRangeSource: operations.openAttachmentRangeSource, createAttachmentRangeSink: operations.createAttachmentRangeSink },
      files: { pickAttachmentFiles: operations.pickAttachmentFiles, pickAttachmentSelections: operations.pickAttachmentSelections,
        saveAttachmentFile: operations.saveAttachmentFile, attachmentPreviewUri: operations.attachmentPreviewUri,
        listenForIncomingFiles: operations.listenForIncomingFiles, releasePreviewUri: operations.releasePreviewUri, discardPreviews: operations.discardPreviews },
      avatar: { pickAvatar: operations.pickAvatar }, payments: { openCreditPayment: operations.openCreditPayment },
      notifications: { showMessageNotification: operations.showMessageNotification },
      push: { getPushStatus: operations.getPushStatus, recoverPushBinding: operations.recoverPushBinding,
        enablePushBinding: operations.enablePushBinding, disablePushBinding: operations.disablePushBinding,
        listenForPushRegistrationChanges: operations.listenForPushRegistrationChanges,
        listenForGenericWakeups: operations.listenForGenericWakeups, listenForNotificationOpens: operations.listenForNotificationOpens },
      legacyPreferences: mobile.scope,
    }),
  });
  return { mobile, scope, calls, services, close() { scope.dispose(); mobile.scope.dispose(); } };
}

test('app service construction exposes operations without exposing raw session authority', () => {
  const f = fixture(1);
  try {
    for (const key of Object.keys(f.scope)) if (key !== 'copyProtectedText') {
      assert.equal(key in f.services, false, `${key} must remain owned by the platform lifetime`);
    }
    assert.equal(typeof f.services.load_profile_export, 'function');
    assert.equal(typeof f.services.copyProtectedText, 'function');
  } finally { f.scope.dispose(); }
});

test('constructed app operations retain their captured native port and refuse after its disposal', async () => {
  const first = fixture(1), second = fixture(2); const request = Uint8Array.of(7);
  try {
    assert.deepEqual(await first.services.load_profile_export(request), Uint8Array.of(1));
    assert.deepEqual(await second.services.load_profile_export(request), Uint8Array.of(2));
    assert.deepEqual(first.calls, [{ symbol: 'mesh_messenger_load_profile', epoch, bytes: request }]);
    assert.deepEqual(second.calls, first.calls);
    first.scope.dispose();
    await assert.rejects(first.services.load_profile_export(request), /stale_epoch/);
    assert.equal(first.calls.length, 1);
    assert.deepEqual(await second.services.load_profile_export(request), Uint8Array.of(2));
  } finally { first.scope.dispose(); second.scope.dispose(); }
});

test('legacy platform methods cannot replace the assembled desktop admission check', async () => {
  const admission = Promise.withResolvers<void>(), f = desktopFixture(admission.promise);
  const pending = f.services.forgetPreferences('owned-account');
  try {
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.deepEqual(f.mobile.forgotten, [], 'legacy erasure must wait for the assembled session admission');
    admission.resolve(); await pending;
    assert.deepEqual(f.mobile.forgotten, ['owned-account']);
  } finally { admission.resolve(); await pending; f.close(); }
});

test('the common assembler uses the captured asynchronous desktop session', async () => {
  const f = desktopFixture(), request = Uint8Array.of(7);
  try {
    assert.equal(f.services.databasePath, '/owned/desktop.db');
    assert.equal(f.services.backups.kind, 'unavailable');
    assert.equal(f.services.supportsAppLock, false);
    assert.equal('setAppLockEnabled' in f.services, false);
    assert.deepEqual(await f.services.load_profile_export(request), Uint8Array.of(9));
    assert.deepEqual(f.calls, [{ symbol: 'mesh_messenger_load_profile', bytes: request }]);
    assert.deepEqual(f.mobile.calls, []);
    f.scope.dispose();
    await assert.rejects(f.services.load_profile_export(request), /stale_epoch/);
    assert.equal(f.calls.length, 1);
  } finally { f.close(); }
});
