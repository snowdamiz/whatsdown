import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createAppLockSession, type AppLockNativePort } from './app-lock.ts';

registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const { createAttachmentFileServices } = await import('./attachment-io.ts');
const epoch = '00000000-0000-4000-8000-000000000001';
const newer = '00000000-0000-4000-8000-000000000002';
const id = '00000000-0000-4000-8000-000000000003';
type Kind = 'source' | 'sink' | 'preview';
const kinds: readonly Kind[] = ['source', 'sink', 'preview'];
const createOperation: Record<Kind, string> = { source: 'claimSource', sink: 'beginExport', preview: 'writePreview' };
const discardOperation: Record<Kind, string> = { source: 'closeSource', sink: 'abortExport', preview: 'releasePreview' };
type FileCall = { operation: string; frame: unknown; byteLength: number; epoch: string };
function fixture(kind: Kind) {
  const entered = Promise.withResolvers<void>(); const gate = Promise.withResolvers<void>();
  const calls: FileCall[] = []; const resources = new Map<string, string>();
  const state = { current: epoch, hold: true, allocateBeforeWait: false, cleanupFails: false,
    response: JSON.stringify(kind === 'source' ? { version: 1, handle: id, size: 3 }
      : kind === 'preview' ? { version: 1, handle: id, uri: 'file:///owned/preview.jpg' }
      : { version: 1, handle: id }) };
  const unused = async (): Promise<never> => { throw Error('unexpected_native_operation'); };
  const native: AppLockNativePort = {
    getAppLockState: unused, authenticateAppLock: unused, setAppLockEnabled: unused,
    cancelAppLockAuthentication: unused, lockApp: unused, activateAppLockScope: unused,
    checkAppLockScope(expected) { if (expected !== state.current) throw Error('stale_epoch'); },
    consumeAppLockInboxIntent: () => false, invokeScoped: unused, walletScoped: unused,
    primePushTokenScoped: unused, clearPushTokenScoped: unused, openCreditPaymentScoped: unused,
    publishMessageNotice: unused, publishEncryptedWakeup: unused, copyProtectedText: unused,
    readLegacyPreference: () => null, removeLegacyPreference() {}, forgetLegacyPreferences() {},
    addListener: () => ({ remove() {} }),
    async protectedFile(operation, frame, bytes, expected) {
      const context: unknown = JSON.parse(frame);
      calls.push({ operation, frame: context, byteLength: bytes.length, epoch: expected });
      if (operation === createOperation[kind]) {
        if (state.allocateBeforeWait) resources.set(id, expected);
        entered.resolve(); if (state.hold) await gate.promise;
        if (!state.allocateBeforeWait) resources.set(id, expected);
        return state.response;
      }
      if (operation === 'pendingChoice') return JSON.stringify({ version: 1, choiceId: id });
      if (operation === 'discardPreviews') {
        for (const [handle, owner] of resources) if (owner === expected) resources.delete(handle);
        return JSON.stringify({ version: 1 });
      }
      if (operation === discardOperation[kind]) {
        assert.deepEqual(context, { version: 1, handle: id }); assert.equal(bytes.length, 0);
        if (state.cleanupFails) throw Error('private_cleanup_detail');
        if (resources.get(id) === expected) resources.delete(id);
        return JSON.stringify({ version: 1 });
      }
      throw Error('unexpected_file_operation');
    },
  };
  const scope = createAppLockSession(native, epoch);
  const ranges = createAttachmentRangeServices(scope);
  const files = kind === 'preview' ? createAttachmentFileServices({ ...scope, ...ranges }) : undefined;
  function start() {
    switch (kind) {
      case 'source': return ranges.openAttachmentRangeSource(id, id, 3);
      case 'sink': return ranges.createAttachmentRangeSink('file.bin', 'application/octet-stream', 3, 'object/ref');
      case 'preview': assert.ok(files); return files.attachmentPreviewUri('preview', 'image/jpeg', Uint8Array.of(1, 2, 3));
    }
  }
  function closeValue(value: Awaited<ReturnType<typeof start>>) {
    if (typeof value === 'string') { assert.ok(files); files.releasePreviewUri(value); }
    else if (value && 'close' in value) value.close();
    else { assert.ok(value); return value.abort(); }
  }
  return { state, calls, resources, entered, gate, native, scope, start, closeValue };
}

for (const kind of kinds) test(`${kind}: inner native completion cleans a resource created after same-epoch local disposal`, async () => {
  const f = fixture(kind); const pending = f.start(); const rejected = assert.rejects(pending, /stale_epoch/);
  try {
    await f.entered.promise; f.scope.dispose(); assert.equal(f.state.current, epoch);
    f.gate.resolve(); await rejected;
    const cleanup = f.calls.filter(call => call.operation === discardOperation[kind]);
    assert.equal(cleanup.length, 1, 'late native ownership must be discarded at the inner completion fence');
    assert.deepEqual(cleanup[0], { operation: discardOperation[kind], frame: { version: 1, handle: id }, byteLength: 0, epoch });
    assert.equal(f.resources.size, 0);
  } finally { f.gate.resolve(); f.scope.dispose(); f.resources.clear(); }
});

for (const kind of kinds) test(`${kind}: ordinary successful file ownership is unchanged`, async () => {
  const f = fixture(kind); f.state.hold = false;
  try {
    const value = await f.start(); assert.ok(value);
    assert.equal(f.calls.filter(call => call.operation === discardOperation[kind]).length, 0);
    assert.equal(f.resources.get(id), epoch);
    if (kind === 'preview') assert.equal(value, 'file:///owned/preview.jpg');
    else assert.equal(typeof value, 'object');
    await f.closeValue(value); assert.equal(f.resources.size, 0);
  } finally { f.scope.dispose(); f.resources.clear(); }
});

test('inner cleanup failure preserves stale_epoch and hides cleanup detail', async () => {
  const f = fixture('source'); f.state.cleanupFails = true;
  const pending = f.start(); const rejected = assert.rejects(pending, error => error instanceof Error && error.message === 'stale_epoch' && error.cause === undefined);
  try {
    await f.entered.promise; f.scope.dispose(); f.gate.resolve(); await rejected;
    assert.equal(f.calls.filter(call => call.operation === 'closeSource').length, 1, 'cleanup must be attempted despite local disposal');
  } finally { f.gate.resolve(); f.scope.dispose(); f.resources.clear(); }
});

test('native revocation cleanup uses captured epoch and cannot discard a fresh owner', async () => {
  const f = fixture('sink'); f.state.allocateBeforeWait = true;
  const pending = f.start(); const rejected = assert.rejects(pending, /stale_epoch/);
  try {
    await f.entered.promise;
    // Native retired the old handle; a later owner is not cleanup authority for this scope.
    f.resources.set(id, newer); f.state.current = newer; f.gate.resolve(); await rejected;
    const cleanup = f.calls.filter(call => call.operation === 'abortExport');
    assert.equal(cleanup.length, 1, 'native completion refusal must still narrow cleanup to the original epoch');
    assert.equal(cleanup[0]?.epoch, epoch); assert.deepEqual(cleanup[0]?.frame, { version: 1, handle: id });
    assert.equal(f.resources.get(id), newer);
  } finally { f.gate.resolve(); f.scope.dispose(); f.resources.clear(); }
});

for (const kind of kinds) test(`${kind}: malformed native metadata never forges cleanup authority`, async () => {
  const f = fixture(kind);
  f.state.response = kind === 'source' ? JSON.stringify({ version: 1, handle: id, size: 3, operation: 'writeExport' })
    : kind === 'sink' ? JSON.stringify({ version: 1, handle: '../forged' })
    : JSON.stringify({ version: 1, handle: id, uri: 'file:///owned/preview.jpg', authority: 'forged' });
  const pending = f.start(); const rejected = assert.rejects(pending, error => error instanceof Error && error.message === 'stale_epoch');
  try {
    await f.entered.promise; f.scope.dispose(); f.gate.resolve(); await rejected;
    assert.equal(f.calls.filter(call => call.operation === discardOperation[kind]).length, 0);
    assert.ok(f.calls.every(call => call.operation === createOperation[kind] || call.operation === 'pendingChoice' || call.operation === 'discardPreviews'));
  } finally { f.gate.resolve(); f.scope.dispose(); f.resources.clear(); /* Native owner ultimately retires malformed resources. */ }
});

test('default private completion still wipes a late Uint8Array without file cleanup', async () => {
  const f = fixture('source'); const bytes = Uint8Array.of(1, 2, 3);
  f.native.invokeScoped = async () => { f.entered.resolve(); await f.gate.promise; return bytes; };
  const pending = f.scope.invoke('owned_fixture', new Uint8Array()); const rejected = assert.rejects(pending, /stale_epoch/);
  try {
    await f.entered.promise; f.scope.dispose(); f.gate.resolve(); await rejected;
    assert.deepEqual(bytes, new Uint8Array(3)); assert.deepEqual(f.calls, []);
  } finally { f.gate.resolve(); f.scope.dispose(); }
});
