import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test, { type TestContext } from 'node:test';
import type { IncomingAttachmentReader } from './attachment-io.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL); if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const id = '00000000-0000-4000-8000-000000000001', subscription = '00000000-0000-4000-8000-000000000002';
function fixture(t: TestContext) {
  const calls: { operation: string; context: unknown }[] = [];
  const state = { empty: false, retireOnRead: false, raw: Uint8Array.of(1, 2, 3) };
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ async check() {}, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const deps = { ...scope, async protectedFile(operation: string, context: unknown) {
    calls.push({ operation, context });
    if (operation === 'pendingChoice') return JSON.stringify(state.empty ? { version: 1 } : { version: 1, choiceId: id, files: [{ selectionId: id, filename: 'file.bin', mimeType: 'application/octet-stream', size: 3 }] });
    if (operation === 'claimSource') return JSON.stringify({ version: 1, handle: id, size: 3 });
    if (operation === 'readSource') { if (state.retireOnRead) scope.dispose(); return state.raw; }
    throw Error('unexpected_' + operation);
  }, async cleanupProtectedFile(operation: string, context: unknown) { calls.push({ operation, context }); } };
  let captured: IncomingAttachmentReader | undefined;
  const files = createAttachmentFileServices({ ...deps, ...createAttachmentRangeServices(deps) }, { previewTransport: 'desktop', incoming: { listen(_handlers, read) { captured = read; return () => {}; } } });
  files.listenForIncomingFiles({ onDragging() {}, onFiles() {}, onError() {} });
  assert.ok(captured); const read = captured;
  t.after(() => { scope.dispose(); });
  return { state, calls, scope, read, deps };
}
test('native intake reads only the pending choice for its captured subscription', async t => {
  const f = fixture(t), selections = await f.read(subscription);
  try {
    assert.deepEqual(f.calls[0], { operation: 'pendingChoice', context: { version: 1, purpose: 'attachment', subscription } });
    assert.equal(selections.length, 1); const first = selections[0]; assert.equal(first?.kind, 'small');
    if (first?.kind !== 'small') throw Error('expected_small');
    assert.deepEqual(first.bytes, Uint8Array.of(1, 2, 3));
    assert.deepEqual(f.calls.map(call => call.operation), ['pendingChoice', 'claimSource', 'readSource', 'closeSource']);
  } finally { for (const selection of selections) selection.dispose(); }
});
test('an empty native intake does not open a chooser or reuse an older explicit action', async t => {
  const f = fixture(t); f.state.empty = true;
  assert.deepEqual(await f.read(subscription), []);
  assert.deepEqual(f.calls, [{ operation: 'pendingChoice', context: { version: 1, purpose: 'attachment', subscription } }]);
});
test('invalid incoming subscription selectors refuse before any native file operation', async t => {
  const f = fixture(t); await assert.rejects(f.read('../file'));
  assert.equal(f.calls.length, 0);
});
test('native intake remains scoped and erases a late plaintext chunk', async t => {
  const f = fixture(t); f.state.retireOnRead = true;
  await assert.rejects(f.read(subscription), /stale_epoch/);
  assert.deepEqual(f.state.raw, new Uint8Array(3));
  assert.equal(f.calls.filter(call => call.operation === 'closeSource').length, 1);
  const before = f.calls.length; await assert.rejects(f.read(subscription), /stale_epoch/); assert.equal(f.calls.length, before);
});
test('mobile default installs no desktop native intake subscription', async t => {
  const f = fixture(t); f.calls.length = 0;
  const mobile = createAttachmentFileServices({ ...f.deps, ...createAttachmentRangeServices(f.deps) });
  const close = mobile.listenForIncomingFiles({ onDragging() {}, onFiles() {}, onError() {} }); close();
  assert.equal(f.calls.length, 0);
});
