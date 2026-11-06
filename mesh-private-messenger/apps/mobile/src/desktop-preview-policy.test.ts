import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test, { type TestContext } from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(specifier + '.ts', context.parentURL); if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const handle = '61616161-6262-6363-6464-656565656565';
const other = '71717171-7272-7373-7474-757575757575';
function fixture(t: TestContext) {
  const unused = async (): Promise<never> => { throw Error('unexpected_operation'); };
  const scope = createDesktopPrivateSession({ async check() {}, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const state = { uri: 'file:///owned/preview.png' };
  const cleanup: { operation: string; context: unknown }[] = [];
  const deps = { ...scope,
    async protectedFile() { return JSON.stringify({ version: 1, handle, uri: state.uri }); },
    async cleanupProtectedFile(operation: string, context: unknown) { cleanup.push({ operation, context }); },
  };
  t.after(() => { scope.dispose(); });
  return { scope, state, cleanup, deps: { ...deps, ...createAttachmentRangeServices(deps) } };
}
test('desktop previews accept only the opaque URI for their native handle and release by handle', async t => {
  const f = fixture(t); f.state.uri = 'morse-private://preview/' + handle;
  const service = createAttachmentFileServices(f.deps, { previewTransport: 'desktop' });
  const uri = await service.attachmentPreviewUri('key', 'image/png', Uint8Array.of(1));
  assert.equal(uri, f.state.uri);
  service.releasePreviewUri(uri);
  assert.deepEqual(f.cleanup, [{ operation: 'releasePreview', context: { version: 1, handle } }]);
});
test('desktop rejects file, remote, cross-handle and decorated preview URIs and releases the owned handle', async t => {
  const f = fixture(t), service = createAttachmentFileServices(f.deps, { previewTransport: 'desktop' });
  for (const uri of ['file:///owned/preview.png', 'https://example.test/image', 'morse-private://preview/' + other,
    'morse-private://preview/' + handle + '?read=1', 'morse-private://preview/' + handle + '#image']) {
    f.state.uri = uri; f.cleanup.length = 0;
    await assert.rejects(service.attachmentPreviewUri('key', 'image/png', Uint8Array.of(1)), /invalid_file_response/);
    assert.deepEqual(f.cleanup, [{ operation: 'releasePreview', context: { version: 1, handle } }]);
  }
});
test('the mobile default retains file previews and refuses desktop scheme replies', async t => {
  const f = fixture(t), service = createAttachmentFileServices(f.deps);
  assert.equal(await service.attachmentPreviewUri('key', 'image/png', Uint8Array.of(1)), f.state.uri);
  service.releasePreviewUri(f.state.uri); f.cleanup.length = 0;
  f.state.uri = 'morse-private://preview/' + handle;
  await assert.rejects(service.attachmentPreviewUri('key', 'image/png', Uint8Array.of(1)), /invalid_file_response/);
  assert.deepEqual(f.cleanup, [{ operation: 'releasePreview', context: { version: 1, handle } }]);
});
