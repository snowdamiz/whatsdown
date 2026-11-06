import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL); if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const id = '00000000-0000-4000-8000-000000000001';
function fixture() {
  const state = { gate: Promise.resolve() }; const calls: string[] = [];
  const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
  const scope = createDesktopPrivateSession({ check: () => state.gate, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const service = createAttachmentRangeServices({ ...scope,
    async protectedFile(operation: string) {
      calls.push(operation);
      if (operation === 'readSource') return Uint8Array.of(1, 2, 3);
      if (operation === 'pendingChoice') return JSON.stringify({ version: 1, choiceId: id });
      if (operation === 'beginExport') return JSON.stringify({ version: 1, handle: id });
      return JSON.stringify({ version: 1, handle: id, size: 3 });
    },
    async cleanupProtectedFile(operation: string) { calls.push(operation); return JSON.stringify({ version: 1 }); },
  });
  return { state, calls, scope, service };
}
test('attachment source claiming waits for asynchronous native admission', async () => {
  const f = fixture(); const gate = Promise.withResolvers<void>(); f.state.gate = gate.promise;
  const pending = f.service.openAttachmentRangeSource(id, id, 3);
  await tick(); const early = f.calls.length; gate.resolve(); const source = await pending; await tick(); source.close(); f.scope.dispose();
  assert.equal(early, 0); assert.deepEqual(f.calls, ['claimSource', 'closeSource']);
});
test('a returned attachment reader waits for current native admission', async () => {
  const f = fixture(); const source = await f.service.openAttachmentRangeSource(id, id, 3);
  const gate = Promise.withResolvers<void>(); f.state.gate = gate.promise; f.calls.length = 0;
  const pending = source.read(0, 3); await tick(); const early = f.calls.length;
  gate.resolve(); assert.deepEqual(await pending, Uint8Array.of(1, 2, 3)); await tick(); source.close(); f.scope.dispose();
  assert.equal(early, 0); assert.deepEqual(f.calls, ['readSource', 'closeSource']);
});
for (const action of ['write', 'finish'] as const) test(`a returned attachment sink waits for native admission before ${action}`, async () => {
  const f = fixture(); const sink = await f.service.createAttachmentRangeSink('file.bin', 'application/octet-stream', 3, 'object/ref'); assert.ok(sink);
  if (action === 'finish') await sink.write(0, Uint8Array.of(1, 2, 3));
  const gate = Promise.withResolvers<void>(); f.state.gate = gate.promise; f.calls.length = 0;
  const pending = action === 'write' ? sink.write(0, Uint8Array.of(1, 2, 3)) : sink.finish();
  await tick(); const early = f.calls.length; gate.resolve(); await pending; await tick(); await sink.abort(); f.scope.dispose();
  assert.equal(early, 0); assert.equal(f.calls[0], action === 'write' ? 'writeExport' : 'commitExport');
});


test('a refused native read length erases its unreturned owned plaintext', async () => {
  const f = fixture(), raw = Uint8Array.of(4, 5);
  const ranges = createAttachmentRangeServices({ ...f.scope,
    async protectedFile(operation: string) {
      return operation === 'readSource' ? raw : JSON.stringify({ version: 1, handle: id, size: 3 });
    },
    async cleanupProtectedFile() {},
  });
  const source = await ranges.openAttachmentRangeSource(id, id, 3);
  try {
    await assert.rejects(source.read(0, 3), /attachment_source_changed/);
    assert.deepEqual(raw, new Uint8Array(2));
  } finally { source.close(); f.scope.dispose(); }
});

test('a valid native read transfers unchanged bytes to its caller', async () => {
  const f = fixture(), raw = Uint8Array.of(4, 5, 6);
  const ranges = createAttachmentRangeServices({ ...f.scope,
    async protectedFile(operation: string) {
      return operation === 'readSource' ? raw : JSON.stringify({ version: 1, handle: id, size: 3 });
    },
    async cleanupProtectedFile() {},
  });
  const source = await ranges.openAttachmentRangeSource(id, id, 3);
  try {
    const bytes = await source.read(0, 3);
    assert.equal(bytes, raw);
    assert.deepEqual(raw, Uint8Array.of(4, 5, 6));
  } finally { raw.fill(0); source.close(); f.scope.dispose(); }
});
