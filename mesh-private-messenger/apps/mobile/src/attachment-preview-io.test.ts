import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';

const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const { createScopedBindings } = await import('../modules/mesh-messenger/scoped.ts');
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const metadata = (value: object) => JSON.stringify({ version: 1, ...value });

test('native-owned same-object previews have independent files and scoped release leaves completed saves alone', async () => {
  const saved = 'file:///saved/photo.png';
  const files = new Map<string, { kind: 'preview' | 'saved'; bytes: Uint8Array }>([
    [saved, { kind: 'saved', bytes: Uint8Array.of(99) }],
  ]);
  let next = 1, released = 0;
  const f = scopeFixture({ async protectedFile(operation: string, serialized: string, bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch); const frame = JSON.parse(serialized);
    switch (operation) {
      case 'writePreview': {
        assert.equal(frame.key, 'same'); const handle = id(next++);
        files.set(handle, { kind: 'preview', bytes: new Uint8Array(bytes) }); return metadata({ handle, uri: `file:///native-preview/${handle}.png` });
      }
      case 'releasePreview': assert.equal(files.get(frame.handle)?.kind, 'preview'); released++; files.delete(frame.handle); return metadata({});
      case 'discardPreviews': for (const [key, value] of files) if (value.kind === 'preview') files.delete(key); return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const client = { ...f.scope, ...createScopedBindings(f.scope) };
  const io = createAttachmentFileServices({ ...client, ...createAttachmentRangeServices(client) });
  try {
    const a = await io.attachmentPreviewUri('same', 'image/png', Uint8Array.of(1));
    const b = await io.attachmentPreviewUri('same', 'image/png', Uint8Array.of(2));
    assert.notEqual(a, b); assert.deepEqual([...files.values()].filter(file => file.kind === 'preview').map(file => file.bytes), [Uint8Array.of(1), Uint8Array.of(2)]);
    io.releasePreviewUri(a); io.releasePreviewUri(a); assert.equal(released, 1);
    assert.deepEqual([...files.values()].filter(file => file.kind === 'preview').map(file => file.bytes), [Uint8Array.of(2)]);
    io.discardPreviews(); assert.deepEqual([...files], [[saved, { kind: 'saved', bytes: Uint8Array.of(99) }]]);
  } finally { f.scope.dispose(); }
});

test('closing while the native destination chooser is open never publishes zeroed preview bytes', async () => {
  const choose = Promise.withResolvers<string>(), choosing = Promise.withResolvers<void>();
  let writes = 0, commits = 0, aborts = 0;
  const f = scopeFixture({ async protectedFile(operation: string, _serialized: string, bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch);
    switch (operation) {
      case 'digest': return metadata({ digest: createHash('sha256').update(bytes).digest('hex') });
      case 'pendingChoice': return metadata({});
      case 'chooseDestination': choosing.resolve(); return choose.promise;
      case 'beginExport': return metadata({ handle: id(2) });
      case 'writeExport': writes++; return metadata({});
      case 'commitExport': commits++; return metadata({});
      case 'abortExport': aborts++; return metadata({});
      case 'discardPreviews': return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const client = { ...f.scope, ...createScopedBindings(f.scope) };
  const io = createAttachmentFileServices({ ...client, ...createAttachmentRangeServices(client) });
  const controller = new AbortController(), bytes = Uint8Array.of(4, 5);
  try {
    const pending = io.saveAttachmentFile('cancelled.png', 'image/png', bytes, controller.signal);
    await choosing.promise; controller.abort(); bytes.fill(0); choose.resolve(metadata({ choiceId: id(1) }));
    assert.equal(await pending, false); assert.equal(writes, 0); assert.equal(commits, 0); assert.equal(aborts, 1);
  } finally { f.scope.dispose(); }
});
