import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import { AttachmentPreviewSession } from './attachment-preview-session.ts';

const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createScopedBindings } = await import('../modules/mesh-messenger/scoped.ts');
const choice = '00000000-0000-4000-8000-000000000001', handle = '00000000-0000-4000-8000-000000000002';
const metadata = (value: object) => JSON.stringify({ version: 1, ...value });
function fixture() {
  const choose = Promise.withResolvers<string>(), choosing = Promise.withResolvers<void>();
  const writes: Uint8Array[] = []; let commits = 0, aborts = 0;
  const f = scopeFixture({ async protectedFile(operation: string, serialized: string, bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch); const frame = JSON.parse(serialized);
    switch (operation) {
      case 'digest': return metadata({ digest: createHash('sha256').update(bytes).digest('hex') });
      case 'pendingChoice': return metadata({});
      case 'chooseDestination': choosing.resolve(); return choose.promise;
      case 'beginExport': assert.equal(frame.choiceId, choice); return metadata({ handle });
      case 'writeExport': writes.push(new Uint8Array(bytes)); return metadata({});
      case 'commitExport': commits++; return metadata({});
      case 'abortExport': aborts++; return metadata({});
      case 'discardPreviews': return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const client = { ...f.scope, ...createScopedBindings(f.scope) };
  const io = createAttachmentFileServices({ ...client, ...createAttachmentRangeServices(client) });
  return { ...f, io, choose, choosing, writes, get commits() { return commits; }, get aborts() { return aborts; } };
}

test('expiry during the native destination picker aborts before staging any retained preview bytes', async () => {
  const f = fixture(), session = new AttachmentPreviewSession('group/a', () => {}, () => {});
  session.restrictTo(['object']); session.remember('object', Uint8Array.of(1, 2));
  assert.equal(session.begin('object'), true);
  const signal = session.requestSignal('object'), held = session.retain('object'); assert.ok(held);
  try {
    const pending = f.io.saveAttachmentFile('fixture.bin', 'application/octet-stream', held.bytes, signal);
    await f.choosing.promise; session.restrictTo([]); assert.equal(signal.aborted, true);
    f.choose.resolve(metadata({ choiceId: choice }));
    assert.equal(await pending, false); assert.equal(f.commits, 0); assert.equal(f.aborts, 1);
    assert.deepEqual(f.writes, []); assert.deepEqual(held.bytes, new Uint8Array(2));
  } finally { held.release(); session.close(); f.scope.dispose(); }
});

test('a completed explicit scoped save and separately owned composer bytes survive preview expiry', async () => {
  const f = fixture(), composer = Uint8Array.of(3, 4), session = new AttachmentPreviewSession('chat/a', () => {}, () => {});
  session.restrictTo(['object']); session.remember('object', new Uint8Array(composer)); assert.equal(session.begin('object'), true);
  const bytes = session.bytes('object'); assert.ok(bytes);
  try {
    const pending = f.io.saveAttachmentFile('fixture.bin', 'application/octet-stream', bytes, session.requestSignal('object'));
    await f.choosing.promise; f.choose.resolve(metadata({ choiceId: choice }));
    assert.equal(await pending, true); assert.equal(f.commits, 1); assert.equal(f.aborts, 0);
    session.restrictTo([]); assert.deepEqual(f.writes, [Uint8Array.of(3, 4)]); assert.deepEqual(composer, Uint8Array.of(3, 4));
  } finally { session.close(); f.scope.dispose(); }
});
