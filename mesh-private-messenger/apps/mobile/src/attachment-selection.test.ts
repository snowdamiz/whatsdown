import assert from 'node:assert/strict';
import test from 'node:test';
import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';

const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const { createScopedBindings } = await import('../modules/mesh-messenger/scoped.ts');
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const metadata = (value: object) => JSON.stringify({ version: 1, ...value });
function fixture(size: number, duplicate = false) {
  let closed = 0, claims = 0; const reads: number[] = [], replies: Uint8Array[] = [];
  const original = Uint8Array.of(1, 2, 3);
  const f = scopeFixture({ async protectedFile(operation: string, serialized: string, _bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch); const frame = JSON.parse(serialized);
    switch (operation) {
      case 'pendingChoice': assert.equal(frame.purpose, 'attachment'); return metadata({});
      case 'chooseSource': {
        const file = { selectionId: id(2), filename: size > 16_777_216 ? 'large.bin' : 'small.txt', mimeType: 'application/octet-stream', size };
        return metadata({ choiceId: id(1), files: duplicate ? [file, file] : [file] });
      }
      case 'claimSource':
        assert.equal(frame.choiceId, id(1)); assert.equal(frame.selectionId, id(2)); assert.equal(frame.size, size);
        claims++; return metadata({ handle: id(3), size });
      case 'readSource': {
        assert.equal(frame.handle, id(3)); assert.ok(frame.length <= 65_536); reads.push(frame.length);
        const bytes = size === 3 ? original.slice(frame.offset, frame.offset + frame.length) : new Uint8Array(frame.length);
        replies.push(bytes); return bytes;
      }
      case 'closeSource': assert.equal(frame.handle, id(3)); closed++; return metadata({});
      case 'discardPreviews': return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const client = { ...f.scope, ...createScopedBindings(f.scope) };
  const io = createAttachmentFileServices({ ...client, ...createAttachmentRangeServices(client) });
  return { ...f, io, reads, replies, original, get closed() { return closed; }, get claims() { return claims; } };
}

test('native picker keeps a large owned source until bounded staging finishes or selection is dismissed', async () => {
  const f = fixture(536_870_912);
  try {
    const selections = await f.io.pickAttachmentSelections(); assert.equal(selections.length, 1);
    const selected = selections[0]; assert.ok(selected); assert.equal(selected.kind, 'large');
    assert.deepEqual(f.reads, []); assert.equal(f.closed, 0); assert.equal(f.claims, 1);
    if (selected.kind !== 'large') throw Error('expected large source');
    assert.equal((await selected.source.read(0, 65_536)).length, 65_536); assert.deepEqual(f.reads, [65_536]);
    selected.dispose(); selected.dispose(); assert.equal(f.closed, 1);
    await assert.rejects(selected.source.read(0, 1), /closed/);
  } finally { f.scope.dispose(); }
});

test('native small selection copies bounded bytes, wipes provider chunks and closes its picker source', async () => {
  const f = fixture(3);
  try {
    const selections = await f.io.pickAttachmentSelections(), selected = selections[0]; assert.ok(selected);
    assert.equal(selected.kind, 'small'); assert.deepEqual(f.reads, [3]); assert.equal(f.closed, 1);
    if (selected.kind !== 'small') throw Error('expected small bytes');
    assert.deepEqual(selected.bytes, Uint8Array.of(1, 2, 3));
    assert.ok(f.replies.every(bytes => bytes.every(byte => byte === 0)));
    selected.dispose(); assert.deepEqual(selected.bytes, new Uint8Array(3)); assert.deepEqual(f.original, Uint8Array.of(1, 2, 3));
  } finally { f.scope.dispose(); }
});

test('duplicate native picker selection IDs are refused before a source is claimed or read', async () => {
  const f = fixture(3, true);
  try {
    await assert.rejects(f.io.pickAttachmentSelections(), /invalid_file_response/);
    assert.equal(f.claims, 0); assert.deepEqual(f.reads, []); assert.equal(f.closed, 0);
  } finally { f.scope.dispose(); }
});
