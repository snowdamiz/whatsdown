import assert from 'node:assert/strict';
import test from 'node:test';
import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';

const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const { createScopedBindings } = await import('../modules/mesh-messenger/scoped.ts');
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const metadata = (value: object) => JSON.stringify({ version: 1, ...value });

test('scoped range reader handles a 512MiB native choice with only requested 64KiB reads and closes once', async () => {
  let size = 536_870_912, closed = 0;
  const reads: number[] = [];
  const f = scopeFixture({ async protectedFile(operation: string, serialized: string, _bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch); const frame = JSON.parse(serialized);
    switch (operation) {
      case 'claimSource': assert.equal(frame.choiceId, id(1)); assert.equal(frame.selectionId, id(2)); return metadata({ handle: id(3), size });
      case 'readSource':
        assert.equal(frame.handle, id(3)); reads.push(frame.length);
        if (size !== 536_870_912) throw Error('attachment_source_changed');
        assert.equal(frame.offset, 536_805_376); return new Uint8Array(frame.length);
      case 'closeSource': assert.equal(frame.handle, id(3)); closed++; return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const io = createAttachmentRangeServices({ ...f.scope, ...createScopedBindings(f.scope) });
  const source = await io.openAttachmentRangeSource(id(1), id(2), size);
  try {
    assert.equal(source.size, 536_870_912);
    assert.equal((await source.read(536_805_376, 65_536)).length, 65_536);
    await assert.rejects(source.read(0, 65_537), /range/); assert.deepEqual(reads, [65_536]);
    size--; await assert.rejects(source.read(0, 1), /changed/);
    source.close(); source.close(); assert.equal(closed, 1);
    await assert.rejects(source.read(0, 1), /closed/);
  } finally { source.close(); f.scope.dispose(); }
});

test('scoped sink bounds writes, commits completed files, and aborts incomplete output without deleting a saved file', async () => {
  let cancelled = false, deleted = 0, written = 0, committed = 0, choices = 0, next = 10;
  const aborted = new Set<string>();
  const f = scopeFixture({ async protectedFile(operation: string, serialized: string, bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch); const frame = JSON.parse(serialized);
    switch (operation) {
      case 'pendingChoice': return metadata({});
      case 'chooseDestination': choices++; return metadata(cancelled ? { cancelled: true } : { choiceId: id(4) });
      case 'beginExport': assert.equal(frame.choiceId, id(4)); assert.equal(frame.sourceContext, 'attachment/object'); return metadata({ handle: id(next++) });
      case 'writeExport': written += bytes.length; return metadata({});
      case 'commitExport': committed++; return metadata({});
      case 'abortExport': if (!aborted.has(frame.handle)) { aborted.add(frame.handle); deleted++; } return metadata({});
      default: throw Error(`unexpected provider operation ${operation}`);
    }
  } });
  const io = createAttachmentRangeServices({ ...f.scope, ...createScopedBindings(f.scope) });
  try {
    await assert.rejects(io.createAttachmentRangeSink('../outside.bin', 'application/octet-stream', 7, 'attachment/object'), /name/);
    assert.equal(choices, 0);
    let sink = await io.createAttachmentRangeSink('saved.bin', 'application/octet-stream', 7, 'attachment/object'); assert.ok(sink);
    await assert.rejects(sink.write(1, Uint8Array.of(1)), /range/); assert.equal(written, 0);
    await sink.write(0, Uint8Array.of(1, 2, 3)); await assert.rejects(sink.finish(), /incomplete/); assert.equal(committed, 0);
    await sink.abort(); await sink.abort(); assert.equal(deleted, 1);
    sink = await io.createAttachmentRangeSink('saved.bin', 'application/octet-stream', 4, 'attachment/object'); assert.ok(sink);
    await sink.write(0, Uint8Array.of(1, 2, 3, 4)); await sink.finish(); await sink.abort();
    assert.equal(deleted, 1); assert.equal(committed, 1); assert.equal(written, 7);
    cancelled = true; assert.equal(await io.createAttachmentRangeSink('saved.bin', 'application/octet-stream', 4, 'attachment/object'), null);
    assert.equal(committed, 1);
  } finally { f.scope.dispose(); }
});

test('native revoke before a pending range reply rejects and wipes the returned bytes before any JS event', async () => {
  const reply = Promise.withResolvers<Uint8Array>(); let closed = 0;
  const f = scopeFixture({ async protectedFile(operation: string, _frame: string, _bytes: Uint8Array, epoch: string) {
    assert.equal(epoch, f.scope.epoch);
    if (operation === 'claimSource') return metadata({ handle: id(3), size: 3 });
    if (operation === 'readSource') return reply.promise;
    if (operation === 'closeSource') { closed++; return metadata({}); }
    throw Error(`unexpected provider operation ${operation}`);
  } });
  const io = createAttachmentRangeServices({ ...f.scope, ...createScopedBindings(f.scope) });
  const source = await io.openAttachmentRangeSource(id(1), id(2), 3);
  try {
    const pending = source.read(0, 3); f.revoke();
    const privateReply = Uint8Array.of(7, 8, 9); reply.resolve(privateReply);
    await assert.rejects(pending, /stale_epoch/); assert.deepEqual(privateReply, new Uint8Array(3));
    source.close(); source.close(); assert.equal(closed, 1);
  } finally { source.close(); f.scope.dispose(); }
});
