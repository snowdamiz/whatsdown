import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@tauri-apps/api/core') return { shortCircuit: true, url: 'data:text/javascript,export const invoke = async () => { throw Error("unexpected native save"); };' };
  if (specifier === './attachment-range-io' && context.parentURL?.includes('/attachment-io.web.ts')) return next('./attachment-range-io.web.ts', context);
  return next(specifier, context);
} });
const io = await import('./attachment-io.web.ts');

test('large picker selections retain a bounded source and never read the whole Blob', async () => {
  let whole = 0; const ranges: number[] = [];
  const file = { name: 'large.bin', type: 'application/octet-stream', size: 536_870_912,
    arrayBuffer: async () => { whole++; throw Error('whole-file read forbidden'); },
    slice: (start: number, end: number) => ({ arrayBuffer: async () => { ranges.push(end - start); return new ArrayBuffer(end - start); } }),
  } as unknown as File;
  const selected = await io.fileToAttachmentSelection(file);
  assert.equal(selected.kind, 'large');
  assert.equal(selected.size, 536_870_912);
  assert.equal(whole, 0);
  if (selected.kind !== 'large') throw Error('expected large source');
  assert.equal((await selected.source.read(536_805_376, 65_536)).length, 65_536);
  assert.deepEqual(ranges, [65_536]);
  selected.dispose(); selected.dispose();
  await assert.rejects(selected.source.read(0, 1), /closed/);
});

test('small selections keep the free path and oversized selections fail before reading', async () => {
  const small = new File([Uint8Array.of(1, 2, 3)], 'a.txt', { type: 'text/plain' });
  const selected = await io.fileToAttachmentSelection(small);
  assert.equal(selected.kind, 'small');
  if (selected.kind !== 'small') throw Error('expected free bytes');
  assert.deepEqual(selected.bytes, Uint8Array.of(1, 2, 3));
  let read = false;
  const oversized = { name: 'too-big.bin', type: '', size: 536_870_913, arrayBuffer: async () => { read = true; return new ArrayBuffer(0); } } as File;
  await assert.rejects(io.fileToAttachmentSelection(oversized), /512/);
  assert.equal(read, false);
});
