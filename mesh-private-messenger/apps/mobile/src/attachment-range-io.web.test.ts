import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const calls: { name: string; body: unknown; options: unknown }[] = [];
let cancel = false;
Object.assign(globalThis, { __rangeInvoke: async (name: string, body: unknown, options: unknown) => {
  calls.push({ name, body, options });
  if (name === 'begin_attachment_save') return cancel ? null : 7;
} });
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@tauri-apps/api/core') return { shortCircuit: true, url: 'data:text/javascript,export const invoke = globalThis.__rangeInvoke;' };
  return next(specifier, context);
} });
const io = await import('./attachment-range-io.web.ts');

test('web range source slices a large selected file without reading its whole Blob', async () => {
  const ranges: [number, number][] = [];
  const file = { size: 536_870_912, arrayBuffer: () => { throw new Error('whole-file read'); },
    slice: (start: number, end: number) => { ranges.push([start, end]); return { arrayBuffer: async () => new ArrayBuffer(end - start) }; } } as unknown as Blob;
  const source = io.openAttachmentRangeSource(file);
  assert.equal((await source.read(536_805_376, 65_536)).length, 65_536);
  assert.deepEqual(ranges, [[536_805_376, 536_870_912]]);
  await assert.rejects(source.read(0, 65_537), /range/);
  source.close(); await assert.rejects(source.read(0, 1), /closed/);
});

test('desktop output uses the chosen native handle with bounded offsets and finalization', async () => {
  const sink = await io.createAttachmentRangeSink('café.bin', 'application/octet-stream', 5);
  assert(sink);
  assert.deepEqual(calls[0]!.body, Uint8Array.of(0, 0, 0, 5));
  assert.deepEqual(calls[0]!.options, { headers: { 'X-File-Name': 'caf%C3%A9.bin' } });
  await sink.write(0, Uint8Array.of(1, 2));
  await assert.rejects(sink.write(0, Uint8Array.of(3)), /range/);
  await assert.rejects(sink.finish(), /incomplete/);
  await sink.write(2, Uint8Array.of(3, 4, 5)); await sink.finish(); await sink.abort();
  assert.deepEqual(calls.filter(c => c.name === 'write_attachment_range').map(c => c.options), [
    { headers: { 'X-Attachment-Id': '7', 'X-Attachment-Offset': '0' } },
    { headers: { 'X-Attachment-Id': '7', 'X-Attachment-Offset': '2' } },
  ]);
  assert(!calls.some(c => c.name === 'abort_attachment_save'));
  cancel = true; assert.equal(await io.createAttachmentRangeSink('file.bin', 'application/octet-stream', 1), null);
});
