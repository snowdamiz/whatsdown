import assert from 'node:assert/strict';
import test from 'node:test';
import { parseGroupHistory, parseGroupPolicy, utf8, vectors, writeU32 } from './codec.ts';
import { historyRefreshDelay } from './expiry.ts';

const wide = (value: number) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(value)); return bytes; };
const id = (value: number, length = 32) => new Uint8Array(length).fill(value);
const entry = (version: number, expiry?: Uint8Array) => {
  const fields = [Uint8Array.of(version), Uint8Array.of(2), wide(1), id(1), id(2, 16), wide(1_000),
    utf8('Synthetic expiring group message'), new Uint8Array(), id(3), Uint8Array.of(0), ...(expiry ? [expiry] : [])];
  return vectors(writeU32(fields.length), ...fields);
};
const history = (...rows: Uint8Array[]) => vectors(writeU32(rows.length), ...rows);

test('group history preserves legacy permanent rows and exposes authenticated timed metadata', () => {
  const [legacy, timed] = parseGroupHistory(history(entry(1), entry(2, writeU32(60))));
  assert.equal(legacy?.disappearingSeconds ?? 0, 0);
  assert.equal(timed?.disappearingSeconds, 60);
  assert.equal(timed?.timestamp, 1_000);
  assert.equal(timed?.body, 'Synthetic expiring group message');
  assert.equal(historyRefreshDelay([legacy!, timed!], 5_000), 56_000);
  assert.equal(historyRefreshDelay([legacy!], 5_000), undefined);
});

test('timed group history rejects missing/invalid duration and version confusion', () => {
  for (const malformed of [entry(2), entry(1, writeU32(60)), entry(3, writeU32(60)),
    entry(2, writeU32(0)), entry(2, writeU32(2_592_001)), entry(2, Uint8Array.of(1,2,3))]) {
    assert.throws(() => parseGroupHistory(history(malformed)));
  }
});

test('group policy frame is exact, bound to the requested group and duration', () => {
  const frame = (group: Uint8Array, seconds: number) => vectors(writeU32(3), Uint8Array.of(1), group, writeU32(seconds));
  assert.equal(parseGroupPolicy(frame(id(9), 0), id(9)), 0);
  assert.equal(parseGroupPolicy(frame(id(9), 2_592_000), id(9)), 2_592_000);
  assert.throws(() => parseGroupPolicy(frame(id(8), 60), id(9)));
  assert.throws(() => parseGroupPolicy(frame(id(9), 2_592_001), id(9)));
  assert.throws(() => parseGroupPolicy(vectors(writeU32(3), Uint8Array.of(2), id(9), writeU32(60)), id(9)));
  assert.throws(() => parseGroupPolicy(vectors(writeU32(4), Uint8Array.of(1), id(9), writeU32(60), Uint8Array.of(0)), id(9)));
});
