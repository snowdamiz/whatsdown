import assert from 'node:assert/strict';
import test from 'node:test';
import { parseMailboxSyncOutcome, synchronizeNativeMailbox } from './native-mailbox-sync.ts';

function outcome(batches: number, received: number, acknowledged: number, more = false) {
  const bytes = new Uint8Array(12); bytes.set([1, 77, 83, 89]);
  const view = new DataView(bytes.buffer);
  view.setUint16(4, batches); view.setUint16(6, received); view.setUint16(8, acknowledged);
  bytes[10] = acknowledged < received ? 1 : 0; bytes[11] = more ? 1 : 0;
  return bytes;
}

test('mailbox scheduling sends only the database to native code and preserves pending state across bounded passes', async () => {
  const replies = [outcome(16, 128, 127, true), outcome(1, 0, 0)];
  const calls: Uint8Array[] = [];
  const result = await synchronizeNativeMailbox('/native/мorse.db', async (request) => {
    calls.push(request); return replies.shift()!;
  });
  assert.deepEqual(result, { batches: 17, received: 128, acknowledged: 127, pending: true });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], new TextEncoder().encode('/native/мorse.db'));
  assert.deepEqual(calls[1], calls[0]);
});

test('native mailbox status rejects malformed versions, counts and flags', () => {
  const wrongTag = outcome(1, 0, 0); wrongTag[0] = 2;
  const wrongFlag = outcome(1, 1, 1); wrongFlag[10] = 1;
  const unknownFlag = outcome(1, 1, 1); unknownFlag[11] = 2;
  for (const bytes of [wrongTag, wrongFlag, unknownFlag, outcome(17, 0, 0), outcome(1, 9, 0), outcome(1, 1, 2), outcome(0, 0, 0), new Uint8Array(11), new Uint8Array(13)]) {
    assert.throws(() => parseMailboxSyncOutcome(bytes), /invalid_mailbox_sync_status/);
  }
  assert.deepEqual(parseMailboxSyncOutcome(outcome(0, 0, 0, true)), { batches: 0, received: 0, acknowledged: 0, pending: false, more: true });
});

test('mailbox scheduling is bounded and never spins on a zero-progress native pass', async () => {
  let calls = 0;
  await assert.rejects(synchronizeNativeMailbox('/native/morse.db', async () => { calls++; return outcome(0, 0, 0, true); }), /mailbox_sync_budget_exhausted/);
  assert.equal(calls, 1);
  calls = 0;
  await assert.rejects(synchronizeNativeMailbox('/native/morse.db', async () => { calls++; return outcome(1, 1, 1, true); }), /mailbox_sync_budget_exhausted/);
  assert.equal(calls, 64);
});
