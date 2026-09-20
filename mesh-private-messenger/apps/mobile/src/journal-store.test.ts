import assert from 'node:assert/strict';
import test from 'node:test';
import { createJournalStore } from './journal-store.ts';

// Stands in for the core: sealed records under keys it cannot list.
function core() {
  const records = new Map<string, string>();
  const writes: string[] = [];
  return {
    records, writes,
    load: async (key: string) => records.get(key) ?? '',
    save: async (key: string, data: string) => { writes.push(key); if (data) records.set(key, data); else records.delete(key); },
  };
}
const chat = `chat/${'a'.repeat(32)}`;
const group = `group/${'b'.repeat(64)}`;

test('a journal is kept as one sealed record per chat, and only what changed is written again', async () => {
  const sealed = core();
  const store = createJournalStore(sealed.load, sealed.save);
  assert.equal(await store.load('read-state'), null);
  await store.save('read-state', { [chat]: ['01'], [group]: ['02'] });
  assert.deepEqual(sealed.writes.sort(), [`read-state/${chat}`, `read-state/${group}`, 'read-state/index'].sort());
  // Reading one chat touches that chat's record and nothing else: not the index, not the other chat.
  sealed.writes.length = 0;
  await store.save('read-state', { [chat]: ['01', '03'], [group]: ['02'] });
  assert.deepEqual(sealed.writes, [`read-state/${chat}`]);
  // A fresh start finds everything again through the index.
  const restarted = createJournalStore(sealed.load, sealed.save);
  assert.deepEqual(JSON.parse((await restarted.load('read-state'))!), { [chat]: ['01', '03'], [group]: ['02'] });
  // A chat that is gone takes its record with it.
  sealed.writes.length = 0;
  await restarted.save('read-state', { [group]: ['02'] });
  assert.deepEqual(sealed.writes.sort(), [`read-state/${chat}`, 'read-state/index'].sort());
  assert.equal(sealed.records.has(`read-state/${chat}`), false);
  // Journals do not share records.
  assert.equal(await restarted.load('receipt-marks'), null);
});

test('what was kept in the clear before is sealed once and then removed', async () => {
  const sealed = core();
  let legacy: string | null = JSON.stringify({ [chat]: ['01'] });
  const store = createJournalStore(sealed.load, sealed.save);
  const moved = await store.load('read-state', { read: () => legacy, remove: () => { legacy = null; } });
  assert.deepEqual(JSON.parse(moved!), { [chat]: ['01'] });
  assert.equal(legacy, null);
  assert.deepEqual(JSON.parse(sealed.records.get(`read-state/${chat}`)!), ['01']);
  // The sealed copy wins from then on, whatever is lying about in the old place.
  legacy = JSON.stringify({ [chat]: ['99'] });
  const again = createJournalStore(sealed.load, sealed.save);
  assert.deepEqual(JSON.parse((await again.load('read-state', { read: () => legacy, remove: () => { legacy = null; } }))!), { [chat]: ['01'] });
  // The clear copy is only removed once the sealed one is written.
  const failing = createJournalStore(sealed.load, async () => { throw new Error('disk full'); });
  let kept: string | null = JSON.stringify({ [chat]: ['07'] });
  await assert.rejects(failing.load('notification-state', { read: () => kept, remove: () => { kept = null; } }));
  assert.notEqual(kept, null);
});
