import assert from 'node:assert/strict';
import test from 'node:test';
import { HistoryCacheEpoch, replaceHistoryCache } from './history-cache-epoch.ts';

test('delayed local history cannot cross account replacement, same-wire ABA, database or preview', async () => {
  for (const change of ['account', 'ABA', 'database', 'preview', 'profile renewal']) {
    const epochs = new HistoryCacheEpoch(), original = Uint8Array.of(1), other = Uint8Array.of(2);
    const before = epochs.capture(original, 'one.db', null);
    let complete!: (value: string[]) => void;
    const result = epochs.read(before, () => new Promise<string[]>(resolve => { complete = resolve; }));
    if (change === 'account') epochs.capture(other, 'one.db', null);
    if (change === 'ABA') { epochs.capture(null, 'one.db', null); epochs.capture(original, 'one.db', null); }
    if (change === 'database') epochs.capture(original, 'two.db', null);
    if (change === 'preview') epochs.capture(original, 'one.db', {});
    if (change === 'profile renewal') epochs.capture(original.slice(), 'one.db', null);
    complete(['old private history']); assert.equal(await result, undefined, change);
    let invoked = false;
    await epochs.read(before, async () => { invoked = true; return []; });
    assert.equal(invoked, false, 'Obsolete epoch must not initiate native reads');
  }
  const epochs = new HistoryCacheEpoch(), profile = {};
  const before = epochs.capture(profile, 'one.db', null);
  assert.equal(epochs.capture(profile, 'one.db', null), before);
  assert.deepEqual(await epochs.read(before, async () => ['current']), ['current']);
});

test('expiry placeholders cannot overwrite a newer local refresh or account reset', () => {
  const old = ['expired'], placeholder: string[] = [], fresh = ['new message'];
  let cache = replaceHistoryCache({ thread: old }, 'thread', old, placeholder);
  cache = { thread: fresh };
  assert.deepEqual(replaceHistoryCache(cache, 'thread', placeholder, ['obsolete completion']), { thread: fresh });
  assert.deepEqual(replaceHistoryCache({}, 'thread', placeholder, ['old account']), {});
  assert.deepEqual(replaceHistoryCache({ thread: placeholder }, 'thread', placeholder, ['native verified']), { thread: ['native verified'] });
});
