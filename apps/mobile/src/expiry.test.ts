import assert from 'node:assert/strict';
import test from 'node:test';
import { historyRefreshDelay } from './expiry.ts';

test('refreshes at the first disappearing-message deadline without polling permanent history', () => {
  const messages = [
    { timestamp: 1_000, disappearingSeconds: 60 },
    { timestamp: 3_000, disappearingSeconds: 3_600 },
    { timestamp: 0, disappearingSeconds: 0 },
  ];
  assert.equal(historyRefreshDelay(messages, 5_000), 56_000);
  assert.equal(historyRefreshDelay(messages, 61_000), 0);
  assert.equal(historyRefreshDelay([], 5_000), undefined);
  assert.equal(historyRefreshDelay([messages[2]!], 5_000), undefined);
  assert.equal(historyRefreshDelay([{ timestamp: 0, disappearingSeconds: 4_294_967_295 }], 0), 2_147_483_647);
});
