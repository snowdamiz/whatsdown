import assert from 'node:assert/strict';
import test from 'node:test';
import { historyRefreshDelay, unexpiredHistory } from './expiry.ts';

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

test('display expiry drops only due native-stamped rows at the inclusive deadline', () => {
  const expired = { timestamp: 1_000, disappearingSeconds: 60, body: 'expired' };
  const permanent = { timestamp: 0, disappearingSeconds: 0, body: 'retained' };
  const legacy = { timestamp: 0, body: 'legacy retained' };
  const later = { timestamp: 2_000, disappearingSeconds: 60, body: 'next deadline' };
  const future = { timestamp: 100_000, disappearingSeconds: 60, body: 'future' };
  const history = [expired, permanent, legacy, later, future];
  assert.equal(unexpiredHistory(history, 60_999), history);
  const first = unexpiredHistory(history, 61_000);
  assert.deepEqual(first, [permanent, legacy, later, future]);
  assert.equal(historyRefreshDelay(first, 61_000), 1_000, 'A failed read must not prevent the next local display deadline');
  assert.deepEqual(unexpiredHistory(first, 62_000), [permanent, legacy, future]);
  assert.equal(history.length, 5, 'Do not mutate a captured getter result or another cache owner');
});

test('late old getter content is filtered again at completion time without changing retained row identity', () => {
  const expired = { timestamp: 1_000, disappearingSeconds: 60 };
  const retained = { timestamp: 1_000 };
  const held = [expired, retained];
  assert.equal(unexpiredHistory(held, 60_999), held);
  const completed = unexpiredHistory(held, 61_001);
  assert.deepEqual(completed, [retained]);
  assert.equal(completed[0], retained);
  assert.equal(unexpiredHistory(completed, 61_001), completed);
});
