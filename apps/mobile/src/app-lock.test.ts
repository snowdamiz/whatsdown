import assert from 'node:assert/strict';
import test from 'node:test';

import { encodeLockSetting, lockDue, parseLockSetting } from './app-lock.ts';

test('the app lock setting reads back what was saved, and anything else as off', () => {
  for (const minutes of [0, 1, 60]) assert.equal(parseLockSetting(encodeLockSetting(minutes)), minutes);
  assert.equal(parseLockSetting(encodeLockSetting(null)), null);
  assert.equal(parseLockSetting(''), null);
  assert.equal(parseLockSetting('7'), null);
  assert.equal(parseLockSetting('{"minutes":"x"}'), null);
});

test('the app locks at launch and after its time in the background, never when off', () => {
  const left = 1_800_000_000_000;
  assert.equal(lockDue(null, left, left + 86_400_000), false);
  assert.equal(lockDue(0, undefined, left), true);
  assert.equal(lockDue(0, left, left + 1), true);
  assert.equal(lockDue(1, left, left + 59_999), false);
  assert.equal(lockDue(1, left, left + 60_000), true);
  assert.equal(lockDue(60, left, left + 59 * 60_000), false);
});
