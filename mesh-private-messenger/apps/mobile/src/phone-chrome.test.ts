import assert from 'node:assert/strict';
import { test } from 'node:test';

import { tabBarClearance } from './phone-chrome.ts';

test('the tab bar rests on the home indicator but floats clear of Android navigation', () => {
  assert.equal(tabBarClearance('ios', 34), 28);
  assert.equal(tabBarClearance('ios', 0), 20);
  // Gesture handle, then the three-button bar: a floating margin above either.
  assert.equal(tabBarClearance('android', 24), 40);
  assert.equal(tabBarClearance('android', 48), 64);
  assert.equal(tabBarClearance('android', 0), 20);
});
