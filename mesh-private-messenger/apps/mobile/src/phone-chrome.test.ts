import assert from 'node:assert/strict';
import { test } from 'node:test';

import { tabBarFoot } from './phone-chrome.ts';

test('the tab bar tucks into the home indicator but stays clear of Android navigation', () => {
  // The home indicator needs less than its whole inset under a bar's labels.
  assert.equal(tabBarFoot('ios', 34), 22);
  assert.equal(tabBarFoot('ios', 0), 8);
  // Android's gesture handle and button bar are content of their own.
  assert.equal(tabBarFoot('android', 24), 24);
  assert.equal(tabBarFoot('android', 48), 48);
  assert.equal(tabBarFoot('android', 0), 8);
});
