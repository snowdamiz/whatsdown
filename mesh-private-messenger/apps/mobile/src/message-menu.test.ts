import assert from 'node:assert/strict';
import test from 'node:test';
import { placeMenu } from './message-menu.ts';

const bounds = { left: 12, top: 59, right: 363, bottom: 778 };
const menu = { width: 300, height: 150 };

test('the menu sits above its bubble, lined up with the edge the bubble hugs', () => {
  const received = { x: 16, y: 400, width: 200, height: 60 };
  assert.deepEqual(placeMenu(bounds, received, menu, false), { left: 16, top: 242 });
  const sent = { x: 159, y: 400, width: 200, height: 60 };
  assert.deepEqual(placeMenu(bounds, sent, menu, true), { left: 59, top: 242 });
});

test('with no room above, the menu drops below the bubble', () => {
  assert.deepEqual(placeMenu(bounds, { x: 16, y: 100, width: 200, height: 60 }, menu, false), { left: 16, top: 168 });
});

test('a menu wider than its bubble, or a bubble taller than the window, stays on screen', () => {
  // A narrow sent bubble: lining the right edges up would push the menu off the left.
  assert.equal(placeMenu(bounds, { x: 40, y: 400, width: 60, height: 40 }, menu, true).left, 12);
  // A narrow received bubble near the right edge.
  assert.equal(placeMenu(bounds, { x: 300, y: 400, width: 60, height: 40 }, menu, false).left, 63);
  // No room above or below: the menu rests over the bubble at the bottom.
  assert.equal(placeMenu(bounds, { x: 16, y: 80, width: 200, height: 680 }, menu, false).top, 628);
});
