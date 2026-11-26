import assert from 'node:assert/strict';
import test from 'node:test';
import { REPLY_SWIPE_TRIGGER, replySwipeOffset, startsReplySwipe } from './reply-swipe.ts';

test('only a clearly rightward drag is a reply swipe, so the thread still scrolls', () => {
  assert.equal(startsReplySwipe(24, 3), true);
  assert.equal(startsReplySwipe(6, 0), false, 'A resting finger wobbles');
  assert.equal(startsReplySwipe(24, 20), false, 'A diagonal drag is a scroll');
  assert.equal(startsReplySwipe(3, 40), false);
  assert.equal(startsReplySwipe(-30, 2), false, 'Leftward is not a reply');
});

test('the bubble follows the finger to the trigger, then drags against a rubber band', () => {
  assert.equal(replySwipeOffset(-20), 0);
  assert.equal(replySwipeOffset(30), 30);
  assert.equal(replySwipeOffset(REPLY_SWIPE_TRIGGER), REPLY_SWIPE_TRIGGER);
  const far = replySwipeOffset(REPLY_SWIPE_TRIGGER + 200);
  assert.ok(far > REPLY_SWIPE_TRIGGER && far < REPLY_SWIPE_TRIGGER + 50, 'A long drag barely moves it further');
  assert.ok(replySwipeOffset(400) > replySwipeOffset(300), 'It never stops answering the finger');
});
