// A message dragged this far to the right is answered when the finger lifts.
export const REPLY_SWIPE_TRIGGER = 56;

// The drag that begins a reply is clearly rightward; anything steeper is the
// thread scrolling, and a resting finger's wobble is nothing at all.
export const startsReplySwipe = (dx: number, dy: number): boolean => dx > 10 && dx > 2 * Math.abs(dy);

// The bubble follows the finger to the trigger point, then drags against a
// rubber band: past there the gesture is already made.
export const replySwipeOffset = (dx: number): number =>
  dx <= REPLY_SWIPE_TRIGGER ? Math.max(dx, 0) : REPLY_SWIPE_TRIGGER + (dx - REPLY_SWIPE_TRIGGER) * 0.2;
