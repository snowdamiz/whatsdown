import assert from 'node:assert/strict';
import { test } from 'node:test';
import { installScrollbars } from './scrollbars.ts';

test('scrolling reveals only its own scrollbar, restarts its fade, and cleans up', () => {
  const animations: { cancelled: boolean; onfinish?: () => void }[] = [];
  class ScrollArea extends EventTarget {
    animate(keyframes: unknown, options: unknown) {
      assert.deepEqual(keyframes, { '--scrollbar-color': ['var(--scrollbar-thumb)', 'transparent'] });
      assert.deepEqual(options, { delay: 600, duration: 240, easing: 'ease-out', fill: 'backwards' });
      const animation = {
        cancelled: false,
        cancel() { this.cancelled = true; },
        onfinish: undefined as (() => void) | undefined,
      };
      animations.push(animation);
      return animation;
    }
  }
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'Element');
  Object.defineProperty(globalThis, 'Element', { configurable: true, value: ScrollArea });
  try {
    const document = new EventTarget();
    const stop = installScrollbars(document as Document);
    const scroll = (target: EventTarget) => {
      const event = new Event('scroll');
      Object.defineProperty(event, 'target', { value: target });
      document.dispatchEvent(event);
    };
    const sidebar = new ScrollArea();
    const thread = new ScrollArea();
    scroll(sidebar);
    scroll(thread);
    scroll(sidebar);
    assert.equal(animations.length, 3);
    assert.equal(animations[0]!.cancelled, true);
    assert.equal(animations[1]!.cancelled, false);
    animations[1]!.onfinish!();
    stop();
    assert.equal(animations[1]!.cancelled, false);
    assert.equal(animations[2]!.cancelled, true);
    scroll(sidebar);
    assert.equal(animations.length, 3);
  } finally {
    if (previous) Object.defineProperty(globalThis, 'Element', previous);
    else Reflect.deleteProperty(globalThis, 'Element');
  }
});
