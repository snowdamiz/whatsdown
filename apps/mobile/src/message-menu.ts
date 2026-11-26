export type Frame = { x: number; y: number; width: number; height: number };

// Where a message's menu goes: above its bubble when there is room, below it
// otherwise, its edge lined up with the bubble's on the side the bubble hugs.
// `bounds` is the window less its margins and insets; the menu never leaves it.
export function placeMenu(
  bounds: { left: number; top: number; right: number; bottom: number },
  anchor: Frame,
  menu: { width: number; height: number },
  alignRight: boolean,
  gap = 8,
): { left: number; top: number } {
  const clamp = (value: number, low: number, high: number) => Math.max(low, Math.min(value, high));
  const above = anchor.y - gap - menu.height;
  const below = anchor.y + anchor.height + gap;
  return {
    left: clamp(alignRight ? anchor.x + anchor.width - menu.width : anchor.x, bounds.left, bounds.right - menu.width),
    top: above >= bounds.top ? above : clamp(below, bounds.top, bounds.bottom - menu.height),
  };
}
