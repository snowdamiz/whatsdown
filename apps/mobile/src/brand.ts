// The Morse mark: a dot above a dash, the two symbols every Morse message is
// built from, stacked and flush on their left edge like a line of code. One
// geometry feeds the in-app glyph, the iOS and Android icons, and the desktop
// icon so they never drift.

import { blue } from "./tokens.ts";

export const MARK_CANVAS = 1024;

// "MORSE" in International Morse code, shown under the wordmark. En dashes and
// middle dots share a baseline in Geist Mono, so the rhythm reads cleanly.
export const MORSE_CODE_WORDMARK = "––  –––  ·–·  ···  ·";

// The mark is lit from the top left: the accent blue, and a lighter step of
// the same ramp.
export const MARK_GRADIENT = { from: blue[300], to: blue[500] };

// Only the central 66% of an adaptive icon survives every launcher mask.
// Scaling the mark by the same factor keeps its size relative to the visible
// tile identical to iOS and guarantees nothing is clipped.
export const ANDROID_SAFE_ZONE = 0.66;
export const ANDROID_SAFE_SCALE = 0.66;

// Morse timing: a dash is three dots long. The dot's diameter is the unit and
// the dash shares it as its height, so the pair reads as one line weight.
const unit = 176;
const gap = 64;

export const MARK_GEOMETRY = (() => {
  const width = 3 * unit;
  const height = unit + gap + unit;
  const x = (MARK_CANVAS - width) / 2;
  const y = (MARK_CANVAS - height) / 2;
  return {
    dot: { cx: x + unit / 2, cy: y + unit / 2, r: unit / 2 },
    dash: { x, y: y + unit + gap, width, height: unit },
  };
})();

export const MARK_BOUNDS = (() => {
  const { dot, dash } = MARK_GEOMETRY;
  const top = dot.cy - dot.r;
  return { x: dash.x, y: top, width: dash.width, height: dash.y + dash.height - top };
})();

function dotPath({ cx, cy, r }: { cx: number; cy: number; r: number }): string {
  return `M ${cx - r} ${cy} A ${r} ${r} 0 1 1 ${cx + r} ${cy} A ${r} ${r} 0 1 1 ${cx - r} ${cy} Z`;
}

function pillPath({ x, y, width, height }: { x: number; y: number; width: number; height: number }): string {
  const r = height / 2;
  return `M ${x + r} ${y} H ${x + width - r} A ${r} ${r} 0 0 1 ${x + width - r} ${y + height} H ${x + r} A ${r} ${r} 0 0 1 ${x + r} ${y} Z`;
}

export const MARK_PATH = `${dotPath(MARK_GEOMETRY.dot)} ${pillPath(MARK_GEOMETRY.dash)}`;

// SVG transform that scales the mark about the centre of its bounding box and
// places that centre at (cx, cy) on a MARK_CANVAS-sized canvas.
export function markTransform(scale: number, cx = MARK_CANVAS / 2, cy = MARK_CANVAS / 2): string {
  const { x, y, width, height } = MARK_BOUNDS;
  const originX = x + width / 2;
  const originY = y + height / 2;
  return `translate(${cx - originX * scale} ${cy - originY * scale}) scale(${scale})`;
}

export function scaledBounds(scale: number, cx = MARK_CANVAS / 2, cy = MARK_CANVAS / 2) {
  const { width, height } = MARK_BOUNDS;
  return {
    x: cx - (width * scale) / 2,
    y: cy - (height * scale) / 2,
    width: width * scale,
    height: height * scale,
  };
}
