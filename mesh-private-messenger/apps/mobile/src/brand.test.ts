import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ANDROID_SAFE_SCALE,
  ANDROID_SAFE_ZONE,
  MARK_BOUNDS,
  MARK_CANVAS,
  MARK_GEOMETRY,
  MARK_PATH,
  markTransform,
  scaledBounds,
} from "./brand.ts";

// Every anchor point the outline passes through. Arc extremes between anchors
// are at most a line width away, so this is a faithful sample of the shape.
function anchors(path: string): Array<[number, number]> {
  const points: Array<[number, number]> = [];
  let x = 0;
  let y = 0;
  for (const segment of path.match(/[MHVA][^MHVAZ]*/g) ?? []) {
    const numbers = segment.slice(1).trim().split(/[\s,]+/).map(Number);
    switch (segment[0]) {
      case "M":
        [x, y] = numbers as [number, number];
        break;
      case "H":
        x = numbers[0];
        break;
      case "V":
        y = numbers[0];
        break;
      case "A":
        x = numbers[5];
        y = numbers[6];
        break;
    }
    points.push([x, y]);
  }
  return points;
}

test("the mark stays inside the icon canvas", () => {
  assert.ok(MARK_BOUNDS.x >= 0 && MARK_BOUNDS.y >= 0);
  assert.ok(MARK_BOUNDS.x + MARK_BOUNDS.width <= MARK_CANVAS);
  assert.ok(MARK_BOUNDS.y + MARK_BOUNDS.height <= MARK_CANVAS);
});

test("the outline never leaves MARK_BOUNDS and is centred on the canvas", () => {
  const points = anchors(MARK_PATH);
  assert.ok(points.length >= 6);
  for (const [x, y] of points) {
    assert.ok(x >= MARK_BOUNDS.x && x <= MARK_BOUNDS.x + MARK_BOUNDS.width, `x=${x}`);
    assert.ok(y >= MARK_BOUNDS.y && y <= MARK_BOUNDS.y + MARK_BOUNDS.height, `y=${y}`);
  }
  assert.equal(MARK_BOUNDS.x + MARK_BOUNDS.width / 2, MARK_CANVAS / 2);
  assert.equal(MARK_BOUNDS.y + MARK_BOUNDS.height / 2, MARK_CANVAS / 2);
});

test("the adaptive-icon foreground fits the Android safe zone", () => {
  const { x, y, width, height } = scaledBounds(ANDROID_SAFE_SCALE);
  const radius = (MARK_CANVAS * ANDROID_SAFE_ZONE) / 2;
  const centre = MARK_CANVAS / 2;
  for (const [cornerX, cornerY] of [
    [x, y],
    [x + width, y],
    [x, y + height],
    [x + width, y + height],
  ]) {
    assert.ok(Math.hypot(cornerX - centre, cornerY - centre) <= radius);
  }
});

test("the transform places the scaled mark where scaledBounds says it is", () => {
  const transform = markTransform(0.5, 300, 400);
  const match = /^translate\((-?[\d.]+) (-?[\d.]+)\) scale\(0\.5\)$/.exec(transform);
  assert.ok(match);
  const translateX = Number(match[1]);
  const translateY = Number(match[2]);
  const bounds = scaledBounds(0.5, 300, 400);
  assert.ok(Math.abs(MARK_BOUNDS.x * 0.5 + translateX - bounds.x) < 1e-9);
  assert.ok(Math.abs(MARK_BOUNDS.y * 0.5 + translateY - bounds.y) < 1e-9);
});

test("the mark is exactly two closed shapes, a dot and a dash", () => {
  assert.equal((MARK_PATH.match(/M/g) ?? []).length, 2);
  assert.equal((MARK_PATH.match(/Z/g) ?? []).length, 2);
  assert.ok(MARK_PATH.trimEnd().endsWith("Z"));
});

test("the dash is three dots long and shares the dot's line weight", () => {
  const { dot, dash } = MARK_GEOMETRY;
  assert.equal(dash.width, 3 * (2 * dot.r));
  assert.equal(dash.height, 2 * dot.r);
});

test("the dot sits above the dash, flush with its left edge", () => {
  const { dot, dash } = MARK_GEOMETRY;
  assert.equal(dot.cx - dot.r, dash.x);
  assert.ok(dot.cy + dot.r < dash.y);
});
