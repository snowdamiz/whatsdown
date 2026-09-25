import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scatterDoodles } from './wallpaper.ts';

test('scattered doodles never touch, even where one tile meets the next', () => {
  const tile = 360;
  const gap = 10;
  const doodles = scatterDoodles(tile, 20, gap);
  // Centres inside the tile are the doodles themselves; the rest are their
  // copies hanging in from the tile beside it.
  const own = doodles.filter((d) => d.x >= 0 && d.x < tile && d.y >= 0 && d.y < tile);
  assert.ok(own.length >= 60, `only ${own.length} doodles`);
  const across = (a: number, b: number) => Math.min(Math.abs(a - b), tile - Math.abs(a - b));
  for (const [index, a] of own.entries()) {
    for (const b of own.slice(index + 1)) {
      const distance = Math.hypot(across(a.x, b.x), across(a.y, b.y));
      assert.ok(distance >= (a.size + b.size) / 2 + gap, `doodles at ${a.x},${a.y} and ${b.x},${b.y}`);
    }
    // A doodle over the right edge shows its rest at the left.
    if (a.x + a.size / 2 > tile) assert.ok(doodles.some((d) => d.x === a.x - tile && d.y === a.y), `no twin for ${a.x},${a.y}`);
  }
});
