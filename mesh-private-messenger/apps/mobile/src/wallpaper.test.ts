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
  assert.ok(own.length >= 40, `only ${own.length} doodles`);
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

test('the wallpaper is dense and mixes small doodles with large ones', () => {
  const tile = 480;
  const doodles = scatterDoodles(tile, 20, 3);
  const own = doodles.filter((d) => d.x >= 0 && d.x < tile && d.y >= 0 && d.y < tile);
  // Dense: the doodles' own discs take up much of the tile, so the gaps
  // between them stay narrow.
  const covered = own.reduce((sum, d) => sum + Math.PI * (d.size / 2) ** 2, 0) / tile ** 2;
  assert.ok(covered >= 0.4, `the doodles cover only ${Math.round(covered * 100)}% of the tile`);
  const sizes = own.map((d) => d.size).sort((a, b) => a - b);
  // Large enough to read as drawings at any size, and some far larger.
  assert.ok(sizes[0]! >= 22, `the smallest doodle is ${sizes[0]}`);
  assert.ok(sizes.at(-1)! >= sizes[0]! * 2.2, `sizes run only from ${sizes[0]} to ${sizes.at(-1)}`);
  // Most are on the smaller side, so the large ones stand out rather than crowd.
  const median = sizes[Math.floor(sizes.length / 2)]!;
  assert.ok(median < (sizes[0]! + sizes.at(-1)!) / 2, `median ${median} is not below the middle of the range`);
});
