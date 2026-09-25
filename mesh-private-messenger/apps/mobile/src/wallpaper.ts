// The doodle wallpaper behind a thread, scattered the way WhatsApp and
// Telegram scatter theirs: glyphs of varied size and tilt, dropped at random
// but never touching, on a square tile that repeats without a visible seam.
// Kept free of React Native so the scatter can be tested.

export type Doodle = { glyph: number; x: number; y: number; size: number; angle: number };

// mulberry32: seeded, so every launch draws the same wallpaper.
function seeded(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Darts are thrown at the tile and a doodle is kept where it lands `gap` clear
// of every kept one, measured across the edges too, since a doodle by the
// right edge sits beside those by the left edge of the next tile. A doodle
// hanging over an edge is drawn again on the far side, where the next tile
// shows the rest of it.
export function scatterDoodles(tile: number, glyphs: number, gap: number, seed = 1): Doodle[] {
  const random = seeded(seed);
  const across = (a: number, b: number) => Math.min(Math.abs(a - b), tile - Math.abs(a - b));
  const placed: Doodle[] = [];
  for (let dart = 0; dart < 5000; dart++) {
    const doodle = {
      glyph: placed.length % glyphs,
      x: random() * tile,
      y: random() * tile,
      size: 16 + random() * 12,
      angle: random() * 90 - 45,
    };
    const clear = placed.every(
      (other) => Math.hypot(across(doodle.x, other.x), across(doodle.y, other.y)) >= (doodle.size + other.size) / 2 + gap,
    );
    if (clear) placed.push(doodle);
  }
  // A tilted glyph reaches at most its half-diagonal from its centre.
  const shifts = [-tile, 0, tile];
  return placed.flatMap((doodle) =>
    shifts.flatMap((dx) =>
      shifts.flatMap((dy) => {
        const [x, y, reach] = [doodle.x + dx, doodle.y + dy, doodle.size * 0.75];
        return x + reach > 0 && x - reach < tile && y + reach > 0 && y - reach < tile ? [{ ...doodle, x, y }] : [];
      }),
    ),
  );
}
