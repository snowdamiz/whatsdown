import assert from 'node:assert/strict';
import { test } from 'node:test';

import { palettes, parseAppearance, resolveScheme, type Palette } from './appearance.ts';
import { contrast } from './wcag.ts';

// Glass is a stack of washes over the pane behind it, and `contrast` reads
// opaque colours, so a stack is flattened to what the screen actually shows.
function flatten(base: string, ...washes: string[]): string {
  let channels = [1, 3, 5].map((offset) => Number.parseInt(base.slice(offset, offset + 2), 16));
  for (const wash of washes) {
    const parts = wash.slice(5, -1).split(',').map(Number);
    const alpha = parts[3]!;
    channels = channels.map((under, index) => alpha * parts[index]! + (1 - alpha) * under);
  }
  return `#${channels.map((c) => Math.round(c).toString(16).padStart(2, '0')).join('')}`;
}

// How far apart two colours sit, counting hue as well as lightness: a tinted
// pane and a grey hairline can share a lightness and still read as different
// things.
function apart(a: string, b: string): number {
  const channels = (hex: string) => [1, 3, 5].map((o) => Number.parseInt(hex.slice(o, o + 2), 16));
  const [x, y] = [channels(a), channels(b)];
  return Math.hypot(...x!.map((channel, index) => channel - y![index]!));
}

test('parseAppearance keeps a saved choice and otherwise follows the system', () => {
  assert.equal(parseAppearance('light'), 'light');
  assert.equal(parseAppearance('dark'), 'dark');
  assert.equal(parseAppearance('system'), 'system');
  assert.equal(parseAppearance(' dark\n'), 'dark');
  assert.equal(parseAppearance('sepia'), 'system');
  assert.equal(parseAppearance(null), 'system');
  assert.equal(parseAppearance(undefined), 'system');
});

test('resolveScheme lets an explicit choice win and otherwise follows the system', () => {
  assert.equal(resolveScheme('light', 'dark'), 'light');
  assert.equal(resolveScheme('dark', 'light'), 'dark');
  assert.equal(resolveScheme('system', 'light'), 'light');
  assert.equal(resolveScheme('system', 'dark'), 'dark');
  // A platform that reports no scheme gets the app's original look.
  assert.equal(resolveScheme('system', null), 'dark');
  assert.equal(resolveScheme('system', undefined), 'dark');
  assert.equal(resolveScheme('system', 'unspecified'), 'dark');
});

for (const [scheme, colors] of Object.entries(palettes) as [string, Palette][]) {
  test(`${scheme} palette keeps text legible on every pane`, () => {
    for (const pane of [colors.canvas, colors.sidebar, colors.surface, colors.raised, colors.elevated]) {
      assert.ok(contrast(colors.text, pane) >= 4.5, `text on ${pane}: ${contrast(colors.text, pane)}`);
      assert.ok(contrast(colors.text2, pane) >= 4.5, `text2 on ${pane}: ${contrast(colors.text2, pane)}`);
    }
    assert.ok(contrast(colors.text3, colors.canvas) >= 3, 'tertiary text on the canvas');
    assert.ok(contrast(colors.accent, colors.canvas) >= 4.5, 'accent text (ghost buttons) on the canvas');
    assert.ok(contrast(colors.danger, colors.canvas) >= 4.5, 'destructive text on the canvas');
    assert.ok(contrast(colors.onAccent, colors.accent) >= 3, 'labels on accent fills');
    // The error pill: its message is body text, its glyph is the danger colour.
    assert.ok(contrast(colors.text, colors.dangerSurface) >= 4.5, 'text on the error surface');
    assert.ok(contrast(colors.danger, colors.dangerSurface) >= 3, 'danger glyph on the error surface');
    // Every glyph tile carries a white glyph.
    for (const tile of [colors.tileMuted, colors.violet, colors.pink, colors.teal]) {
      assert.ok(contrast(colors.white, tile) >= 3, `white glyph on tile ${tile}`);
    }
  });

  // The sidebar's segmented control has nothing but its thumb to say which
  // list is showing, so that pane has to read as a selection rather than as
  // another piece of the pill's edge.
  test(`${scheme} palette sets an on-glass selection apart from the glass itself`, () => {
    const track = flatten(colors.sidebar, colors.glass);
    const pane = flatten(track, colors.glassFill);
    const hairline = flatten(colors.sidebar, colors.glassLine);
    assert.ok(apart(pane, hairline) >= 20, `selected pane ${pane} against hairline ${hairline}`);
    assert.ok(contrast(colors.glassGlyph, pane) >= 3, `selected glyph on ${pane}`);
  });

  // Only the canvas lies behind the sidebar's glass, so the film alone sets the
  // pane apart. Light's milky glass once left it white on a white canvas.
  test(`${scheme} palette sets the glass sidebar a shade off the canvas`, () => {
    const pane = flatten(colors.canvas, colors.sidebarGlass);
    assert.ok(apart(pane, colors.canvas) >= 15, `sidebar pane ${pane} against canvas ${colors.canvas}`);
  });

  test(`${scheme} palette keeps the printed card legible in both schemes`, () => {
    assert.ok(contrast(colors.ink, colors.paper) >= 7, 'code modules on the card');
    assert.ok(contrast(colors.inkSoft, colors.paper) >= 4.5, 'card copy');
    assert.ok(contrast(colors.inkFaint, colors.paper) >= 4.5, 'card fine print');
  });
}
