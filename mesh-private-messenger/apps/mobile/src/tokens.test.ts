import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  amber,
  avatarGradients,
  avatarInk,
  avatarToneIndex,
  blue,
  control,
  easing,
  gray,
  green,
  opacity,
  radius,
  red,
  size,
  space,
  typeScale,
  withAlpha,
} from './tokens.ts';
import { contrast, luminance } from './wcag.ts';

const ascending = (values: number[]) =>
  values.every((value, index) => index === 0 || value > values[index - 1]!);

test('space keeps a four-point rhythm on a two-point grid', () => {
  const steps = Object.entries(space)
    .map(([key, value]) => [Number(key), value] as const)
    .sort(([a], [b]) => a - b);
  for (const [key, value] of steps) {
    assert.equal(value, key * 4, `space[${key}]`);
    assert.equal(value % 2, 0, `space[${key}] sits off the two-point grid`);
  }
  assert.ok(ascending(steps.map(([, value]) => value)));
});

test('radius steps ascend and end in the pill', () => {
  const { pill, ...corners } = radius;
  const values = Object.values(corners);
  assert.ok(ascending(values));
  assert.ok(pill > Math.max(...values));
});

test('every colour ramp darkens as its step number rises', () => {
  for (const [name, ramp] of Object.entries({ gray, blue, green, amber, red })) {
    const steps = Object.entries(ramp)
      .map(([step, hex]) => [Number(step), hex] as const)
      .sort(([a], [b]) => a - b);
    const luminances = steps.map(([, hex]) => luminance(hex));
    assert.ok(
      luminances.every((value, index) => index === 0 || value < luminances[index - 1]!),
      `${name}: ${steps.map(([step]) => step).join(' > ')}`,
    );
  }
});

test('the type scale fits its lines and steps down for dense screens', () => {
  for (const [role, { touch, dense }] of Object.entries(typeScale)) {
    assert.ok(touch[1] >= touch[0], `${role} touch line height`);
    assert.ok(dense[1] >= dense[0], `${role} dense line height`);
    assert.ok(dense[0] <= touch[0], `${role} dense size`);
    assert.ok(dense[1] <= touch[1], `${role} dense line height`);
  }
});

test('control heights ascend, and a touch control is a full hit target', () => {
  assert.ok(ascending(Object.values(control)));
  assert.ok(control['2xl'] >= size.hit);
});

test('size ladders ascend', () => {
  for (const ladder of [size.icon, size.avatar, size.tile, size.badge, size.well, size.mark]) {
    assert.ok(ascending(Object.values(ladder)));
  }
});

test('glow strengths ascend from faint to strong', () => {
  assert.ok(ascending([opacity.glowFaint, opacity.glow, opacity.glowStrong]));
});

// CSS rejects a cubic-bezier whose x control points leave the unit interval,
// and the native driver would silently accept it.
test('easing curves are valid cubic-bezier control points', () => {
  for (const [x1, , x2] of Object.values(easing)) {
    assert.ok(x1 >= 0 && x1 <= 1 && x2 >= 0 && x2 <= 1);
  }
});

// A sender's name in a group thread takes their avatar's hue: the gradient's
// light stop on a dark bubble, its ink on a light one. Either way it is small
// text and must read as such on the received-bubble pane of that scheme.
test('every avatar tone has a legible name colour in each scheme', () => {
  assert.equal(avatarInk.length, avatarGradients.length);
  avatarGradients.forEach(([from], index) => {
    assert.ok(contrast(from, gray[900]) >= 4.5, `tone ${index} on a dark bubble`);
    assert.ok(contrast(avatarInk[index]!, gray[200]) >= 4.5, `ink ${index} on a light bubble`);
  });
});

// Identities are coloured by account ID. IDs that differ only by a repeated
// byte, as fixtures and test accounts do, must not all land on one hue.
test('avatar tones spread across seeds that differ by a repeated byte', () => {
  const seeds = Array.from({ length: 16 }, (_, index) => (index + 3).toString(16).padStart(2, '0').repeat(32));
  const tones = seeds.map(avatarToneIndex);
  assert.ok(tones.every((tone) => Number.isInteger(tone) && tone >= 0 && tone < avatarGradients.length));
  assert.ok(new Set(tones).size >= avatarGradients.length - 2, `only ${new Set(tones).size} hues in use`);
  assert.equal(avatarToneIndex('marcus'), avatarToneIndex('marcus'));
});

test('withAlpha keeps the hue and applies the opacity', () => {
  assert.equal(withAlpha('#4C8DFF', 0.16), 'rgba(76,141,255,0.16)');
  assert.equal(withAlpha('#000000', 1), 'rgba(0,0,0,1)');
});
