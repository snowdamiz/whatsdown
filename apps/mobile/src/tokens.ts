// Reference tokens: the raw values Morse is drawn with, and nothing else.
//
// This is the bottom of the design system. It knows no colour scheme,
// platform or component; it is plain data so it can be tested. Above it,
// appearance.ts assigns colours to roles per scheme (the semantic layer),
// theme.ts hands every group to components through `useTheme`, and a
// component writes a bare number or hex only where no token fits, and says
// why in a comment.

// ---------------------------------------------------------------- Colour
//
// Ramps run light to dark: a higher step is always darker. Steps exist only
// where the design uses them, so a new one is a deliberate addition.

export const gray = {
  0: "#FFFFFF",
  50: "#F5F5F7",
  100: "#F2F2F5",
  200: "#E9E9EE",
  300: "#DFDFE6",
  400: "#9C9CA6",
  500: "#8E8E98",
  600: "#63636D",
  700: "#5E5E6A",
  800: "#3A3A44",
  850: "#27272F",
  900: "#1E1E25",
  950: "#15151A",
  1000: "#0A0A0C",
} as const;

export const blue = { 300: "#6AA6FF", 400: "#4C8DFF", 500: "#2F6BEA", 600: "#2459D0" } as const;
export const green = { 400: "#3DDC84", 600: "#178A4E" } as const;
export const amber = { 400: "#FFB020", 600: "#B26B00" } as const;
export const red = { 50: "#FBEAEB", 400: "#FF5D5D", 600: "#D8323A", 950: "#2B1B1E" } as const;

// Identity tones: one step each, used the same way in either scheme, and
// each deep enough to carry a white glyph.
export const violet = "#8B5CF6";
export const pink = "#EC4899";
export const teal = "#0D9488";

// Two-stop gradients keep initials legible while giving every contact a
// distinct identity.
export const avatarGradients = [
  ["#5B9DFF", "#3462FF"],
  ["#B57BFF", "#7B4DFF"],
  ["#FF7DBA", "#F0468C"],
  ["#FFB35C", "#FF7A3D"],
  ["#5EE39B", "#22AD6C"],
  ["#4FD6E6", "#2492B3"],
  ["#FF8A75", "#E8553F"],
  ["#A6B2C8", "#6D7B94"],
] as const;

// Each gradient's hue as ink: deep enough to set a sender's name in on a
// light pane, where the gradient's own stops would wash out.
export const avatarInk = [
  "#2E5CB8",
  "#7544B4",
  "#AD2D69",
  "#934611",
  "#18673D",
  "#1A687B",
  "#AD4033",
  "#54627A",
] as const;

// Which gradient a seed takes: FNV-1a, with the bucket read from the high
// bits after a final stir. The low bits of a plain polynomial hash ignore how
// a seed's characters are arranged, so account IDs that differ by a repeated
// byte all fell into one hue; the high bits have been stirred by every
// character.
export function avatarToneIndex(seed: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < seed.length; index += 1) {
    hash = Math.imul(hash ^ seed.charCodeAt(index), 0x01000193);
  }
  return Math.floor(((Math.imul(hash, 0x9e3779b1) >>> 0) / 2 ** 32) * avatarGradients.length);
}

// A six-digit hex colour at partial opacity, for translucent surfaces that
// keep a pane's own hue.
export function withAlpha(hex: string, alpha: number): string {
  const value = Number.parseInt(hex.slice(1), 16);
  return `rgba(${value >> 16},${(value >> 8) & 0xff},${value & 0xff},${alpha})`;
}

// ---------------------------------------------------------------- Space
//
// A four-point rhythm: the key is the multiple of the unit, so `space[4]` is
// 16. Half steps exist below 16, where controls need finer tuning. Anything
// off this grid is an optical adjustment and is written as such.

export const space = {
  0: 0,
  0.5: 2,
  1: 4,
  1.5: 6,
  2: 8,
  2.5: 10,
  3: 12,
  3.5: 14,
  4: 16,
  5: 20,
  6: 24,
  7: 28,
  8: 32,
  10: 40,
  12: 48,
} as const;

// ---------------------------------------------------------------- Shape

// Corners step by two points. Touch surfaces sit two or three steps above
// their desktop counterparts; a shape nested inside another with padding
// takes the outer radius minus that padding, so the curves stay concentric.
export const radius = {
  xs: 8,
  sm: 10,
  md: 12,
  lg: 14,
  xl: 16,
  "2xl": 18,
  "3xl": 20,
  "4xl": 24,
  pill: 999,
} as const;

// ---------------------------------------------------------------- Size

// Ladders step by size, not by platform: a touch screen and a dense desktop
// pick different steps of the same ladder, as they do with radii.
export const size = {
  // The smallest area a finger can reliably hit.
  hit: 44,
  icon: { xs: 12, sm: 14, md: 16, lg: 18, xl: 22, "2xl": 28 },
  avatar: { xs: 28, sm: 34, md: 40, lg: 46, xl: 54, "2xl": 64, "3xl": 92 },
  // The glyph tile at the head of a row.
  tile: { sm: 26, md: 32 },
  // The count badge on a tab, segment or row.
  badge: { sm: 16, md: 18, lg: 20 },
  // The round well a glyph sits in on a feature row or a dialog's big icon.
  well: { xs: 36, sm: 44, md: 48, lg: 64, xl: 72 },
  // The brand mark: in a dense hero, a phone hero, and on the splash.
  mark: { sm: 48, md: 56, lg: 76 },
} as const;

// Heights of interactive controls: buttons, fields, rows and bars. A touch
// control is at least `2xl`, a full hit target; desktop controls sit lower.
export const control = {
  xs: 28,
  sm: 30,
  md: 34,
  lg: 38,
  xl: 40,
  "2xl": 46,
  "3xl": 52,
  "4xl": 60,
} as const;

// ---------------------------------------------------------------- Type

export const fonts = {
  regular: "Geist_400Regular",
  medium: "Geist_500Medium",
  semibold: "Geist_600SemiBold",
  bold: "Geist_700Bold",
  mono: "GeistMono_500Medium",
} as const;

// Font size, line height and tracking for each text role, on a touch screen
// and on a dense desktop display read at arm's length.
export type TypeMetrics = readonly [fontSize: number, lineHeight: number, letterSpacing?: number];

export const typeScale = {
  largeTitle: { touch: [34, 40, -0.9], dense: [26, 32, -0.6] },
  title: { touch: [28, 34, -0.7], dense: [22, 28, -0.5] },
  title2: { touch: [22, 28, -0.5], dense: [18, 24, -0.4] },
  headline: { touch: [17, 22, -0.3], dense: [15, 20, -0.2] },
  body: { touch: [16, 23, -0.1], dense: [14, 20] },
  subhead: { touch: [15, 20], dense: [13.5, 18] },
  label: { touch: [13, 18], dense: [12.5, 16] },
  footnote: { touch: [13, 18], dense: [12.5, 16] },
  caption: { touch: [12, 16], dense: [11.5, 15] },
  // Counts and timestamps: the smallest text drawn.
  micro: { touch: [11, 14], dense: [10.5, 13] },
  sectionTitle: { touch: [13, 18, 0.2], dense: [12, 16, 0.3] },
  // Text entry follows the platform's field size rather than body copy.
  input: { touch: [17, 22], dense: [14, 20] },
  mono: { touch: [13, 20], dense: [12.5, 18] },
  monoSmall: { touch: [11, 16], dense: [11, 16] },
  // Codes read as objects to compare, not prose: the safety number's groups
  // and the device code's digits.
  monoLarge: { touch: [17, 26, 1.6], dense: [14, 22, 1.2] },
  code: { touch: [30, 40, 4], dense: [24, 32, 3] },
} as const satisfies Record<string, { touch: TypeMetrics; dense: TypeMetrics }>;

// ---------------------------------------------------------------- Opacity

export const opacity = {
  disabled: 0.4,
  // The glow behind hero content: a faint wash under a card, the backdrop of
  // a full screen, and full strength behind the splash mark.
  glowFaint: 0.22,
  glow: 0.26,
  glowStrong: 0.34,
  // How much of an accent tint a glass control lets through. Prominent glass
  // is nearly the tint itself, as UIKit draws it; a thinner wash turned the
  // desktop's primary buttons pale enough to read as disabled.
  wash: 0.9,
} as const;

// ---------------------------------------------------------------- Motion

// State-driven changes settle; one-shot entrances take longer; exits are
// always quicker than entrances so attention moves forward, not back. Glass
// forms and dissolves at UIKit's own pace.
export const duration = {
  quick: 140,
  settle: 220,
  enter: 320,
  exit: 160,
  materialize: 240,
} as const;

// Curves as cubic-bezier control points, so the same hand moves native
// animations and the web view's CSS transitions.
export type Curve = readonly [x1: number, y1: number, x2: number, y2: number];

export const easing = {
  out: [0.2, 0, 0, 1],
  in: [0.4, 0, 1, 1],
  inOut: [0.45, 0, 0.25, 1],
} as const satisfies Record<string, Curve>;

// A curve as CSS writes it.
export const cubicBezier = (curve: Curve): string => `cubic-bezier(${curve.join(", ")})`;
