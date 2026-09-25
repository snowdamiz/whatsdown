// The look of the app, as the user chooses it and as it resolves on screen.
//
// This is the semantic layer of the design system: it gives the reference
// colours in tokens.ts a role in each scheme. Components name roles, never
// ramp steps, so a scheme can be retuned here without touching them. Kept
// free of React Native so the choice and the palettes can be tested.

import { amber, blue, gray, green, pink, red, teal, violet, withAlpha } from "./tokens.ts";

export { withAlpha } from "./tokens.ts";

export type ColorScheme = "dark" | "light";

// What the user picked: a scheme, or whatever the device is set to.
export type Appearance = ColorScheme | "system";

export function parseAppearance(saved: unknown): Appearance {
  const value = typeof saved === "string" ? saved.trim() : "";
  return value === "light" || value === "dark" ? value : "system";
}

// Morse was drawn dark first, so a platform that reports no scheme (or an
// unknown one) gets that.
export function resolveScheme(
  appearance: Appearance,
  system: string | null | undefined,
): ColorScheme {
  if (appearance !== "system") return appearance;
  return system === "light" ? "light" : "dark";
}

export type Palette = {
  // ---- Panes. Surfaces step away from the canvas in order: surface, raised,
  // elevated. The desktop sidebar sits a shade off the canvas so the two
  // panes read as separate regions without a divider line.
  canvas: string;
  sidebar: string;
  surface: string;
  raised: string;
  elevated: string;
  // A small pane lifted off its surface: the moving pane of a switch or
  // segmented control, and the reaction pill hung from a message bubble.
  thumb: string;
  // Desktop glass: the film over blurred content, its edge, its lit top
  // edge, and the fill of a thumb or indicator drawn on it with the glyph
  // that rides on that fill.
  glass: string;
  glassLine: string;
  glassSheen: string;
  glassFill: string;
  glassGlyph: string;
  // The film of the desktop sidebar's glass pane. Only the canvas lies behind
  // it, so the film alone has to land the pane on the sidebar's shade: light's
  // milky glass over a white canvas is white on white.
  sidebarGlass: string;
  line: string;
  lineStrong: string;
  // The desktop scrollbar while scrolling; it fades to transparent at rest.
  scrollThumb: string;
  // The wash a pressed or hovered control takes on.
  highlight: string;
  // The doodles behind every screen, fainter than a hairline.
  wallpaper: string;
  scrim: string;

  // ---- Text, in descending emphasis, and text on accent fills.
  text: string;
  text2: string;
  text3: string;
  onAccent: string;
  onAccentMuted: string;

  // ---- The accent and the status colours, each with a soft fill.
  accent: string;
  accentDeep: string;
  accentSoft: string;
  accentLine: string;
  success: string;
  successSoft: string;
  warning: string;
  warningSoft: string;
  danger: string;
  dangerSoft: string;
  // An opaque pane for an error message, where a soft fill would be too faint.
  dangerSurface: string;

  // ---- Glyph tiles. Every tile carries a white glyph; the identity tones
  // are the same in either scheme.
  tileMuted: string;
  violet: string;
  pink: string;
  teal: string;

  // ---- Fixed regardless of scheme. The QR card is a printed object: white
  // paper, dark ink, so it scans in either scheme. White and black are for
  // glyphs on gradients, camera chrome and translucent overlays.
  paper: string;
  ink: string;
  inkSoft: string;
  inkFaint: string;
  white: string;
  black: string;
};

const fixed = {
  onAccent: gray[0],
  onAccentMuted: withAlpha(gray[0], 0.72),
  violet,
  pink,
  teal,
  paper: gray[0],
  ink: gray[1000],
  inkSoft: gray[800],
  inkFaint: gray[600],
  white: gray[0],
  black: "#000000",
};

const dark: Palette = {
  canvas: gray[1000],
  sidebar: gray[950],
  surface: gray[950],
  raised: gray[900],
  elevated: gray[850],
  thumb: gray[850],
  glass: withAlpha(gray[0], 0.07),
  glassLine: withAlpha(gray[0], 0.11),
  glassSheen: withAlpha(gray[0], 0.08),
  glassFill: withAlpha(gray[0], 0.12),
  glassGlyph: gray[50],
  sidebarGlass: withAlpha(gray[0], 0.07),
  line: withAlpha(gray[0], 0.08),
  lineStrong: withAlpha(gray[0], 0.14),
  scrollThumb: withAlpha(gray[0], 0.1),
  highlight: withAlpha(gray[0], 0.07),
  wallpaper: withAlpha(gray[0], 0.035),
  scrim: withAlpha(fixed.black, 0.6),
  text: gray[50],
  text2: gray[400],
  text3: gray[600],
  accent: blue[400],
  accentDeep: blue[500],
  accentSoft: withAlpha(blue[400], 0.16),
  accentLine: withAlpha(blue[400], 0.45),
  success: green[400],
  successSoft: withAlpha(green[400], 0.14),
  warning: amber[400],
  warningSoft: withAlpha(amber[400], 0.14),
  danger: red[400],
  dangerSoft: withAlpha(red[400], 0.14),
  dangerSurface: red[950],
  tileMuted: gray[850],
  ...fixed,
};

// The light scheme mirrors the dark one: surfaces step down from a white
// canvas instead of up from a black one, hairlines and washes are black at
// low alpha instead of white, and the status colours deepen so they carry
// text and white glyphs on pale panes. A muted tile takes the tertiary text
// grey, as system settings do, because a raised pane would be white on white.
// Over light content a faint white film would vanish, so glass becomes a
// milky pane with a dark hairline. That leaves no room for a selected pane
// drawn in grey: lightening it loses it in the milk, and darkening it lands
// on the hairline's own tone, so the switch reads as chrome rather than as a
// choice. Light marks the selection with the accent instead, the way the tab
// bar already does, and deepens the glyph a step so it carries on the wash.
const light: Palette = {
  canvas: gray[0],
  sidebar: gray[50],
  surface: gray[100],
  raised: gray[200],
  elevated: gray[300],
  thumb: gray[0],
  glass: withAlpha(gray[0], 0.6),
  glassLine: withAlpha(fixed.black, 0.08),
  glassSheen: withAlpha(gray[0], 0.7),
  glassFill: withAlpha(blue[500], 0.18),
  glassGlyph: blue[600],
  sidebarGlass: withAlpha(fixed.black, 0.04),
  line: withAlpha(fixed.black, 0.08),
  lineStrong: withAlpha(fixed.black, 0.13),
  scrollThumb: withAlpha(fixed.black, 0.12),
  highlight: withAlpha(fixed.black, 0.05),
  wallpaper: withAlpha(fixed.black, 0.04),
  scrim: withAlpha(fixed.black, 0.35),
  text: gray[1000],
  text2: gray[700],
  text3: gray[500],
  accent: blue[500],
  accentDeep: blue[600],
  accentSoft: withAlpha(blue[500], 0.12),
  accentLine: withAlpha(blue[500], 0.4),
  success: green[600],
  successSoft: withAlpha(green[600], 0.14),
  warning: amber[600],
  warningSoft: withAlpha(amber[600], 0.14),
  danger: red[600],
  dangerSoft: withAlpha(red[600], 0.12),
  dangerSurface: red[50],
  tileMuted: gray[500],
  ...fixed,
};

export const palettes: Record<ColorScheme, Palette> = { dark, light };
