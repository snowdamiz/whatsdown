// The theme: every token group, assembled for the scheme in effect and handed
// to components through `useTheme`.
//
// tokens.ts holds the raw values and appearance.ts gives colours their roles;
// this module is the only place that knows about React, the platform, or
// which scheme is showing. Components style themselves from a Theme (or from
// the scheme-independent groups exported below) and never from a bare value.

import { Geist_400Regular } from "@expo-google-fonts/geist/400Regular";
import { Geist_500Medium } from "@expo-google-fonts/geist/500Medium";
import { Geist_600SemiBold } from "@expo-google-fonts/geist/600SemiBold";
import { Geist_700Bold } from "@expo-google-fonts/geist/700Bold";
import { GeistMono_500Medium } from "@expo-google-fonts/geist-mono/500Medium";
import { useFonts } from "expo-font";
import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  Appearance as SystemAppearance,
  Easing,
  Platform,
  useColorScheme,
  type TextStyle,
  type ViewStyle,
} from "react-native";

import {
  palettes,
  resolveScheme,
  type Appearance,
  type ColorScheme,
  type Palette,
} from "./appearance";
import {
  avatarGradients,
  avatarInk,
  avatarToneIndex,
  control,
  duration,
  easing,
  fonts,
  opacity,
  radius,
  size,
  space,
  typeScale,
  withAlpha,
  type TypeMetrics,
} from "./tokens";

export { control, fonts, opacity, radius, size, space, withAlpha };
export type { Appearance, ColorScheme, Palette };

// The web build only ships inside the Tauri desktop shell, so "web" means a
// pointer-driven desktop window: denser type, smaller controls, hover states,
// and glass drawn by the web view (glass.web.tsx) rather than by UIKit.
export const isDesktop = Platform.OS === "web";
export const WindowsChromeContext = createContext(false);

export function useAppFonts(): boolean {
  const [loaded, error] = useFonts({
    [fonts.regular]: Geist_400Regular,
    [fonts.medium]: Geist_500Medium,
    [fonts.semibold]: Geist_600SemiBold,
    [fonts.bold]: Geist_700Bold,
    [fonts.mono]: GeistMono_500Medium,
  });
  return loaded || error !== null;
}

// ---------------------------------------------------------------- Type

// Desktop text is read at arm's length on a dense display, so every role
// takes its dense metrics there.
const metrics = (role: keyof typeof typeScale) => {
  const scale: TypeMetrics = isDesktop ? typeScale[role].dense : typeScale[role].touch;
  const [fontSize, lineHeight, letterSpacing = 0] = scale;
  return { fontSize, lineHeight, letterSpacing };
};

// A text role always carries its full metrics, so a component can derive a
// height or a size from one without checking for absence.
export type TextRole = TextStyle & {
  fontFamily: string;
  fontSize: number;
  lineHeight: number;
  letterSpacing: number;
  color: string;
};

// Each text role pairs a weight with its metrics and the colour it is legible
// in, so the scheme's palette decides the colour.
function typography(colors: Palette) {
  const role = (name: keyof typeof typeScale, fontFamily: string, color: string): TextRole => ({
    fontFamily,
    ...metrics(name),
    color,
  });
  return {
    largeTitle: role("largeTitle", fonts.bold, colors.text),
    title: role("title", fonts.bold, colors.text),
    title2: role("title2", fonts.bold, colors.text),
    headline: role("headline", fonts.semibold, colors.text),
    body: role("body", fonts.regular, colors.text2),
    bodyStrong: role("body", fonts.medium, colors.text),
    subhead: role("subhead", fonts.regular, colors.text2),
    label: role("label", fonts.medium, colors.text2),
    footnote: role("footnote", fonts.regular, colors.text2),
    caption: role("caption", fonts.medium, colors.text3),
    micro: role("micro", fonts.medium, colors.text3),
    sectionTitle: role("sectionTitle", fonts.medium, colors.text2),
    input: role("input", fonts.regular, colors.text),
    mono: role("mono", fonts.mono, colors.text2),
    monoSmall: role("monoSmall", fonts.mono, colors.text2),
    monoLarge: role("monoLarge", fonts.mono, colors.text),
    code: role("code", fonts.mono, colors.text),
  };
}
export type Typography = ReturnType<typeof typography>;

// ---------------------------------------------------------------- Colour

// The identity colours a seed hashes to: the gradient its avatar is drawn
// with, and the colour its name is set in on a dark pane (the gradient's
// light stop) or a light one (the ink).
export function avatarTone(
  seed: string,
  scheme: ColorScheme = "dark",
): { from: string; to: string; ink: string; index: number } {
  const index = avatarToneIndex(seed);
  const [from, to] = avatarGradients[index]!;
  return { from, to, ink: scheme === "dark" ? from : avatarInk[index]!, index };
}

// ---------------------------------------------------------------- Elevation

export type Elevation = {
  // A card, sheet or pill lifted off the canvas.
  raised: ViewStyle;
  // The moving pane of a segmented control.
  thumb: ViewStyle;
  // The app glyph on the hero. Android elevation on a transparent wrapper
  // draws a stray outline, so the glyph only casts a shadow on iOS.
  glyph: ViewStyle;
  // A soft accent-coloured lift under primary calls to action. Android's
  // elevation shadows are always black, so the glow is iOS-only by design.
  accent: ViewStyle;
  // A pane of desktop glass: its lit top edge and the soft shadow it casts.
  glass: ViewStyle;
};

// A shadow that would lift a surface off a black canvas reads as a smudge on
// a white one, so light surfaces cast fainter ones.
function elevationFor(scheme: ColorScheme, colors: Palette): Elevation {
  const dark = scheme === "dark";
  const raisedOpacity = dark ? 0.4 : 0.14;
  const raised: ViewStyle =
    Platform.OS === "ios"
      ? { shadowColor: colors.black, shadowOpacity: raisedOpacity, shadowRadius: 16, shadowOffset: { width: 0, height: 8 } }
      : isDesktop
        ? { boxShadow: `0 ${space[2]}px ${space[6]}px ${withAlpha(colors.black, dark ? 0.45 : 0.16)}` }
        : { elevation: 8 };
  return {
    raised,
    thumb: { boxShadow: `0 1px 2px ${withAlpha(colors.black, dark ? 0.35 : 0.14)}` },
    glyph: Platform.OS === "ios" ? { ...raised, shadowOpacity: dark ? 0.5 : 0.18 } : {},
    accent:
      Platform.OS === "ios"
        ? { shadowColor: colors.accent, shadowOpacity: 0.32, shadowRadius: 14, shadowOffset: { width: 0, height: 6 } }
        : {},
    glass: {
      boxShadow: `inset 0 1px 0 ${colors.glassSheen}, 0 ${space[2]}px ${space[6]}px ${withAlpha(colors.black, dark ? 0.24 : 0.08)}`,
    },
  };
}

// ---------------------------------------------------------------- Motion

// One vocabulary for motion so every surface moves the same way.
export const motion = {
  ...duration,
  easeOut: Easing.bezier(...easing.out),
  easeIn: Easing.bezier(...easing.in),
  easeInOut: Easing.bezier(...easing.inOut),
  // Critically damped: arrives without overshoot.
  spring: { stiffness: 320, damping: 36, mass: 1 },
  // Same character, twice as stiff, for feedback that must track the finger.
  springSnap: { stiffness: 640, damping: 51, mass: 1 },
  // A touch of give for playful moments such as a message landing.
  springSoft: { stiffness: 260, damping: 24, mass: 1 },
};

// ---------------------------------------------------------------- Theme

export type Theme = {
  scheme: ColorScheme;
  colors: Palette;
  type: Typography;
  elevation: Elevation;
  space: typeof space;
  radius: typeof radius;
  size: typeof size;
  control: typeof control;
  opacity: typeof opacity;
};

function buildTheme(scheme: ColorScheme): Theme {
  const colors = palettes[scheme];
  return {
    scheme,
    colors,
    type: typography(colors),
    elevation: elevationFor(scheme, colors),
    space,
    radius,
    size,
    control,
    opacity,
  };
}

export const themes: Record<ColorScheme, Theme> = {
  dark: buildTheme("dark"),
  light: buildTheme("light"),
};

const ThemeContext = createContext<Theme>(themes.dark);

export function useTheme(): Theme {
  return useContext(ThemeContext);
}

// Styles that take their values from the theme. Both schemes' sheets are
// built once, up front, and the hook hands back the one in effect, so a
// component reads `styles.x` exactly as it would from a static sheet.
export function themed<T>(build: (theme: Theme) => T): () => T {
  const built: Record<ColorScheme, T> = {
    dark: build(themes.dark),
    light: build(themes.light),
  };
  return function useThemedStyles() {
    return built[useTheme().scheme];
  };
}

// ---------------------------------------------------------------- Appearance

type AppearanceState = {
  appearance: Appearance;
  setAppearance: (next: Appearance) => void;
};

const AppearanceContext = createContext<AppearanceState>({
  appearance: "system",
  setAppearance: () => undefined,
});

export function useAppearance(): AppearanceState {
  return useContext(AppearanceContext);
}

// Owns the user's choice and resolves it against the device's scheme into
// the theme everything below renders with. `load` runs once, synchronously,
// so the first frame is already in the right scheme; `save` keeps the choice
// wherever the platform stores it.
export function AppearanceProvider({
  load,
  save,
  children,
}: {
  load: () => Appearance;
  save: (next: Appearance) => void;
  children: ReactNode;
}) {
  const [appearance, setStored] = useState(load);
  const system = useColorScheme();
  const scheme = resolveScheme(appearance, system);
  const setAppearance = (next: Appearance) => {
    setStored(next);
    save(next);
  };
  // On a phone the choice also governs system UI (keyboards, alerts, share
  // sheets), so it is handed to the OS as an override. The desktop shell does
  // the same for its window when the choice is saved; the web view itself has
  // no such API.
  useEffect(() => {
    if (Platform.OS === "web") return;
    SystemAppearance.setColorScheme(appearance === "system" ? "unspecified" : appearance);
  }, [appearance]);
  return createElement(
    AppearanceContext.Provider,
    { value: { appearance, setAppearance } },
    createElement(ThemeContext.Provider, { value: themes[scheme] }, children),
  );
}
