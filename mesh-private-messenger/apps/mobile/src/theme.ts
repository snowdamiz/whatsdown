import { Geist_400Regular } from "@expo-google-fonts/geist/400Regular";
import { Geist_500Medium } from "@expo-google-fonts/geist/500Medium";
import { Geist_600SemiBold } from "@expo-google-fonts/geist/600SemiBold";
import { Geist_700Bold } from "@expo-google-fonts/geist/700Bold";
import { GeistMono_500Medium } from "@expo-google-fonts/geist-mono/500Medium";
import { useFonts } from "expo-font";
import { Platform } from "react-native";

export const colors = {
  canvas: "#0A0A0C",
  surface: "#15151A",
  raised: "#1E1E25",
  elevated: "#27272F",
  line: "rgba(255,255,255,0.08)",
  lineStrong: "rgba(255,255,255,0.14)",
  text: "#F5F5F7",
  text2: "#9C9CA6",
  text3: "#63636D",
  onAccent: "#FFFFFF",
  accent: "#4C8DFF",
  accentDeep: "#2F6BEA",
  accentSoft: "rgba(76,141,255,0.16)",
  accentLine: "rgba(76,141,255,0.45)",
  success: "#3DDC84",
  successSoft: "rgba(61,220,132,0.14)",
  warning: "#FFB020",
  warningSoft: "rgba(255,176,32,0.14)",
  danger: "#FF5D5D",
  dangerSoft: "rgba(255,93,93,0.14)",
  white: "#FFFFFF",
  black: "#000000",
  scrim: "rgba(0,0,0,0.6)",
};

export const fonts = {
  regular: "Geist_400Regular",
  medium: "Geist_500Medium",
  semibold: "Geist_600SemiBold",
  bold: "Geist_700Bold",
  mono: "GeistMono_500Medium",
};

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

export const radius = { sm: 10, md: 14, lg: 18, xl: 24, pill: 999 };

export const type = {
  largeTitle: {
    fontFamily: fonts.bold,
    fontSize: 34,
    lineHeight: 40,
    letterSpacing: -0.9,
    color: colors.text,
  },
  title: {
    fontFamily: fonts.bold,
    fontSize: 28,
    lineHeight: 34,
    letterSpacing: -0.7,
    color: colors.text,
  },
  title2: {
    fontFamily: fonts.bold,
    fontSize: 22,
    lineHeight: 28,
    letterSpacing: -0.5,
    color: colors.text,
  },
  headline: {
    fontFamily: fonts.semibold,
    fontSize: 17,
    lineHeight: 22,
    letterSpacing: -0.3,
    color: colors.text,
  },
  body: {
    fontFamily: fonts.regular,
    fontSize: 16,
    lineHeight: 23,
    letterSpacing: -0.1,
    color: colors.text2,
  },
  bodyStrong: {
    fontFamily: fonts.medium,
    fontSize: 16,
    lineHeight: 23,
    letterSpacing: -0.1,
    color: colors.text,
  },
  subhead: {
    fontFamily: fonts.regular,
    fontSize: 15,
    lineHeight: 20,
    color: colors.text2,
  },
  label: {
    fontFamily: fonts.medium,
    fontSize: 13,
    lineHeight: 18,
    color: colors.text2,
  },
  footnote: {
    fontFamily: fonts.regular,
    fontSize: 13,
    lineHeight: 18,
    color: colors.text2,
  },
  caption: {
    fontFamily: fonts.medium,
    fontSize: 12,
    lineHeight: 16,
    color: colors.text3,
  },
  sectionTitle: {
    fontFamily: fonts.medium,
    fontSize: 13,
    lineHeight: 18,
    letterSpacing: 0.2,
    color: colors.text2,
  },
  mono: {
    fontFamily: fonts.mono,
    fontSize: 13,
    lineHeight: 20,
    color: colors.text2,
  },
};

// Two-stop gradients keep initials legible while giving every contact a distinct identity.
const avatarTones = [
  ["#5B9DFF", "#3462FF"],
  ["#B57BFF", "#7B4DFF"],
  ["#FF7DBA", "#F0468C"],
  ["#FFB35C", "#FF7A3D"],
  ["#5EE39B", "#22AD6C"],
  ["#4FD6E6", "#2492B3"],
  ["#FF8A75", "#E8553F"],
  ["#A6B2C8", "#6D7B94"],
] as const;

export function avatarTone(seed: string): { from: string; to: string; index: number } {
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) >>> 0;
  }
  const index = hash % avatarTones.length;
  const [from, to] = avatarTones[index]!;
  return { from, to, index };
}

export const shadow =
  Platform.OS === "ios"
    ? {
        shadowColor: "#000",
        shadowOpacity: 0.4,
        shadowRadius: 16,
        shadowOffset: { width: 0, height: 8 },
      }
    : { elevation: 8 };
