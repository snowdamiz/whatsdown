import {
  GlassView,
  isGlassEffectAPIAvailable,
  isLiquidGlassAvailable,
} from "expo-glass-effect";
import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import {
  AccessibilityInfo,
  Platform,
  StyleSheet,
  View,
  type StyleProp,
  type ViewProps,
  type ViewStyle,
} from "react-native";
import { motion, radius, size, themed, useTheme } from "./theme";

// Liquid Glass needs iOS 26, an Xcode 26 build, and the native module compiled
// into this binary. A dev client built before the module was added must fall
// back to surfaces rather than throw from `requireNativeModule`.
const compiledIn = (() => {
  if (Platform.OS !== "ios") return false;
  try {
    return isLiquidGlassAvailable() && isGlassEffectAPIAvailable();
  } catch {
    return false;
  }
})();

let reduceTransparency = false;
let watching = false;
const listeners = new Set<() => void>();

function watchAccessibility() {
  if (watching || !compiledIn) return;
  watching = true;
  const update = (enabled: boolean) => {
    if (enabled === reduceTransparency) return;
    reduceTransparency = enabled;
    listeners.forEach((listener) => listener());
  };
  void AccessibilityInfo.isReduceTransparencyEnabled().then(update, () => undefined);
  AccessibilityInfo.addEventListener("reduceTransparencyChanged", update);
}

function subscribe(listener: () => void) {
  watchAccessibility();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

const snapshot = () => compiledIn && !reduceTransparency;

// True when controls should render as Liquid Glass. Anyone who has asked iOS
// for reduced transparency gets the opaque surfaces instead of frosted glass.
export function useLiquidGlass(): boolean {
  return useSyncExternalStore(subscribe, snapshot);
}

// Glass that is mounted invisible and then formed by the system on the next
// frame, so it materialises in place rather than simply appearing. Setting
// `visible` false runs the matching dematerialise animation.
export function useMaterialized(visible: boolean): boolean {
  const [materialized, setMaterialized] = useState(false);
  useEffect(() => {
    if (!visible) {
      setMaterialized(false);
      return;
    }
    const frame = requestAnimationFrame(() => setMaterialized(true));
    return () => cancelAnimationFrame(frame);
  }, [visible]);
  return materialized;
}

export type GlassProps = ViewProps & {
  children?: ReactNode;
  // Accent-tinted glass marks the one prominent action in a toolbar.
  tint?: string;
  // Lets the glass answer touch with the system's own press response.
  interactive?: boolean;
  // `clear` suits glass over media such as a camera feed; `regular` adapts
  // to whatever scrolls beneath it.
  clear?: boolean;
  // The surface drawn where glass is unavailable.
  fallback?: StyleProp<ViewStyle>;
  // Drives the system materialise/dematerialise animation. Leave undefined
  // for glass that is simply present.
  materialized?: boolean;
};

// The one control-layer material. Never animate the opacity of this view or
// any ancestor: UIKit stops rendering the glass entirely (iOS 26.1+). Move
// content instead, fade children, or toggle `materialized`.
export function Glass({
  children,
  tint,
  interactive = false,
  clear = false,
  fallback,
  materialized,
  style,
  onLayout,
  ...rest
}: GlassProps) {
  const glass = useLiquidGlass();
  const { scheme } = useTheme();
  const styles = useStyles();
  // The pill token is an oversized radius that ordinary views clamp for us.
  // Glass hands its radius straight to UIKit's corner configuration, so a
  // capsule needs the real half-height, taken from layout. Until then it is
  // guessed from the style, or assumed to be a hit target's.
  const flat = StyleSheet.flatten(style) ?? {};
  const pill = typeof flat.borderRadius === "number" && flat.borderRadius >= radius.pill;
  const guess =
    typeof flat.height === "number"
      ? flat.height / 2
      : typeof flat.minHeight === "number"
        ? flat.minHeight / 2
        : size.hit / 2;
  const [measured, setMeasured] = useState<number>();
  if (!glass) {
    return (
      <View {...rest} onLayout={onLayout} style={[style, fallback ?? styles.surface]}>
        {children}
      </View>
    );
  }
  const base = clear ? "clear" : "regular";
  return (
    <GlassView
      {...rest}
      onLayout={(event) => {
        onLayout?.(event);
        if (!pill) return;
        const { width, height } = event.nativeEvent.layout;
        const next = Math.min(width, height) / 2;
        if (next > 0 && next !== measured) setMeasured(next);
      }}
      style={[style, pill && { borderRadius: measured ?? guess }]}
      colorScheme={scheme}
      tintColor={tint}
      isInteractive={interactive}
      glassEffectStyle={
        materialized === undefined
          ? base
          : {
              style: materialized ? base : "none",
              animate: true,
              animationDuration: motion.materialize / 1000,
            }
      }
    >
      {children}
    </GlassView>
  );
}

// The desktop build (glass.web.tsx) blurs chrome with the web view's backdrop
// filter; native chrome gets its material from the Glass view itself.
export const glassBackdrop: ViewStyle = {};

const useStyles = themed(({ colors }) =>
  StyleSheet.create({
    surface: {
      backgroundColor: colors.raised,
      borderWidth: 1,
      borderColor: colors.line,
    },
  }),
);
