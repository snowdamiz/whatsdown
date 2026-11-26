import { useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import {
  Animated,
  StyleSheet,
  View,
  type StyleProp,
  type ViewProps,
  type ViewStyle,
} from "react-native";
import { motion, opacity, themed, withAlpha } from "./theme";

// The desktop shell has no UIKit to form glass, so the material is WebKit's
// own backdrop blur over whatever scrolls beneath a control: the same frosted
// layer the phone gets, drawn by the web view. Anyone who has asked the
// system for reduced transparency gets the opaque surfaces instead, as on iOS.
const reduceTransparency =
  typeof matchMedia === "function"
    ? matchMedia("(prefers-reduced-transparency: reduce)")
    : null;

function subscribe(listener: () => void) {
  reduceTransparency?.addEventListener("change", listener);
  return () => reduceTransparency?.removeEventListener("change", listener);
}

const snapshot = () => !(reduceTransparency?.matches ?? false);

export function useLiquidGlass(): boolean {
  return useSyncExternalStore(subscribe, snapshot);
}

// Glass that is mounted invisible and then formed on the next frame, so it
// materialises in place rather than simply appearing. Setting `visible` false
// runs the matching dematerialise animation.
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
  // Lets the glass answer the pointer with hover and press states.
  interactive?: boolean;
  // `clear` suits glass over media such as a camera feed; `regular` adapts
  // to whatever scrolls beneath it.
  clear?: boolean;
  // The surface drawn where glass is unavailable.
  fallback?: StyleProp<ViewStyle>;
  // Drives the materialise/dematerialise animation. Leave undefined for
  // glass that is simply present.
  materialized?: boolean;
};

// Hover and press are answered from the stylesheet in Root.web.tsx, keyed on
// this attribute, so interactive glass needs no pointer state of its own.
const interactiveRegion = { dataSet: { glass: "interactive" } } as unknown as ViewProps;

// Tints arrive either as the accent hex, which becomes a translucent wash, or
// already translucent.
const wash = (tint: string) => (tint.startsWith("#") ? withAlpha(tint, opacity.wash) : tint);

export function Glass({
  children,
  tint,
  interactive = false,
  clear = false,
  fallback,
  materialized,
  style,
  ...rest
}: GlassProps) {
  const glass = useLiquidGlass();
  const styles = useStyles();
  const [presence] = useState(() => new Animated.Value(materialized === false ? 0 : 1));
  useEffect(() => {
    if (materialized === undefined) return;
    const animation = Animated.timing(presence, {
      toValue: materialized ? 1 : 0,
      duration: motion.materialize,
      easing: motion.easeOut,
      useNativeDriver: false,
    });
    animation.start();
    return () => animation.stop();
  }, [materialized, presence]);
  if (!glass) {
    return (
      <View {...rest} style={[style, fallback ?? styles.surface]}>
        {children}
      </View>
    );
  }
  return (
    <Animated.View
      {...rest}
      {...(interactive ? interactiveRegion : {})}
      style={[
        style,
        clear ? styles.clear : styles.glass,
        tint ? { backgroundColor: wash(tint) } : null,
        materialized !== undefined && { opacity: presence },
      ]}
    >
      {children}
    </Animated.View>
  );
}

// Properties React Native's types do not know but the web view renders.
const web = (style: Record<string, string>) => style as unknown as ViewStyle;

// The blur is shared by every piece of desktop chrome so strips and pills
// read as one material.
export const glassBackdrop = web({ backdropFilter: "blur(28px) saturate(1.6)" });

// The material is a film over the blur with a lit top edge; the palette
// decides what that film is made of over dark and over light content.
const useStyles = themed(({ colors, elevation }) =>
  StyleSheet.create({
    surface: {
      backgroundColor: colors.raised,
      borderWidth: 1,
      borderColor: colors.line,
    },
    glass: {
      backgroundColor: colors.glass,
      borderWidth: 1,
      borderColor: colors.glassLine,
      ...glassBackdrop,
      ...elevation.glass,
    },
    clear: {
      borderWidth: 1,
      borderColor: colors.line,
      ...glassBackdrop,
    },
  }),
);
