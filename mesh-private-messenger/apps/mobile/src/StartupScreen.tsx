import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { AccessibilityInfo, Animated, Easing, Platform, StyleSheet, Text, View } from 'react-native';
import Svg, { Defs, LinearGradient, Path, Stop } from 'react-native-svg';

import { MARK_CANVAS, MARK_GRADIENT, MARK_PATH, MORSE_CODE_WORDMARK } from './brand';
import { motion, space, themes } from './theme';

// Keep the OS launch screen until the branded React surface has laid out.
void SplashScreen.preventAutoHideAsync().catch(() => undefined);
SplashScreen.setOptions({ fade: false });

const { colors, type } = themes.dark;
const AnimatedGradient = Animated.createAnimatedComponent(LinearGradient);
// Two cosine waves soften the highlight's edges and meet smoothly at the loop seam.
const highlightStops = Array.from({ length: 33 }, (_, index) => ({
  offset: index / 32,
  opacity: (1 - Math.cos(index * Math.PI / 8)) / 2,
}));

export function StartupScreen({ ready = false, fontsReady = false, error }: {
  ready?: boolean;
  fontsReady?: boolean;
  error?: string;
}) {
  const [visible, setVisible] = useState(true);
  const [opacity] = useState(() => new Animated.Value(1));
  const [flow] = useState(() => new Animated.Value(0));
  const [reduceMotion, setReduceMotion] = useState<boolean | null>(null);
  useEffect(() => {
    let active = true;
    void AccessibilityInfo.isReduceMotionEnabled().then(
      (value) => { if (active) setReduceMotion(value); },
      () => { if (active) setReduceMotion(true); },
    );
    const subscription = AccessibilityInfo.addEventListener('reduceMotionChanged', setReduceMotion);
    return () => { active = false; subscription.remove(); };
  }, []);
  useEffect(() => {
    if (!visible || error || reduceMotion !== false) return;
    const animation = Animated.loop(Animated.timing(flow, {
      toValue: 1,
      duration: 2200,
      easing: Easing.linear,
      useNativeDriver: false,
      isInteraction: false,
    }));
    animation.start();
    return () => { animation.stop(); flow.setValue(0); };
  }, [error, flow, reduceMotion, visible]);
  useEffect(() => {
    if (!ready || reduceMotion === null) return;
    // The app mounts beneath this opaque cover. Give its layout a painted
    // frame before lifting the cover; never animate an ancestor of glass.
    const animation = Animated.timing(opacity, {
      toValue: 0,
      duration: reduceMotion ? 0 : motion.enter,
      easing: motion.easeOut,
      useNativeDriver: false,
    });
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => animation.start(({ finished }) => {
        if (finished) setVisible(false);
      }));
    });
    return () => { cancelAnimationFrame(frame); animation.stop(); };
  }, [opacity, ready, reduceMotion]);

  if (!visible) return null;
  const gradientStart = flow.interpolate({ inputRange: [0, 1], outputRange: [-1.25, 0] });
  const gradientEnd = flow.interpolate({ inputRange: [0, 1], outputRange: [1.25, 2.5] });
  return (
    <Animated.View
      testID="startup-screen"
      accessibilityRole={error ? 'alert' : 'progressbar'}
      accessibilityLabel={error || 'Opening Morse'}
      accessibilityState={{ busy: !error }}
      accessibilityViewIsModal
      onLayout={() => {
        if (Platform.OS === 'web') document.getElementById('morse-launch')?.remove();
        else SplashScreen.hide();
      }}
      style={[styles.screen, { opacity }]}
    >
      <StatusBar style="light" />
      <Svg width={200} height={200} viewBox={`0 0 ${MARK_CANVAS} ${MARK_CANVAS}`} accessible={false}>
        <Defs>
          <AnimatedGradient
            id="startup-mark"
            x1={gradientStart} y1={gradientStart}
            x2={gradientEnd} y2={gradientEnd}
          >
            {highlightStops.map(({ offset, opacity }) => (
              <Stop key={offset} offset={offset} stopColor={MARK_GRADIENT.from} stopOpacity={opacity} />
            ))}
          </AnimatedGradient>
        </Defs>
        <Path d={MARK_PATH} fill={MARK_GRADIENT.to} />
        <Path d={MARK_PATH} fill="url(#startup-mark)" />
      </Svg>
      <View style={styles.caption}>
        {fontsReady ? <>
          <Text style={type.title2}>Morse</Text>
          <Text style={styles.code} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">{MORSE_CODE_WORDMARK}</Text>
        </> : null}
        {error ? <Text style={styles.error}>{error}</Text> : null}
      </View>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  screen: { ...StyleSheet.absoluteFill, alignItems: 'center', justifyContent: 'center', backgroundColor: colors.canvas, zIndex: 100 },
  // Keep the mark at the exact centre, matching the OS splash and HTML.
  caption: { position: 'absolute', top: '50%', marginTop: 100, alignItems: 'center', gap: space[2], paddingHorizontal: space[6] },
  code: { ...type.monoSmall, color: colors.text3, letterSpacing: 1.5 },
  error: { color: colors.text2, textAlign: 'center', maxWidth: 320 },
});
