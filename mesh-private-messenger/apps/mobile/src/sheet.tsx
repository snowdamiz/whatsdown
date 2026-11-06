import { ActivityModal as Modal, useActivityOverlayViewport } from "./activity-overlays";
// A sheet where the system has none to lend (Android; iPhone uses its own,
// sheet.ios.tsx): the backdrop fades while the sheet slides, each on its own,
// so the dark never travels up the screen with the sheet's edge. It sizes to
// what it holds, rises with the keyboard, and follows a finger down to close.

import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  Animated,
  PanResponder,
  Pressable,
  StyleSheet,
  View,
  type StyleProp,
  type ViewStyle,
} from "react-native";
import { initialWindowMetrics } from "react-native-safe-area-context";

import { KeyboardAvoidingView } from "./keyboard";
import { motion, radius, space, themed } from "./theme";

export type SheetProps = {
  visible: boolean;
  label: string;
  onClose: () => void;
  // Called once the sheet has come to rest, for a field that focuses then.
  onShown?: () => void;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
};

// How far down, as a share of its height, or how fast, a sheet must be pulled
// to close rather than settle back.
const dismissShare = 0.3;
const dismissVelocity = 1.1;

export function Sheet({ visible, label, onClose, onShown, children, style }: SheetProps) {
  const styles = useStyles();
  const { height: windowHeight } = useActivityOverlayViewport();
  // Stays mounted through the exit, so the sheet leaves as it arrived.
  const [mounted, setMounted] = useState(visible);
  const [height, setHeight] = useState(windowHeight);
  const [progress] = useState(() => new Animated.Value(0));
  const [drag] = useState(() => new Animated.Value(0));
  const closing = useRef(false);

  if (visible && !mounted) setMounted(true);

  useEffect(() => {
    if (!mounted) return;
    if (visible) {
      closing.current = false;
      drag.setValue(0);
      Animated.timing(progress, { toValue: 1, duration: motion.enter, easing: motion.easeOut, useNativeDriver: true })
        .start(({ finished }) => { if (finished) onShown?.(); });
    } else {
      Animated.timing(progress, { toValue: 0, duration: motion.exit + 60, easing: motion.easeIn, useNativeDriver: true })
        .start(({ finished }) => { if (finished) setMounted(false); });
    }
  }, [visible, mounted]);

  // A pull down the sheet moves it with the finger; let go far or fast enough
  // and it closes, otherwise it settles back. Pulling up gives a little.
  const pan = useRef(PanResponder.create({
    onMoveShouldSetPanResponder: (_, { dx, dy }) => dy > 6 && Math.abs(dy) > Math.abs(dx) * 1.5,
    onPanResponderMove: (_, { dy }) => drag.setValue(dy > 0 ? dy : dy / 6),
    onPanResponderRelease: (_, { dy, vy }) => {
      if (dy > heightRef.current * dismissShare || vy > dismissVelocity) {
        closing.current = true;
        onCloseRef.current();
      } else {
        Animated.spring(drag, { toValue: 0, ...motion.springSnap, useNativeDriver: true }).start();
      }
    },
    onPanResponderTerminate: () => {
      Animated.spring(drag, { toValue: 0, ...motion.springSnap, useNativeDriver: true }).start();
    },
  })).current;
  const heightRef = useRef(height);
  heightRef.current = height;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  if (!mounted) return null;
  const rest = progress.interpolate({ inputRange: [0, 1], outputRange: [height, 0] });
  return (
    <Modal visible transparent animationType="none" statusBarTranslucent navigationBarTranslucent onRequestClose={onClose}>
      <Animated.View pointerEvents="none" style={[styles.scrim, { opacity: progress }]} />
      {/* The scrim answers a tap outside without announcing itself; the
          system's back gesture is the way out assistive technology takes. */}
      <Pressable accessible={false} importantForAccessibility="no" onPress={onClose} style={StyleSheet.absoluteFill} />
      <KeyboardAvoidingView behavior="padding" pointerEvents="box-none" style={styles.frame}>
        <Animated.View
          {...pan.panHandlers}
          role="dialog"
          accessibilityViewIsModal
          accessibilityLabel={label}
          onLayout={(event) => setHeight(event.nativeEvent.layout.height)}
          style={[
            styles.sheet,
            { maxHeight: windowHeight * 0.9, transform: [{ translateY: Animated.add(rest, drag) }] },
            style,
          ]}
        >
          <View style={styles.grabber} />
          {children}
        </Animated.View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const useStyles = themed(({ colors }) => StyleSheet.create({
  scrim: { ...StyleSheet.absoluteFill, backgroundColor: colors.scrim },
  frame: { flex: 1, justifyContent: "flex-end" },
  // Material's large top corners, resting on the navigation's inset.
  sheet: {
    paddingBottom: Math.max(initialWindowMetrics?.insets.bottom ?? 0, space[3]) + space[3],
    borderTopLeftRadius: radius["4xl"] + space[1],
    borderTopRightRadius: radius["4xl"] + space[1],
    backgroundColor: colors.raised,
  },
  grabber: {
    alignSelf: "center",
    width: space[8],
    height: space[1],
    marginTop: space[3],
    marginBottom: space[4],
    borderRadius: radius.pill,
    backgroundColor: colors.lineStrong,
  },
}));
