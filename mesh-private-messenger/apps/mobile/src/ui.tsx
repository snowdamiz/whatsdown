import {
  Children,
  Fragment,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";
import {
  ActivityIndicator,
  Animated,
  Clipboard,
  Easing,
  Image,
  Modal,
  PanResponder,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  useWindowDimensions,
  View,
  type AccessibilityRole,
  type AccessibilityState,
  type Insets,
  type StyleProp,
  type TextStyle,
  type ViewProps,
  type ViewStyle,
} from "react-native";
import QRCode from "react-native-qrcode-svg";
import { initialWindowMetrics } from "react-native-safe-area-context";
import Svg, {
  Circle,
  Defs,
  LinearGradient,
  Path,
  RadialGradient,
  Rect,
  Stop,
} from "react-native-svg";

import { MAXIMUM_ATTACHMENTS } from "./codec";
import { mentionAt, completeMention, mentionSpans } from "./mentions";
import { placeMenu, type Frame } from "./message-menu";
import { REPLY_SWIPE_TRIGGER, replySwipeOffset, startsReplySwipe } from "./reply-swipe";
import { describeStatus, type MessageStatus } from "./receipts";
import {
  describeReactions,
  rankReactions,
  reactionEmojis,
  reactionLabel,
  summarizeReactions,
  type Reaction,
} from "./reactions";
import { MARK_CANVAS, MARK_GRADIENT, MARK_PATH } from "./brand";
import {
  SCROLLBAR_WIDTH,
  SIDEBAR_INSET,
  SIDEBAR_LIST_TOP,
  SIDEBAR_TOOLBAR_FADE,
  TOOLBAR_BLUR_TAIL,
  TOOLBAR_FADE,
  TOOLBAR_HEIGHT,
  WINDOWS_CONTROLS_WIDTH,
} from "./desktop-layout";
import { formatClock, groupDigits } from "./format";
import { Glass, glassBackdrop, useLiquidGlass, useMaterialized } from "./glass";
import type { Direction } from "./navigation";
import { qrFrames } from "./qr";
import {
  avatarTone,
  control,
  fonts,
  isDesktop,
  motion,
  opacity as opacities,
  radius,
  size as sizes,
  space,
  themed,
  useTheme,
  withAlpha,
  WindowsChromeContext,
  type Theme,
} from "./theme";

// Touch metrics first, then whatever the pointer-driven desktop changes:
// smaller targets, squarer corners and denser spacing.
const desk = (mobile: TextStyle, desktop: TextStyle): TextStyle =>
  isDesktop ? { ...mobile, ...desktop } : mobile;

// The margin between a phone screen's edge and its content.
const screenInset = space[5];

// The step a group of rows sits in from its card's edge.
const rowGroupInset = space[1];

// A message's reactions gather in one pill hung from the bubble's bottom edge,
// overlapping it by two steps; the rest of the pill's height hangs below.
const reactionPillHeight = isDesktop ? space[5] : space[6];
const reactionHang = reactionPillHeight - space[2];

// How long a finger rests on a message before its menu opens, and the menu's
// metrics: its size is known before it is drawn, so it can be placed at once.
const longPressDelay = 350;
const menuPadding = isDesktop ? space[1] : space[1.5];
const menuRowHeight = isDesktop ? control.md : sizes.well.md;
const menuMargin = space[3];
// The small disc that grows in behind a message swiped to reply.
const replySwipeGlyph = sizes.tile.sm;

// Match Root.web.tsx's scrollbar width; floating effects must leave its track clear.
const scrollbarGutter = isDesktop ? SCROLLBAR_WIDTH : 0;

// Any empty part of a desktop toolbar drags the window, as the hidden title
// bar would have. Tauri reads the attribute off the element under the pointer.
const dragRegion: ViewProps = isDesktop
  ? ({ dataSet: { tauriDragRegion: true } } as unknown as ViewProps)
  : {};

// Interactive state changes are driven from the JS thread on purpose: the
// native driver has left opacity stuck at 0 when the keyboard resized the
// layout mid-animation. Only self-contained loops use the native driver.
function useTimed(target: number, duration: number = motion.settle): Animated.Value {
  const [value] = useState(() => new Animated.Value(target));
  useEffect(() => {
    const animation = Animated.timing(value, {
      toValue: target,
      duration,
      easing: motion.easeOut,
      useNativeDriver: false,
    });
    animation.start();
    return () => animation.stop();
  }, [duration, target, value]);
  return value;
}

function useSprung(target: number, config = motion.spring): Animated.Value {
  const [value] = useState(() => new Animated.Value(target));
  useEffect(() => {
    const animation = Animated.spring(value, {
      toValue: target,
      useNativeDriver: false,
      ...config,
    });
    animation.start();
    return () => animation.stop();
  }, [config, target, value]);
  return value;
}

function useLoop(build: (value: Animated.Value) => Animated.CompositeAnimation): Animated.Value {
  const [value] = useState(() => new Animated.Value(0));
  useEffect(() => {
    const loop = Animated.loop(build(value));
    loop.start();
    return () => loop.stop();
    // The builder is a static description of the loop, not reactive input.
  }, [value]);
  return value;
}

const paths = {
  chat: "M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v8a2.5 2.5 0 0 1-2.5 2.5H9.2l-4.4 3.4c-.4.3-.8 0-.8-.4V6.5Z",
  groups:
    "M15.5 19v-1.4a3.6 3.6 0 0 0-3.6-3.6H6.6A3.6 3.6 0 0 0 3 17.6V19M12.5 8a3.25 3.25 0 1 1-6.5 0 3.25 3.25 0 0 1 6.5 0ZM16.5 14.2a3.6 3.6 0 0 1 4.5 3.4V19M15.2 4.9a3.25 3.25 0 0 1 0 6.2",
  person:
    "M19 20v-1.2a4.3 4.3 0 0 0-4.3-4.3H9.3A4.3 4.3 0 0 0 5 18.8V20M15.8 7.8a3.8 3.8 0 1 1-7.6 0 3.8 3.8 0 0 1 7.6 0Z",
  compose:
    "M12 5H6.5A2.5 2.5 0 0 0 4 7.5v10A2.5 2.5 0 0 0 6.5 20h10a2.5 2.5 0 0 0 2.5-2.5V12M17.3 3.7a1.9 1.9 0 0 1 2.7 2.7l-7.4 7.4-3.6.9.9-3.6 7.4-7.4Z",
  plus: "M12 5v14M5 12h14",
  back: "M14.5 5.5 8 12l6.5 6.5",
  chevron: "m9.5 5.5 6.5 6.5-6.5 6.5",
  scan: "M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2M7 12h10",
  lock: "M7.5 10.5V8a4.5 4.5 0 0 1 9 0v2.5M6.5 10.5h11a1.5 1.5 0 0 1 1.5 1.5v6.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 18.5V12a1.5 1.5 0 0 1 1.5-1.5ZM12 14.5v2",
  arrowUp: "M12 19V5M5.5 11.5 12 5l6.5 6.5",
  refresh:
    "M20 6v5h-5M4 18v-5h5M18.4 11A6.5 6.5 0 0 0 6.9 8.2M5.6 13a6.5 6.5 0 0 0 11.5 2.8",
  device:
    "M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2ZM11 17.5h2",
  bell: "M6 16.5V11a6 6 0 0 1 12 0v5.5l1.2 1.5H4.8L6 16.5ZM10 20a2 2 0 0 0 4 0",
  check: "m5.5 12.5 4 4 9-9",
  checks: "m2 12.5 4 4 9-9M11 15l1.5 1.5 9-9",
  close: "m6.5 6.5 11 11M17.5 6.5l-11 11",
  minimize: "M5 12h14",
  maximize: "M5 5h14v14H5Z",
  restore: "M8 8V4h12v12h-4M4 8h12v12H4Z",
  shield:
    "M12 3.5 4.5 6.5v5.2c0 4.3 3.2 7.4 7.5 8.8 4.3-1.4 7.5-4.5 7.5-8.8V6.5L12 3.5ZM8.8 12.2l2.2 2.2 4.4-4.6",
  clock: "M12 7.5V12l3 2M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0Z",
  info: "M12 11v5.5M12 7.8h.01M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0Z",
  warning: "M12 4.5 2.8 19.5h18.4L12 4.5ZM12 10v4.5M12 17.5h.01",
  link: "m10.5 13.5 3-3M8.5 15.5l-1.2 1.2a3.2 3.2 0 0 1-4.5-4.5l3-3a3.2 3.2 0 0 1 4.5 0M15.5 8.5l1.2-1.2a3.2 3.2 0 0 1 4.5 4.5l-3 3a3.2 3.2 0 0 1-4.5 0",
  camera:
    "M4 8.5A1.5 1.5 0 0 1 5.5 7H8l1.5-2h5L16 7h2.5A1.5 1.5 0 0 1 20 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 17.5v-9ZM15 12.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z",
  block: "M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0ZM6 6l12 12",
  timer: "M12 8v4.5l2.8 1.7M9.5 3h5M12 21a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z",
  smile: "M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0ZM9.2 9.8h.01M14.8 9.8h.01M8.6 13.8a3.9 3.9 0 0 0 6.8 0",
  key: "M14.5 9.5 21 3M18.5 5.5 21 8M9 21a6 6 0 1 0 0-12 6 6 0 0 0 0 12Zm0-8.5v.01",
  inbox:
    "M4 13h4.2l1.3 2.5h5l1.3-2.5H20M6.5 5h11l2.5 8v5.5a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5V13l2.5-8Z",
  sliders:
    "M4 8h8M18 8h2M4 16h2M12 16h8M13 8a2 2 0 1 0 4 0 2 2 0 1 0-4 0ZM7 16a2 2 0 1 0 4 0 2 2 0 1 0-4 0Z",
  sun: "M12 3.5v2M12 18.5v2M3.5 12h2M18.5 12h2M6 6l1.4 1.4M16.6 16.6 18 18M6 18l1.4-1.4M16.6 7.4 18 6M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z",
  moon: "M20.5 13.2A8.5 8.5 0 1 1 10.8 3.5a6.6 6.6 0 0 0 9.7 9.7Z",
  // A disc split light and dark: the appearance that follows the device.
  contrast: "M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0ZM12 3.5v17M12 7.5a4.5 4.5 0 0 1 0 9",
  paperclip:
    "m20.6 11.4-8.4 8.4a5.3 5.3 0 0 1-7.5-7.5l8.6-8.6a3.5 3.5 0 0 1 5 5l-8.7 8.6a1.8 1.8 0 0 1-2.5-2.5l8-8",
  file: "M13.5 3.5h-6A1.5 1.5 0 0 0 6 5v14a1.5 1.5 0 0 0 1.5 1.5h9A1.5 1.5 0 0 0 18 19V8l-4.5-4.5ZM13.5 3.5V8H18",
  image:
    "M5.5 4h13A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5v-13A1.5 1.5 0 0 1 5.5 4ZM9 10.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3ZM20 15.5l-4.5-4.5L6.5 20",
  download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14",
  reply: "M9.5 7 4.5 12l5 5M4.5 12H14a5.5 5.5 0 0 1 5.5 5.5V19",
  copy: "M9.5 8h8A1.5 1.5 0 0 1 19 9.5v9a1.5 1.5 0 0 1-1.5 1.5h-8A1.5 1.5 0 0 1 8 18.5v-9A1.5 1.5 0 0 1 9.5 8ZM16 8V5.5A1.5 1.5 0 0 0 14.5 4h-8A1.5 1.5 0 0 0 5 5.5v9A1.5 1.5 0 0 0 6.5 16H8",
};
export type IconName = keyof typeof paths | "qr";

export function Icon({
  name,
  size = 22,
  color,
  strokeWidth = 2,
}: {
  name: IconName;
  size?: number;
  color?: string;
  strokeWidth?: number;
}) {
  const { colors } = useTheme();
  return (
    <Svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color ?? colors.text}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {name === "qr" ? (
        <>
          <Rect x={3.5} y={3.5} width={6.5} height={6.5} rx={1.5} />
          <Rect x={14} y={3.5} width={6.5} height={6.5} rx={1.5} />
          <Rect x={3.5} y={14} width={6.5} height={6.5} rx={1.5} />
          <Path d="M14 14h2.5v2.5H14zM18 14h2.5M20.5 17.5v3M14 20.5h2.5M17.5 18v2.5" />
        </>
      ) : (
        <Path d={paths[name]} />
      )}
    </Svg>
  );
}

export function Tap({
  children,
  onPress,
  onLongPress,
  label,
  role = "button",
  state,
  disabled = false,
  accessible,
  testID,
  style,
  containerStyle,
  hitSlop,
  scaleTo = 0.97,
  pressedOpacity = 0.82,
  feedback = "scale",
  dimDisabled = true,
}: {
  children: ReactNode;
  onPress: () => void;
  onLongPress?: () => void;
  label?: string;
  role?: AccessibilityRole;
  state?: AccessibilityState;
  disabled?: boolean;
  accessible?: boolean;
  testID?: string;
  style?: StyleProp<ViewStyle>;
  containerStyle?: StyleProp<ViewStyle>;
  hitSlop?: number | Insets;
  scaleTo?: number;
  pressedOpacity?: number;
  // `scale` suits buttons; `highlight` washes a full-width row the way native
  // lists do, without shrinking content the thumb is resting on; `none` is
  // for glass, which answers touch itself and must never be dimmed.
  feedback?: "scale" | "highlight" | "none";
  dimDisabled?: boolean;
}) {
  const styles = useStyles();
  const [scale] = useState(() => new Animated.Value(1));
  const [wash] = useState(() => new Animated.Value(0));
  const [hover] = useState(() => new Animated.Value(0));
  const press = (down: boolean) => {
    if (feedback === "none") return;
    if (feedback === "scale") {
      Animated.spring(scale, {
        toValue: down ? scaleTo : 1,
        useNativeDriver: true,
        ...(down ? motion.springSnap : motion.spring),
      }).start();
      return;
    }
    Animated.timing(wash, {
      toValue: down ? 1 : 0,
      duration: down ? 60 : motion.settle,
      easing: motion.easeOut,
      useNativeDriver: true,
    }).start();
  };
  // A pointer resting on a control gets a faint wash before the click, the
  // way desktop rows and toolbar buttons answer the mouse.
  const hovered = (over: boolean) => {
    if (feedback === "none" || disabled) return;
    Animated.timing(hover, {
      toValue: over ? 1 : 0,
      duration: motion.quick,
      easing: motion.easeOut,
      useNativeDriver: true,
    }).start();
  };
  const washRadius = StyleSheet.flatten(style)?.borderRadius;
  const washes = feedback === "highlight" || (isDesktop && feedback !== "none");
  return (
    <Pressable
      accessibilityRole={accessible === false ? undefined : role}
      accessibilityLabel={accessible === false ? undefined : label}
      accessibilityState={
        accessible === false ? undefined : { ...state, disabled }
      }
      // React Native Web reads ARIA props and ignores accessibilityState, so a
      // radio or a selected row says which it is there only through these.
      {...(Platform.OS === "web" && accessible !== false
        ? { "aria-checked": state?.checked, "aria-selected": state?.selected }
        : {})}
      accessible={accessible}
      testID={testID}
      disabled={disabled}
      hitSlop={hitSlop}
      onPress={onPress}
      onLongPress={onLongPress}
      delayLongPress={longPressDelay}
      onPressIn={() => press(true)}
      onPressOut={() => press(false)}
      onHoverIn={isDesktop ? () => hovered(true) : undefined}
      onHoverOut={isDesktop ? () => hovered(false) : undefined}
      style={containerStyle}
    >
      {({ pressed }) => (
        <Animated.View
          style={[
            style,
            feedback === "scale" && { transform: [{ scale }] },
            pressed && feedback === "scale" && { opacity: pressedOpacity },
            disabled && dimDisabled && styles.disabled,
          ]}
        >
          {washes ? (
            <Animated.View
              pointerEvents="none"
              style={[
                styles.wash,
                {
                  opacity: Animated.add(wash, Animated.multiply(hover, 0.6)).interpolate({
                    inputRange: [0, 1],
                    outputRange: [0, 1],
                    extrapolate: "clamp",
                  }),
                  borderRadius: washRadius,
                },
              ]}
            />
          ) : null}
          {children}
        </Animated.View>
      )}
    </Pressable>
  );
}

// Fades and lifts a block into place once. Chunks of a screen stagger by
// passing increasing delays. Where Liquid Glass is drawn the block only
// lifts: fading an ancestor stops UIKit rendering any glass inside it, which
// left glass buttons invisible but still tappable.
export function Reveal({
  children,
  delay = 0,
  distance = 12,
  style,
}: {
  children: ReactNode;
  delay?: number;
  distance?: number;
  style?: StyleProp<ViewStyle>;
}) {
  const fade = !useLiquidGlass();
  const [progress] = useState(() => new Animated.Value(0));
  useEffect(() => {
    const animation = Animated.timing(progress, {
      toValue: 1,
      duration: 420,
      delay,
      easing: motion.easeOut,
      useNativeDriver: false,
    });
    animation.start();
    return () => animation.stop();
  }, [delay, progress]);
  return (
    <Animated.View
      style={[
        style,
        {
          ...(fade && { opacity: progress }),
          transform: [
            {
              translateY: progress.interpolate({
                inputRange: [0, 1],
                outputRange: [distance, 0],
              }),
            },
          ],
        },
      ]}
    >
      {children}
    </Animated.View>
  );
}

// Mount/exit bookkeeping shared by anything that leaves softly: `progress`
// springs to 1 on show and eases to 0 on hide, and `mounted` only drops once
// the exit has finished.
function usePresence(visible: boolean): { mounted: boolean; progress: Animated.Value } {
  const [mounted, setMounted] = useState(visible);
  const [progress] = useState(() => new Animated.Value(visible ? 1 : 0));
  useEffect(() => {
    if (visible) {
      setMounted(true);
      const animation = Animated.spring(progress, {
        toValue: 1,
        useNativeDriver: false,
        ...motion.springSoft,
      });
      animation.start();
      return () => animation.stop();
    }
    const animation = Animated.timing(progress, {
      toValue: 0,
      duration: motion.exit,
      easing: motion.easeIn,
      useNativeDriver: false,
    });
    animation.start(({ finished }) => {
      if (finished) setMounted(false);
    });
    return () => animation.stop();
  }, [progress, visible]);
  return { mounted, progress };
}

// Keeps children mounted through a soft exit so nothing blinks out of
// existence. Enter springs in; exit is quicker and quieter.
export function Presence({
  visible,
  children,
  style,
  offset = -10,
}: {
  visible: boolean;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
  offset?: number;
}) {
  const { mounted, progress } = usePresence(visible);
  if (!mounted) return null;
  return (
    <Animated.View
      pointerEvents={visible ? "box-none" : "none"}
      style={[
        style,
        {
          opacity: progress,
          transform: [
            {
              translateY: progress.interpolate({
                inputRange: [0, 1],
                outputRange: [offset, 0],
              }),
            },
            {
              scale: progress.interpolate({
                inputRange: [0, 1],
                outputRange: [0.96, 1],
              }),
            },
          ],
        },
      ]}
    >
      {children}
    </Animated.View>
  );
}

// Every screen change runs through here. The incoming screen slides a short
// distance from the side it came from while a canvas-coloured veil lifts off
// it. The veil, not the screen, carries the fade: glass controls inside the
// screen stop rendering if any ancestor's opacity is animated.
export function ScreenTransition({
  screenKey,
  direction,
  children,
  style,
  pointerEvents,
}: {
  screenKey: string;
  direction: Direction;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
  pointerEvents?: "none" | "auto";
}) {
  const styles = useStyles();
  const [progress] = useState(() => new Animated.Value(0));
  const [origin] = useState(() => new Animated.ValueXY({ x: 0, y: 0 }));
  useLayoutEffect(() => {
    // A pane in a desktop window changes content rather than pushing screens,
    // so it moves less and settles sooner.
    const slide = isDesktop ? space[3.5] : space[7];
    origin.setValue(
      direction === "forward"
        ? { x: slide, y: 0 }
        : direction === "backward"
          ? { x: -slide, y: 0 }
          : { x: 0, y: isDesktop ? space[1.5] : space[2.5] },
    );
    progress.setValue(0);
    const animation = Animated.timing(progress, {
      toValue: 1,
      duration: isDesktop ? motion.settle : motion.enter,
      easing: motion.easeOut,
      useNativeDriver: false,
    });
    animation.start();
    return () => animation.stop();
    // Direction is captured at the moment the screen key changes.
  }, [origin, progress, screenKey]);
  const remaining = progress.interpolate({ inputRange: [0, 1], outputRange: [1, 0] });
  return (
    <Animated.View
      pointerEvents={pointerEvents}
      style={[
        style,
        {
          transform: [
            { translateX: Animated.multiply(remaining, origin.x) },
            { translateY: Animated.multiply(remaining, origin.y) },
          ],
        },
      ]}
    >
      {children}
      <Animated.View pointerEvents="none" style={[styles.veil, { opacity: remaining }]} />
    </Animated.View>
  );
}

// A slow, barely-there scale loop for resting hero elements.
export function Breathing({
  children,
  style,
}: {
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  const phase = useLoop((value) =>
    Animated.sequence([
      Animated.timing(value, {
        toValue: 1,
        duration: 1700,
        easing: motion.easeInOut,
        useNativeDriver: true,
      }),
      Animated.timing(value, {
        toValue: 0,
        duration: 1700,
        easing: motion.easeInOut,
        useNativeDriver: true,
      }),
    ]),
  );
  return (
    <Animated.View
      style={[
        style,
        {
          transform: [
            { scale: phase.interpolate({ inputRange: [0, 1], outputRange: [1, 1.035] }) },
          ],
        },
      ]}
    >
      {children}
    </Animated.View>
  );
}

// Soft radial light behind hero content. Gives the flat canvas a sense of
// depth without introducing a second surface colour.
export function Glow({
  size = 520,
  top = -size * 0.55,
  opacity = opacities.glow,
  color,
  style,
}: {
  size?: number;
  top?: number;
  opacity?: number;
  color?: string;
  style?: StyleProp<ViewStyle>;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const tone = color ?? colors.accent;
  return (
    <Svg
      pointerEvents="none"
      width={size}
      height={size}
      viewBox="0 0 100 100"
      style={[styles.glow, { top, left: "50%", marginLeft: -size / 2 }, style]}
    >
      <Defs>
        <RadialGradient id="glow" cx="50%" cy="50%" r="50%">
          <Stop offset="0" stopColor={tone} stopOpacity={opacity} />
          <Stop offset="0.5" stopColor={tone} stopOpacity={opacity * 0.32} />
          <Stop offset="1" stopColor={tone} stopOpacity={0} />
        </RadialGradient>
      </Defs>
      <Circle cx={50} cy={50} r={50} fill="url(#glow)" />
    </Svg>
  );
}

// An accent ring that fades in around a focused input. Sits one pixel outside
// the shell so it replaces, rather than doubles, the resting hairline.
export function FocusRing({
  progress,
  radius: ringRadius,
}: {
  progress: Animated.Value;
  radius: number;
}) {
  const styles = useStyles();
  return (
    <Animated.View
      pointerEvents="none"
      style={[styles.focusRing, { borderRadius: ringRadius, opacity: progress }]}
    />
  );
}

export function useFocusProgress(focused: boolean): Animated.Value {
  return useTimed(focused ? 1 : 0);
}

// Tells a list which keys appeared since its last render so only genuinely
// new rows animate in. Nothing is fresh until `scope` matches the loaded data,
// and a scope change (opening another conversation) resets the baseline.
export function useFreshKeys(
  keys: readonly string[],
  scope: string | null,
): (key: string) => boolean {
  const signature = keys.join("\n");
  const [known, setKnown] = useState(() => ({ scope, signature }));
  useEffect(() => {
    setKnown({ scope, signature });
  }, [scope, signature]);
  const baseline =
    scope !== null && known.scope === scope
      ? new Set(known.signature ? known.signature.split("\n") : [])
      : null;
  return (key) => baseline !== null && !baseline.has(key);
}

export function Button({
  label,
  accessibilityLabel,
  onPress,
  variant = "primary",
  size = "md",
  icon,
  disabled = false,
  testID,
}: {
  label: string;
  accessibilityLabel?: string;
  onPress: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "md" | "sm";
  icon?: IconName;
  disabled?: boolean;
  testID?: string;
}) {
  const { colors, elevation } = useTheme();
  const styles = useStyles();
  // Every button with a surface is Liquid Glass where the system draws it:
  // the primary action tinted with the accent, a destructive one with the
  // danger colour, the rest clear. Ghost buttons are text alone and stay so.
  const liquid = useLiquidGlass() && variant !== "ghost";
  const textColor =
    liquid && disabled
      ? colors.text3
      : variant === "primary"
        ? colors.onAccent
        : variant === "danger"
          ? colors.danger
          : variant === "ghost"
            ? colors.accent
            : colors.text;
  const shape = [
    styles.button,
    size === "sm" && styles.buttonSmall,
    // Optical balance: the icon side carries slightly less padding.
    icon && (size === "sm" ? styles.buttonSmallWithIcon : styles.buttonWithIcon),
  ];
  const iconSize = isDesktop
    ? size === "sm" ? sizes.icon.sm : sizes.icon.md
    : size === "sm" ? sizes.icon.md : sizes.icon.lg;
  const content = (
    <>
      {icon ? <Icon name={icon} size={iconSize} color={textColor} /> : null}
      <Text
        style={[
          styles.buttonText,
          size === "sm" && styles.buttonTextSmall,
          { color: textColor },
        ]}
      >
        {label}
      </Text>
    </>
  );
  if (liquid) {
    // A disabled button loses its tint along with its label's colour, so it
    // reads as inert glass rather than a dimmed call to action.
    const tint = disabled
      ? undefined
      : variant === "primary"
        ? colors.accent
        : variant === "danger"
          ? withAlpha(colors.danger, 0.2)
          : undefined;
    return (
      <Tap
        label={accessibilityLabel ?? label}
        onPress={onPress}
        disabled={disabled}
        testID={testID}
        feedback="none"
        dimDisabled={false}
      >
        <Glass interactive tint={tint} style={shape}>
          {content}
        </Glass>
      </Tap>
    );
  }
  return (
    <Tap
      label={accessibilityLabel ?? label}
      onPress={onPress}
      disabled={disabled}
      testID={testID}
      style={[
        shape,
        variant === "primary" && styles.buttonPrimary,
        variant === "primary" && size === "md" && !disabled && elevation.accent,
        variant === "secondary" && styles.buttonSecondary,
        variant === "danger" && styles.buttonDanger,
      ]}
    >
      {content}
    </Tap>
  );
}

export function IconButton({
  name,
  label,
  onPress,
  variant = "plain",
  disabled = false,
  dimDisabled = true,
  spinning = false,
  size = isDesktop ? control.sm : sizes.hit,
  glass = true,
  testID,
}: {
  name: IconName;
  label: string;
  onPress: () => void;
  // On desktop, `plain` is the neutral toolbar glyph that sits beside the
  // window controls; `tonal` and `filled` keep their surfaces for emphasis.
  // `soft` is a quiet accent disc for an action offered inside another
  // surface, such as beside a name in a list.
  variant?: "plain" | "tonal" | "filled" | "soft";
  disabled?: boolean;
  dimDisabled?: boolean;
  spinning?: boolean;
  size?: number;
  // Tonal and filled icon buttons are toolbar controls, so they render as
  // Liquid Glass (filled ones tinted) where the system offers it. Pass false
  // for a button that lives inside another surface.
  glass?: boolean;
  testID?: string;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const liquid = useLiquidGlass() && glass && (variant === "tonal" || variant === "filled");
  const [turn] = useState(() => new Animated.Value(0));
  useEffect(() => {
    if (!spinning) return;
    turn.setValue(0);
    const loop = Animated.loop(
      Animated.timing(turn, {
        toValue: 1,
        duration: 900,
        easing: Easing.linear,
        useNativeDriver: false,
      }),
    );
    loop.start();
    return () => {
      // Finish the current revolution instead of freezing mid-turn.
      loop.stop();
      turn.stopAnimation((value) =>
        Animated.timing(turn, {
          toValue: Math.ceil(value),
          duration: motion.settle,
          easing: motion.easeOut,
          useNativeDriver: false,
        }).start(() => turn.setValue(0)),
      );
    };
  }, [spinning, turn]);
  const glyph = (
    <Animated.View
      style={[
        liquid && disabled && dimDisabled && styles.disabled,
        {
          transform: [
            {
              rotate: turn.interpolate({
                inputRange: [0, 1],
                outputRange: ["0deg", "360deg"],
              }),
            },
          ],
        },
      ]}
    >
      <Icon
        name={name}
        size={isDesktop ? Math.round(size * 0.56) : size * 0.5}
        color={
          variant === "filled"
            ? colors.onAccent
            : variant === "soft"
              ? colors.accent
              : variant === "plain"
                ? isDesktop
                  ? colors.text2
                  : colors.accent
                : colors.text
        }
        strokeWidth={isDesktop ? 1.9 : 2.1}
      />
    </Animated.View>
  );
  const shape = [styles.iconButton, { width: size, height: size }];
  if (liquid) {
    return (
      <Tap
        label={label}
        onPress={onPress}
        disabled={disabled}
        dimDisabled={false}
        testID={testID}
        feedback="none"
        hitSlop={size < 40 ? Math.ceil((40 - size) / 2) : undefined}
        containerStyle={{ width: size, height: size }}
      >
        <Glass interactive tint={variant === "filled" ? colors.accent : undefined} style={shape}>
          {glyph}
        </Glass>
      </Tap>
    );
  }
  return (
    <Tap
      label={label}
      onPress={onPress}
      disabled={disabled}
      dimDisabled={dimDisabled}
      testID={testID}
      scaleTo={0.95}
      pressedOpacity={variant === "plain" ? 0.55 : 0.85}
      hitSlop={size < 40 ? Math.ceil((40 - size) / 2) : undefined}
      containerStyle={{ width: size, height: size }}
      style={[
        shape,
        variant === "tonal" && styles.iconButtonTonal,
        variant === "filled" && styles.iconButtonFilled,
        variant === "soft" && styles.iconButtonSoft,
      ]}
    >
      {glyph}
    </Tap>
  );
}

// Controls float over content instead of sitting above it, so lists scroll
// underneath the glass. These are the heights content must leave clear.
const tabHeight = control["2xl"];
const tabPillPadding = space[1.5];
const tabGap = space[3];
// The pill rests on the home indicator's inset where there is one. Android's
// navigation bar has no indicator to rest on, so the pill clears it instead.
const tabBarPadding = Math.max((initialWindowMetrics?.insets.bottom ?? 0) - space[1.5], screenInset) +
  (Platform.OS === "android" ? space[2.5] : 0);
const tabBarHeight = tabHeight + 2 * (tabPillPadding + 1);
const paneHeaderPadding = space[4];
// Centre pane controls on the inset sidebar's toolbar.
const paneHeaderHeight = TOOLBAR_HEIGHT + 2 * SIDEBAR_INSET;
const paneContentTop = paneHeaderHeight + space[3];
export const chrome = {
  // A phone header holds a hit-target-sized control with breathing room; the
  // large-title and chat headers give theirs more.
  header: isDesktop ? paneHeaderHeight : sizes.hit + 2 * space[1.5],
  largeHeader: isDesktop ? paneHeaderHeight : sizes.hit + 2 * space[2.5],
  chatHeader: isDesktop ? paneHeaderHeight : sizes.avatar.md + 2 * space[2],
  // The desktop sidebar's strip, with the list switch and actions in it.
  sidebar: TOOLBAR_HEIGHT,
  sidebarControl: control.xs,
  tabBar: tabBarHeight,
  // Space a list leaves at its end so the last row clears the floating bar.
  tabBarSpace: tabBarHeight + tabBarPadding + space[2.5],
};

// How far the pane's colour reaches past a floating edge. A phone's larger
// type needs a longer ramp than a dense desktop pane.
const edgeFade = isDesktop ? TOOLBAR_FADE : space[8];

// The pane's own colour bleeding into content along a floating edge, so text
// stays legible as rows pass beneath the controls.
function ScrollEdge({
  side,
  height,
  color,
}: {
  side: "top" | "bottom";
  height: number;
  color?: string;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const tone = color ?? colors.canvas;
  const towardsContent = side === "top";
  // Gradient ids are shared by every SVG on a web page, so each side and
  // colour names its own, or a bottom edge would borrow a top edge's ramp.
  const id = `edge-${side}-${tone.replace(/[^0-9a-z]/gi, "")}`;
  return (
    <View
      pointerEvents="none"
      style={[styles.scrollEdge, towardsContent ? styles.scrollEdgeTop : styles.scrollEdgeBottom]}
    >
      <Svg width="100%" height={height}>
        <Defs>
          <LinearGradient
            id={id}
            x1="0"
            y1={towardsContent ? "0" : "1"}
            x2="0"
            y2={towardsContent ? "1" : "0"}
          >
            <Stop offset="0" stopColor={tone} stopOpacity={1} />
            <Stop offset="0.45" stopColor={tone} stopOpacity={0.86} />
            <Stop offset="0.75" stopColor={tone} stopOpacity={0.4} />
            <Stop offset="1" stopColor={tone} stopOpacity={0} />
          </LinearGradient>
        </Defs>
        <Rect x={0} y={0} width="100%" height={height} fill={`url(#${id})`} />
      </Svg>
    </View>
  );
}

// Content dissolving under desktop chrome: a backdrop blur that fades out
// past the bar's lower edge, so rows frost as they slide beneath the controls
// instead of being cut off by a line. The pane colour fading in over it (the
// ScrollEdge) keeps the controls legible.
function Frost({ height, tail }: { height: number; tail: number }) {
  const styles = useStyles();
  return (
    <View
      pointerEvents="none"
      style={[
        styles.frost,
        glassBackdrop,
        { height: height + tail },
        {
          maskImage: `linear-gradient(#000 ${height - 10}px, transparent ${height + tail}px)`,
        } as unknown as ViewStyle,
      ]}
    />
  );
}

// The strip every header is built on. It floats over the content with the
// pane colour fading in beneath it; on desktop the content also frosts as it
// passes under. At rest the strip is indistinguishable from the pane, so the
// window has no title bar to speak of. Empty parts of it drag the window, and
// titles let the pointer through for the same reason. Without glass the
// desktop strip is simply solid.
function Toolbar({
  height,
  color,
  fade = edgeFade,
  children,
}: {
  height: number;
  color?: string;
  fade?: number;
  children: ReactNode;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const pane = color ?? colors.canvas;
  const glass = useLiquidGlass();
  const solid = isDesktop && !glass;
  return (
    <View style={[styles.chrome, { height }]} pointerEvents={toolbarRow}>
      {isDesktop && glass ? <Frost height={height} tail={Math.min(TOOLBAR_BLUR_TAIL, fade)} /> : null}
      {solid ? null : <ScrollEdge side="top" height={height + fade} color={pane} />}
      {isDesktop ? (
        <View {...dragRegion} style={[StyleSheet.absoluteFill, { right: scrollbarGutter }, solid && { backgroundColor: pane }]} />
      ) : null}
      {children}
    </View>
  );
}

// Toolbar rows let clicks in their empty space reach the drag region behind
// them on desktop; on a phone the bar simply absorbs the touch as before.
const toolbarRow = isDesktop ? ("box-none" as const) : undefined;

// All pane headers share the same full-width row and desktop spacing.
// Variants retain their mobile padding, control gaps, and header heights.
function PaneHeader({
  variant = "header",
  inset = 0,
  color,
  children,
}: {
  variant?: "header" | "largeHeader" | "chatHeader";
  inset?: number;
  color?: string;
  children: ReactNode;
}) {
  const styles = useStyles();
  const windowsChrome = useContext(WindowsChromeContext);
  return (
    <Toolbar height={chrome[variant]} color={color}>
      <View
        style={[
          styles.headerRow,
          styles[variant],
          isDesktop && {
            paddingHorizontal: paneHeaderPadding,
            // `inset` is how far the window buttons reach into the row, not
            // where the row may start: a round control set beside the round
            // window buttons needs more than the row's own margin to read as
            // the app's rather than the window's.
            paddingLeft: inset ? inset + paneHeaderPadding + space[2.5] : paneHeaderPadding,
            paddingRight: paneHeaderPadding + (windowsChrome ? WINDOWS_CONTROLS_WIDTH : 0),
          },
        ]}
        pointerEvents={toolbarRow}
      >
        {children}
      </View>
    </Toolbar>
  );
}

// An invisible drag handle across the top of screens that have no toolbar of
// their own, such as onboarding, so the window still moves like a window.
export function DragStrip() {
  const styles = useStyles();
  if (!isDesktop) return null;
  return <View {...dragRegion} style={styles.dragStrip} />;
}

// A screen with floating chrome. Content renders first so the bar paints on
// top of it without relying on zIndex; content styles reserve the bar's height.
export function Page({
  header,
  children,
  style,
}: {
  header?: ReactNode;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  return (
    <View style={[layout.flex, style]}>
      {children}
      {header}
    </View>
  );
}

// Toolbar buttons are glass discs wherever glass is drawn, and tonal discs
// where it is not.
const toolbarButton = "tonal";

export function Header({
  title,
  onBack,
  backLabel = "Back",
  action,
  inset = 0,
}: {
  title: string;
  onBack?: () => void;
  backLabel?: string;
  action?: ReactNode;
  // Space for the macOS window buttons when this header spans the window.
  inset?: number;
}) {
  const styles = useStyles();
  const back = onBack ? (
    <IconButton
      name="back"
      label={backLabel}
      onPress={onBack}
      variant={toolbarButton}
      size={isDesktop ? sizes.avatar.xs : sizes.avatar.md}
    />
  ) : null;
  // A desktop pane header reads left to right: back, title, then actions,
  // across the full pane, starting clear of the window buttons when it
  // spans the window.
  if (isDesktop) {
    return (
      <PaneHeader inset={inset}>
        {back}
        <Text
          accessibilityRole="header"
          numberOfLines={1}
          style={[styles.toolbarTitle, layout.flex, styles.passive]}
        >
          {title}
        </Text>
        {action ? <View style={styles.headerActions}>{action}</View> : null}
      </PaneHeader>
    );
  }
  return (
    <PaneHeader>
      <View style={styles.headerSide}>{back}</View>
      <Text accessibilityRole="header" numberOfLines={1} style={styles.headerTitle}>
        {title}
      </Text>
      <View style={[styles.headerSide, styles.headerSideEnd]}>{action}</View>
    </PaneHeader>
  );
}

export function LargeHeader({
  title,
  actions,
  color,
}: {
  title: string;
  actions?: ReactNode;
  // The colour of the pane this header floats over, when not the canvas.
  color?: string;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <PaneHeader variant="largeHeader" color={color}>
      <Text
        accessibilityRole="header"
        numberOfLines={1}
        style={[isDesktop ? styles.toolbarTitle : type.largeTitle, layout.flex, isDesktop && styles.passive]}
      >
        {title}
      </Text>
      {actions ? <View style={styles.headerActions}>{actions}</View> : null}
    </PaneHeader>
  );
}

// The sidebar's top strip, laid out like a window's toolbar: the window
// controls and switch between lists lead, and the list's actions trail,
// leaving the middle free to drag the window. Rows blur under it as
// the list scrolls.
export function SidebarChrome({
  inset,
  tabs,
  actions,
}: {
  inset: number;
  tabs: ReactNode;
  actions?: ReactNode;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const glass = useLiquidGlass();
  return (
    <Toolbar height={chrome.sidebar} color={glass ? "transparent" : colors.sidebar} fade={SIDEBAR_TOOLBAR_FADE}>
      <View
        style={[styles.sidebarHeader, { paddingLeft: inset ? inset + 6 : 12 }]}
        pointerEvents={toolbarRow}
      >
        {tabs}
        <View style={layout.flex} pointerEvents="none" />
        {actions ? <View style={styles.headerActions}>{actions}</View> : null}
      </View>
    </Toolbar>
  );
}

// The bar over a thread: who it is with, and the way to its details. The
// name stands alone; a state worth knowing mid-conversation (verified, keys
// changed, blocked) is a glyph at its shoulder, as in the list. The avatar
// can be a control of its own, such as the way to a group's members.
export function ChatHeader({
  name,
  avatar,
  colorSeed,
  group = false,
  mark,
  onBack,
  backLabel = "Back",
  onAvatarPress,
  avatarLabel,
  onInfo,
  infoLabel,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  group?: boolean;
  mark?: { icon: IconName; color: string; label: string };
  // Omitted when the conversation list is already on screen beside the thread.
  onBack?: () => void;
  backLabel?: string;
  onAvatarPress?: () => void;
  avatarLabel?: string;
  onInfo: () => void;
  infoLabel: string;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  const avatarSize = isDesktop ? sizes.avatar.xs : sizes.avatar.md;
  const picture = <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={avatarSize} group={group} />;
  return (
    <PaneHeader variant="chatHeader">
      {onBack ? (
        <IconButton
          name="back"
          label={backLabel}
          onPress={onBack}
          variant={toolbarButton}
          size={avatarSize}
        />
      ) : null}
      {onAvatarPress ? (
        <Tap
          label={avatarLabel ?? name}
          onPress={onAvatarPress}
          scaleTo={0.94}
          hitSlop={space[1.5]}
          style={{ borderRadius: avatarSize / 2 }}
        >
          {picture}
        </Tap>
      ) : (
        picture
      )}
      <View style={[styles.chatTitle, isDesktop && styles.passive]}>
        <Text numberOfLines={1} style={[type.headline, styles.chatName]}>
          {name}
        </Text>
        {mark ? (
          <View accessible accessibilityRole="image" accessibilityLabel={mark.label}>
            <Icon
              name={mark.icon}
              size={isDesktop ? sizes.icon.sm : sizes.icon.md}
              color={mark.color}
              strokeWidth={2.3}
            />
          </View>
        ) : null}
      </View>
      <IconButton
        name="info"
        label={infoLabel}
        onPress={onInfo}
        variant={toolbarButton}
        size={avatarSize}
      />
    </PaneHeader>
  );
}

const initials = (name: string): string => {
  name = name.replace(/^@/, "");
  const parts = name.split(/[._\-\s]+/).filter(Boolean);
  const letters =
    parts.length >= 2 ? `${parts[0]![0]}${parts[1]![0]}` : name.slice(0, 2);
  return letters.toUpperCase();
};

export function Avatar({
  name,
  uri,
  colorSeed,
  size = 48,
  group = false,
}: {
  name: string;
  uri?: string;
  // What the hue hashes from. An identity is seeded by its account or group
  // ID wherever one is known, so a person is the same colour in every list,
  // header and bubble, and keeps it through a nickname. The name is the
  // fallback for identities that have no ID yet, such as a pending invitation.
  colorSeed?: string;
  size?: number;
  group?: boolean;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const tone = avatarTone(colorSeed ?? name);
  const [failedUri, setFailedUri] = useState<string>();
  if (uri && uri !== failedUri) return (
    <Image source={{ uri }} accessibilityLabel={`${name} photo`} onError={() => setFailedUri(uri)}
      style={{ width: size, height: size, borderRadius: size / 2 }} resizeMode="cover" />
  );
  const gradientId = `avatar-${tone.index}`;
  return (
    <View style={{ width: size, height: size }}>
      <Svg width={size} height={size} viewBox="0 0 100 100">
        <Defs>
          <LinearGradient id={gradientId} x1="0" y1="0" x2="1" y2="1">
            <Stop offset="0" stopColor={tone.from} />
            <Stop offset="1" stopColor={tone.to} />
          </LinearGradient>
        </Defs>
        <Circle cx={50} cy={50} r={50} fill={`url(#${gradientId})`} />
        {/* A faint inner ring separates the disc from the canvas. */}
        <Circle cx={50} cy={50} r={49} stroke={withAlpha(colors.white, 0.14)} strokeWidth={2} fill="none" />
      </Svg>
      <View style={styles.avatarOverlay}>
        {group ? (
          <Icon name="groups" size={size * 0.48} color={colors.white} strokeWidth={2.2} />
        ) : (
          <Text
            style={{
              fontFamily: fonts.semibold,
              fontSize: size * 0.38,
              letterSpacing: -0.5,
              color: colors.white,
            }}
          >
            {initials(name)}
          </Text>
        )}
      </View>
    </View>
  );
}

// A picture that is also the control for changing it: the avatar with a
// camera on its shoulder, as every messenger draws a group or profile photo
// that can be edited. The badge spins while a photo is being chosen. Where
// the photo cannot be edited at all, there is no badge and no control, just
// the picture.
export function PhotoButton({
  name,
  uri,
  colorSeed,
  group = false,
  size,
  editable = true,
  disabled = false,
  busy = false,
  onPress,
}: {
  name: string;
  uri?: string;
  colorSeed?: string;
  group?: boolean;
  size: number;
  editable?: boolean;
  // Editing is momentarily unavailable, as while another change saves.
  disabled?: boolean;
  busy?: boolean;
  onPress: () => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const badge = Math.round(size * 0.34);
  const picture = (
    <View style={{ width: size, height: size }}>
      <Avatar name={name} uri={uri} colorSeed={colorSeed} size={size} group={group} />
      {editable ? (
        <View style={[styles.photoBadge, { width: badge, height: badge, borderRadius: badge / 2 }]}>
          {busy ? (
            <ActivityIndicator size="small" color={colors.onAccent} />
          ) : (
            <Icon name="camera" size={Math.round(badge * 0.56)} color={colors.onAccent} strokeWidth={2.2} />
          )}
        </View>
      ) : null}
    </View>
  );
  if (!editable) return picture;
  return (
    <Tap
      label={uri ? "Change photo" : "Add photo"}
      onPress={onPress}
      disabled={disabled || busy}
      dimDisabled={false}
      scaleTo={0.96}
      style={{ borderRadius: size / 2 }}
    >
      {picture}
    </Tap>
  );
}

// The app mark: the same geometry the launcher icons are rendered from.
export function AppGlyph({ size = sizes.mark.lg }: { size?: number }) {
  const { colors } = useTheme();
  const styles = useStyles();
  const canvas = MARK_CANVAS;
  return (
    <View style={[{ width: size, height: size, borderRadius: size * 0.26 }, styles.glyph]}>
      <Svg width={size} height={size} viewBox={`0 0 ${canvas} ${canvas}`}>
        <Defs>
          <LinearGradient id="glyph" x1="0" y1="0" x2="1" y2="1">
            <Stop offset="0" stopColor={MARK_GRADIENT.from} />
            <Stop offset="1" stopColor={MARK_GRADIENT.to} />
          </LinearGradient>
          <LinearGradient id="glyph-sheen" x1="0" y1="0" x2="0" y2="1">
            <Stop offset="0" stopColor={colors.white} stopOpacity={0.22} />
            <Stop offset="0.5" stopColor={colors.white} stopOpacity={0} />
          </LinearGradient>
        </Defs>
        <Rect x={0} y={0} width={canvas} height={canvas} rx={canvas * 0.26} fill="url(#glyph)" />
        <Rect x={0} y={0} width={canvas} height={canvas} rx={canvas * 0.26} fill="url(#glyph-sheen)" />
        <Path d={MARK_PATH} fill={colors.white} />
      </Svg>
    </View>
  );
}

// The avatar a hero draws when it is not handed one: on a desktop pane a
// detail view's size, on a phone the large one.
export const heroAvatarSize = isDesktop ? sizes.avatar["2xl"] : sizes.avatar["3xl"];

export function Hero({
  name,
  avatar,
  colorSeed,
  group = false,
  leading,
  title,
  subtitle,
  badge,
  actions,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  group?: boolean;
  // Stands in for the avatar: a PhotoButton where the picture can be changed.
  leading?: ReactNode;
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  // Buttons that act on the identity shown, set in a row beneath the words.
  actions?: ReactNode;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  const picture = leading ?? <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={heroAvatarSize} group={group} />;
  // A desktop pane puts the identity on one line, avatar beside the words,
  // the way a window's detail views do; a phone stacks it under a large avatar.
  if (isDesktop) {
    return (
      <View style={styles.heroDesktop}>
        {picture}
        <View style={styles.heroDesktopText}>
          <Text numberOfLines={1} style={type.title2}>
            {title}
          </Text>
          {subtitle ? <Text style={type.subhead}>{subtitle}</Text> : null}
          {badge ? <View style={styles.heroDesktopBadge}>{badge}</View> : null}
          {actions ? <View style={styles.heroActions}>{actions}</View> : null}
        </View>
      </View>
    );
  }
  return (
    <View style={styles.hero}>
      {picture}
      <Text style={type.title2}>{title}</Text>
      {subtitle ? <Text style={[type.subhead, layout.centerText]}>{subtitle}</Text> : null}
      {badge}
      {actions ? <View style={[styles.heroActions, styles.heroActionsCentred]}>{actions}</View> : null}
    </View>
  );
}

export function Badge({
  label,
  tone = "accent",
  icon,
}: {
  label: string;
  tone?: "accent" | "muted" | "danger" | "success" | "warning";
  icon?: IconName;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const color =
    tone === "accent"
      ? colors.accent
      : tone === "danger"
        ? colors.danger
        : tone === "success"
          ? colors.success
          : tone === "warning"
            ? colors.warning
            : colors.text2;
  const background =
    tone === "accent"
      ? colors.accentSoft
      : tone === "danger"
        ? colors.dangerSoft
        : tone === "success"
          ? colors.successSoft
          : tone === "warning"
            ? colors.warningSoft
            : colors.raised;
  return (
    <View style={[styles.badge, { backgroundColor: background }]}>
      {icon ? <Icon name={icon} size={sizes.icon.xs} color={color} strokeWidth={2.4} /> : null}
      <Text style={[styles.badgeText, { color }]}>{label}</Text>
    </View>
  );
}

export function Field({
  label,
  value,
  onChangeText,
  placeholder,
  multiline = false,
  prefix,
  hint,
  autoFocus = false,
  maxLength,
}: {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  placeholder: string;
  multiline?: boolean;
  prefix?: string;
  hint?: string;
  autoFocus?: boolean;
  maxLength?: number;
}) {
  const { colors, type } = useTheme();
  const styles = useStyles();
  const [focused, setFocused] = useState(false);
  const focus = useFocusProgress(focused);
  return (
    <View style={styles.field}>
      <Text style={type.label}>{label}</Text>
      <Animated.View
        style={[
          styles.inputShell,
          multiline && styles.inputShellMultiline,
          {
            backgroundColor: focus.interpolate({
              inputRange: [0, 1],
              outputRange: [colors.surface, colors.raised],
            }),
          },
        ]}
      >
        <FocusRing progress={focus} radius={isDesktop ? 8 : radius.md} />
        {prefix ? <Text style={styles.inputPrefix}>{prefix}</Text> : null}
        <TextInput
          accessibilityLabel={label}
          testID={label}
          autoCapitalize="none"
          autoCorrect={false}
          autoFocus={autoFocus}
          maxLength={maxLength}
          multiline={multiline}
          onBlur={() => setFocused(false)}
          onChangeText={onChangeText}
          onFocus={() => setFocused(true)}
          placeholder={placeholder}
          placeholderTextColor={colors.text3}
          selectionColor={colors.accent}
          style={[styles.input, multiline && styles.inputMultiline]}
          value={value}
        />
      </Animated.View>
      {hint ? <Text style={type.caption}>{hint}</Text> : null}
    </View>
  );
}

// The "To" line of a new message, set as the centrepiece of its screen rather
// than as a header row: one shell holding the label, the handle prefix and
// the name, shaped like the composer beneath it. Submitting hands focus on
// to whatever comes next, so the message follows without a tap.
export function RecipientField({
  value,
  onChangeText,
  onSubmitEditing,
  autoFocus = true,
}: {
  value: string;
  onChangeText: (value: string) => void;
  onSubmitEditing?: () => void;
  // The recipient is the first thing to fill in, unless it arrived filled.
  autoFocus?: boolean;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const [focused, setFocused] = useState(false);
  const focus = useFocusProgress(focused);
  return (
    <View style={styles.recipient}>
      <FocusRing progress={focus} radius={isDesktop ? radius.md : radius.pill} />
      <Text style={styles.recipientLabel}>To</Text>
      <Text style={styles.recipientPrefix}>@</Text>
      <TextInput
        accessibilityLabel="Username"
        testID="Username"
        value={value}
        onBlur={() => setFocused(false)}
        onChangeText={onChangeText}
        onFocus={() => setFocused(true)}
        onSubmitEditing={onSubmitEditing}
        submitBehavior="submit"
        returnKeyType="next"
        placeholder="exact username"
        placeholderTextColor={colors.text3}
        selectionColor={colors.accent}
        autoCapitalize="none"
        autoCorrect={false}
        autoFocus={autoFocus}
        style={styles.recipientInput}
      />
    </View>
  );
}

export function Card({
  children,
  tone = "surface",
  padded = true,
  style,
}: {
  children: ReactNode;
  tone?: "surface" | "raised" | "accent";
  padded?: boolean;
  style?: StyleProp<ViewStyle>;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <View
      style={[
        styles.card,
        padded && styles.cardPadded,
        tone === "raised" && { backgroundColor: colors.raised },
        tone === "accent" && styles.cardAccent,
        style,
      ]}
    >
      {children}
    </View>
  );
}

export function Section({
  title,
  children,
  trailing,
  footer,
}: {
  title: string;
  children: ReactNode;
  trailing?: ReactNode;
  // Explanatory copy sits under the group, the way system settings do it,
  // so the group itself stays scannable.
  footer?: string;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.section}>
      <View style={styles.sectionHeader}>
        <Text style={type.sectionTitle}>{title}</Text>
        {trailing}
      </View>
      {children}
      {footer ? <Text style={styles.sectionFooter}>{footer}</Text> : null}
    </View>
  );
}

// Rows in a card, set a step in from its edge. No lines between them: each
// row's tile and text give the group its rhythm, and a pressed or hovered
// row lights up as a rounded shape of its own inside the card.
export function RowGroup({ children }: { children: ReactNode }) {
  const styles = useStyles();
  return (
    <Card padded={false} style={styles.rowGroup}>
      {children}
    </Card>
  );
}

export type TileTone =
  | "accent"
  | "success"
  | "warning"
  | "danger"
  | "muted"
  | "violet"
  | "pink"
  | "teal";

// Every tile carries a white glyph, so each tone is a palette role deep
// enough to hold one in either scheme.
function tileColor(tone: TileTone, { colors }: Theme): string {
  switch (tone) {
    case "accent":
      return colors.accent;
    case "success":
      return colors.success;
    case "warning":
      return colors.warning;
    case "danger":
      return colors.danger;
    case "muted":
      return colors.tileMuted;
    case "violet":
      return colors.violet;
    case "pink":
      return colors.pink;
    case "teal":
      return colors.teal;
  }
}

export function Row({
  icon,
  leading,
  title,
  subtitle,
  onPress,
  trailing,
  tone = "accent",
  emphasis,
  selected,
  accessibilityLabel,
}: {
  icon?: IconName;
  leading?: ReactNode;
  title: string;
  subtitle?: string;
  onPress?: () => void;
  trailing?: ReactNode;
  tone?: TileTone;
  // Colours the title for rows that are actions rather than destinations.
  emphasis?: "accent" | "danger";
  // Turns the row into one choice of a set, marked with a check.
  selected?: boolean;
  accessibilityLabel?: string;
}) {
  const theme = useTheme();
  const { colors, type } = theme;
  const styles = useStyles();
  const titleColor =
    emphasis === "accent" ? colors.accent : emphasis === "danger" ? colors.danger : colors.text;
  const content = (
    <>
      {leading ?? (icon ? (
        <View style={[styles.rowIcon, { backgroundColor: tileColor(tone, theme) }]}>
          <Icon name={icon} size={isDesktop ? sizes.icon.sm : sizes.icon.lg} color={colors.white} strokeWidth={2.2} />
        </View>
      ) : null)}
      <View style={layout.flex}>
        <Text numberOfLines={1} style={[type.bodyStrong, { color: titleColor }]}>
          {title}
        </Text>
        {subtitle ? (
          <Text numberOfLines={2} style={type.footnote}>
            {subtitle}
          </Text>
        ) : null}
      </View>
      {trailing !== undefined ? (
        trailing
      ) : selected !== undefined ? (
        <View style={styles.rowCheck}>
          {selected ? <Icon name="check" size={sizes.icon.lg} color={colors.accent} strokeWidth={2.6} /> : null}
        </View>
      ) : onPress ? (
        <Icon name="chevron" size={sizes.icon.md} color={colors.text3} strokeWidth={2.4} />
      ) : null}
    </>
  );
  const rowStyle = [styles.row, !icon && styles.rowPlain];
  if (!onPress) return <View style={rowStyle}>{content}</View>;
  return (
    <Tap
      label={accessibilityLabel ?? title}
      role={selected !== undefined ? "radio" : "button"}
      state={selected !== undefined ? { checked: selected } : undefined}
      onPress={onPress}
      style={rowStyle}
      feedback="highlight"
    >
      {content}
    </Tap>
  );
}

// One choice from a few, as a compact track with the chosen segment lifted on
// a thumb: what a row carries at its trailing edge when its two to four
// options are all worth seeing at once, where a column of rows would spend a
// screen on them. A segment shows a glyph, or a word short enough to share a
// phone row with the title; assistive technology reads the full label, and
// the row's subtitle can spell the choice out.
export function Segmented<T extends string | number>({
  label,
  options,
  value,
  onSelect,
}: {
  // Names the set for assistive technology; each segment is "label: option".
  label: string;
  options: readonly { value: T; label: string; short?: string; icon?: IconName }[];
  value: T;
  onSelect: (value: T) => void;
}) {
  const styles = useStyles();
  return (
    <View accessibilityRole="radiogroup" accessibilityLabel={label} style={[styles.segmented, styles.segmentedSurface, styles.choiceTrack]}>
      {options.map((option) => (
        <ChoiceSegment
          key={option.value}
          label={`${label}: ${option.label}`}
          text={option.short ?? option.label}
          icon={option.icon}
          selected={option.value === value}
          onPress={() => onSelect(option.value)}
        />
      ))}
    </View>
  );
}

// Each segment carries its own thumb and fades it in when chosen, so segments
// can take the width of their words without anything being measured.
function ChoiceSegment({
  label,
  text,
  icon,
  selected,
  onPress,
}: {
  label: string;
  text: string;
  icon?: IconName;
  selected: boolean;
  onPress: () => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const lift = useTimed(selected ? 1 : 0, motion.quick);
  return (
    <Tap
      label={label}
      role="radio"
      state={{ checked: selected }}
      onPress={onPress}
      // The track is lower than a finger needs; the slop makes up the rest.
      hitSlop={{ top: space[1], bottom: space[1] }}
      feedback="highlight"
      style={[styles.choiceSegment, !icon && styles.choiceSegmentWord]}
    >
      <Animated.View pointerEvents="none" style={[styles.choiceThumb, { opacity: lift }]} />
      {icon ? (
        // A bare glyph is not a positioned box on the web, so the thumb would
        // paint over it; inside a view it keeps its place in the order.
        <View>
          <Icon
            name={icon}
            size={isDesktop ? sizes.icon.sm : sizes.icon.lg}
            color={selected ? colors.text : colors.text2}
            strokeWidth={selected ? 2.2 : 1.9}
          />
        </View>
      ) : (
        <Text numberOfLines={1} style={[styles.choiceWord, selected && styles.choiceWordSelected]}>
          {text}
        </Text>
      )}
    </Tap>
  );
}

// A desktop switch in the platform's proportions, which no control step
// fits: a capsule thumb, wider than it is tall, in a track under two thumbs long.
const toggleTrack = { width: 40, height: 22 };
const toggleThumb = { width: 24, height: toggleTrack.height - 2 * space[0.5] };
const toggleTravel = toggleTrack.width - toggleThumb.width - 2 * space[0.5];

// On or off, at a row's trailing edge. A phone has the platform's own switch,
// which iOS forms from Liquid Glass. The web view has none and React Native
// Web's is Material, so the desktop draws the platform's shape on the
// segmented choice's track: the accent floods it when on, and a white thumb
// slides inside.
export function Toggle({
  label,
  value,
  disabled = false,
  onValueChange,
}: {
  label: string;
  value: boolean;
  disabled?: boolean;
  onValueChange: (value: boolean) => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const on = useTimed(value ? 1 : 0, motion.quick);
  if (!isDesktop) {
    return (
      <Switch
        accessibilityLabel={label}
        value={value}
        disabled={disabled}
        onValueChange={onValueChange}
        trackColor={{ true: colors.accent }}
      />
    );
  }
  return (
    <Tap
      label={label}
      role="switch"
      state={{ checked: value }}
      disabled={disabled}
      onPress={() => onValueChange(!value)}
      feedback="none"
      style={[styles.toggle, styles.segmentedSurface]}
    >
      <Animated.View pointerEvents="none" style={[styles.toggleOn, { opacity: on }]} />
      <Animated.View
        pointerEvents="none"
        style={[
          styles.toggleThumb,
          { transform: [{ translateX: on.interpolate({ inputRange: [0, 1], outputRange: [0, toggleTravel] }) }] },
        ]}
      />
    </Tap>
  );
}

// A panel over the screen for something to look at without leaving the
// thread: on a phone a sheet rising from the bottom edge, on desktop a card
// centred in the window. A close disc sits in its top corner; the scrim
// around it dismisses it too, as does the system's back gesture or key.
export function Dialog({
  visible,
  label,
  onClose,
  children,
  style,
}: {
  visible: boolean;
  label: string;
  onClose: () => void;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <Modal
      visible={visible}
      transparent
      animationType={isDesktop ? "fade" : "slide"}
      onRequestClose={onClose}
    >
      <View style={styles.dialogScrim}>
        {/* The disc is the close control assistive technology reaches; the
            scrim answers a tap outside without announcing itself. */}
        <Pressable accessible={false} importantForAccessibility="no" onPress={onClose} style={StyleSheet.absoluteFill} />
        <View role="dialog" accessibilityViewIsModal accessibilityLabel={label} style={[styles.dialog, style]}>
          {children}
          <Tap
            label="Close"
            onPress={onClose}
            hitSlop={space[2]}
            scaleTo={0.94}
            pressedOpacity={0.7}
            containerStyle={styles.dialogClose}
            style={styles.dialogCloseDisc}
          >
            <Icon name="close" size={sizes.icon.sm} color={colors.text2} strokeWidth={2.4} />
          </Tap>
        </View>
      </View>
    </Modal>
  );
}

// A 64-character safety number as four lines of four hex groups, the way
// other messengers lay a security code out to be read aloud and checked
// against another screen. The lines sit in a well as wide as the card: a wide
// pane pairs them into two rows of eight, a narrow one stacks all four. Every
// other group is set back a shade so the eye keeps its place across a line,
// and the well takes the tone of the number's state. Every group is four
// monospaced characters, so the columns line up without being told a width.
export function SafetyNumber({
  value,
  tone = "muted",
}: {
  value: string;
  tone?: "success" | "warning" | "muted";
}) {
  const styles = useStyles();
  const groups = groupDigits(value, 4);
  const lines = Array.from({ length: Math.ceil(groups.length / 4) }, (_, line) =>
    groups.slice(line * 4, line * 4 + 4));
  return (
    <View
      accessible
      accessibilityLabel={`Safety number ${groups.join(" ")}`}
      style={[
        styles.safetyWell,
        tone === "success" && styles.safetyWellVerified,
        tone === "warning" && styles.safetyWellChanged,
      ]}
    >
      {lines.map((line, index) => (
        <View key={index} style={styles.safetyLine}>
          {line.map((group, column) => (
            <Text key={column} selectable style={[styles.safetyDigits, column % 2 === 1 && styles.safetyDigitsSetBack]}>
              {group}
            </Text>
          ))}
        </View>
      ))}
    </View>
  );
}

export function Notice({
  text,
  tone = "info",
  onDismiss,
}: {
  text: string;
  tone?: "info" | "warning" | "error";
  onDismiss?: () => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const color =
    tone === "error" ? colors.danger : tone === "warning" ? colors.warning : colors.accent;
  return (
    <View
      accessibilityLiveRegion={tone === "error" ? "assertive" : "polite"}
      style={[
        styles.notice,
        tone === "error" && { backgroundColor: colors.dangerSoft },
        tone === "warning" && { backgroundColor: colors.warningSoft },
      ]}
    >
      <Icon name={tone === "info" ? "shield" : "warning"} color={color} size={sizes.icon.lg} />
      <Text style={[styles.noticeText, tone !== "info" && { color }]}>{text}</Text>
      {onDismiss ? (
        <Tap label="Dismiss" onPress={onDismiss} hitSlop={space[3]} pressedOpacity={0.55}>
          <Icon name="close" size={sizes.icon.md} color={color} />
        </Tap>
      ) : null}
    </View>
  );
}

export function SidebarEmptyState({ title }: { title: string }) {
  const styles = useStyles();
  return (
    <View style={styles.empty}>
      <Text style={styles.sidebarEmptyText}>{title}</Text>
    </View>
  );
}

// A bare glyph, a line of title and a sentence or two, centred in whatever
// space is empty. The glyph is tertiary and small enough to read as
// punctuation over the title rather than as a badge of its own, so the
// sentence leads and the illustration does not. Some screens are empty
// because they are waiting for one thing from the person; that control goes
// in as children, between the copy and the actions, and arrives in the same
// cadence.
export function EmptyState({
  icon,
  title,
  body,
  children,
  action,
}: {
  icon: IconName;
  title: string;
  body: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.empty}>
      <Reveal style={styles.emptyIconWrap}>
        <Icon name={icon} size={sizes.icon["2xl"]} color={colors.text3} strokeWidth={1.75} />
      </Reveal>
      <Reveal delay={70}>
        <Text style={styles.emptyTitle}>{title}</Text>
      </Reveal>
      <Reveal delay={130}>
        <Text style={styles.emptyBody}>{body}</Text>
      </Reveal>
      {children ? (
        <Reveal delay={190} style={styles.emptyControl}>
          {children}
        </Reveal>
      ) : null}
      {action ? (
        <Reveal delay={children ? 250 : 200} style={styles.emptyAction}>
          {action}
        </Reveal>
      ) : null}
    </View>
  );
}

// The field's inner padding, and how many lines it grows to before it
// scrolls: about six on a phone, eight on the desktop.
const composerPadding = isDesktop ? space[2] : space[3];
const composerLines = isDesktop ? 8 : 6;
export function composerCeiling(lineHeight: number): number {
  return lineHeight * composerLines + 2 * composerPadding;
}
// The shell's height at one line, and the corner that makes it a capsule
// there. The focus ring sits a pixel outside the shell, so it is concentric
// at one pixel more.
const composerHeight = isDesktop ? control.lg : control["2xl"];
const composerRadius = composerHeight / 2;
// How far the quoted message sits in from the shell's edge when replying.
const composerReplyInset = isDesktop ? space[1] : space[1.5];
// The gap a thread keeps between its newest message and the composer. The
// bar's fade ends there too: it dims rows as they pass beneath the bar, and
// never the message resting above it.
export const composerClearance = space[2];

// A browser textarea is two rows tall unless told otherwise; the field
// starts at one and grows from there.
const webTextareaRows = { rows: 1 } as object;

// A file waiting in the composer to go with the next message.
export type ComposerAttachment = {
  id: string;
  filename: string;
  size: string;
  // A picture shows itself; anything else shows as a file.
  previewUri?: string;
};

// The staged file, above the field: a thumbnail or a file tile, its name and
// size, and a way to take it back out.
function ComposerAttachmentChip({
  attachment,
  onRemove,
  disabled,
}: {
  attachment: ComposerAttachment;
  onRemove: () => void;
  disabled: boolean;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <Reveal style={styles.composerAttachment}>
      {attachment.previewUri ? (
        <Image
          source={{ uri: attachment.previewUri }}
          accessibilityIgnoresInvertColors
          style={styles.composerAttachmentThumb}
        />
      ) : (
        <View style={styles.composerAttachmentTile}>
          <Icon name="file" size={sizes.icon.lg} color={colors.accent} strokeWidth={1.9} />
        </View>
      )}
      <View style={styles.composerAttachmentText}>
        <Text numberOfLines={1} style={styles.composerAttachmentName}>
          {attachment.filename}
        </Text>
        <Text numberOfLines={1} style={styles.composerAttachmentMeta}>
          {attachment.size}
        </Text>
      </View>
      <IconButton
        name="close"
        label={`Remove ${attachment.filename}`}
        variant="plain"
        glass={false}
        size={isDesktop ? control.xs : sizes.tile.md}
        disabled={disabled}
        onPress={onRemove}
      />
    </Reveal>
  );
}

export function Composer({
  value,
  onChangeText,
  onSend,
  group = false,
  disabled = false,
  sendDisabled = false,
  placeholder = "Message",
  label,
  sendLabel = "Send",
  onHeightChange,
  inputRef,
  autoFocus = false,
  attachments = [],
  onAttach,
  onRemoveAttachment,
  dropping = false,
  mentionMembers = [],
  reply,
  onCancelReply,
}: {
  value: string;
  onChangeText: (value: string) => void;
  onSend: () => void;
  group?: boolean;
  disabled?: boolean;
  sendDisabled?: boolean;
  placeholder?: string;
  label?: string;
  sendLabel?: string;
  // The bar floats over the thread; the list uses this to keep the newest
  // message clear of it as the field grows.
  onHeightChange?: (height: number) => void;
  // For a screen that wants to move focus here from another field.
  inputRef?: RefObject<TextInput | null>;
  // For a screen that opens with nothing left to fill in but the message.
  autoFocus?: boolean;
  // Files staged to go with the message; they can be sent without text.
  attachments?: ComposerAttachment[];
  // Offers the file picker; without it the bar has no attach button.
  onAttach?: () => void;
  onRemoveAttachment?: (id: string) => void;
  // A file is being dragged over the window: the shell invites the drop.
  dropping?: boolean;
  mentionMembers?: { username: string; name: string }[];
  // The message being answered, quoted above the field as its bubble will
  // quote it, until it is sent or dismissed. `id` tells one reply from the next.
  reply?: { id: string; name: string; accountId?: string; text: string };
  onCancelReply?: () => void;
}) {
  const { colors, scheme, type } = useTheme();
  const styles = useStyles();
  const name = label ?? (group ? "Group message" : "Message");
  const [focused, setFocused] = useState(false);
  const [height, setHeight] = useState(0);
  const [width, setWidth] = useState(0);
  const focus = useFocusProgress((focused && !disabled) || dropping);
  const canSend = !disabled && !sendDisabled && (value.trim().length > 0 || attachments.length > 0);
  const ready = useSprung(canSend ? 1 : 0);
  const glass = useLiquidGlass();
  // With glass the desktop bar is open like the phone's, the shell floating
  // over the thread; without it the bar is a solid strip below the thread.
  const floating = !isDesktop || glass;
  const field = useRef<TextInput | null>(null);
  const [cursor, setCursor] = useState(value.length);
  const [selection, setSelection] = useState<{ start: number; end: number }>();
  const [suggestionIndex, setSuggestionIndex] = useState(0);
  const [dismissedMention, setDismissedMention] = useState<string | null>(null);
  const mention = group && !disabled && dismissedMention !== value ? mentionAt(value, cursor) : null;
  const suggestions = mention ? mentionMembers.filter((member, index, all) =>
    member.username.startsWith(mention.query) && all.findIndex((other) => other.username === member.username) === index).slice(0, 6) : [];
  const chooseMention = (username: string) => {
    if (!mention) return;
    const completed = completeMention(value, mention, username);
    onChangeText(completed.text);
    setCursor(completed.cursor);
    setSelection({ start: completed.cursor, end: completed.cursor });
    setSuggestionIndex(0);
    field.current?.focus();
  };
  const attachField = (node: TextInput | null) => {
    field.current = node;
    if (inputRef) inputRef.current = node;
  };
  // The quoted person's colour, as their name is set in a bubble.
  const replyInk = reply?.accountId ? avatarTone(reply.accountId, scheme).ink : colors.accent;
  // Choosing a message to answer puts the cursor where the answer goes.
  const replyId = reply?.id;
  useEffect(() => {
    if (replyId) field.current?.focus();
  }, [replyId]);
  // A native field measures its own text and grows with it. A textarea keeps
  // whatever height it has, so on the web it is sized to its content each
  // time the text or the bar's width changes: one line to begin with, a line
  // more as the words reach the send button, up to the shell's ceiling,
  // where it scrolls instead.
  useEffect(() => {
    if (Platform.OS !== "web") return;
    const node = field.current as unknown as HTMLTextAreaElement | null;
    if (!node) return;
    node.style.height = "auto";
    node.style.height = `${Math.min(node.scrollHeight, composerCeiling(type.input.lineHeight))}px`;
  }, [value, width, type.input.lineHeight]);
  return (
    <View
      style={[styles.composerBar, isDesktop && floating && styles.composerBarFloating]}
      pointerEvents={toolbarRow}
      onLayout={(event) => {
        const next = event.nativeEvent.layout.height;
        setHeight(next);
        setWidth(event.nativeEvent.layout.width);
        onHeightChange?.(next);
      }}
    >
      {floating ? <ScrollEdge side="bottom" height={height + composerClearance} /> : null}
      <View style={styles.composerShellWrap}>
        <Glass style={styles.composerShell} fallback={styles.composerShellSurface}>
          {suggestions.length ? (
            <ScrollView keyboardShouldPersistTaps="always" style={{ maxHeight: 200 }} accessibilityLabel="Mention a group member">
              {suggestions.map((member, index) => (
                <Row key={member.username} title={`@${member.username}`} subtitle={member.name}
                  onPress={() => chooseMention(member.username)}
                  trailing={index === suggestionIndex ? <Icon name="arrowUp" size={16} color={colors.accent} /> : undefined} />
              ))}
            </ScrollView>
          ) : null}
          {reply && onCancelReply ? (
            <Reveal key={reply.id} distance={space[1.5]} style={styles.composerReply}>
              <View style={[styles.composerReplyBar, { backgroundColor: replyInk }]} />
              <View accessible accessibilityLabel={`Replying to ${reply.name}: ${reply.text}`} style={styles.composerReplyText}>
                <Text numberOfLines={1} style={[styles.bubbleQuoteName, { color: replyInk }]}>{reply.name}</Text>
                <Text numberOfLines={1} style={[styles.bubbleQuoteBody, { color: colors.text2 }]}>{reply.text}</Text>
              </View>
              <Tap
                label="Cancel reply"
                onPress={onCancelReply}
                hitSlop={space[2.5]}
                scaleTo={0.9}
                style={styles.composerReplyClose}
              >
                <Icon name="close" size={sizes.icon.xs} color={colors.text2} strokeWidth={2.4} />
              </Tap>
            </Reveal>
          ) : null}
          {attachments.length && onRemoveAttachment ? (
            <ScrollView horizontal showsHorizontalScrollIndicator accessibilityLabel="Attached files">
              {attachments.map((attachment) => (
                <View key={attachment.id} style={{ width: 240 }}>
                  <ComposerAttachmentChip attachment={attachment} onRemove={() => onRemoveAttachment(attachment.id)} disabled={disabled} />
                </View>
              ))}
            </ScrollView>
          ) : null}
          <View style={styles.composerRow}>
            {onAttach ? (
              <View style={styles.composerAttach}>
                <IconButton
                  name="paperclip"
                  label={`Attach files (${attachments.length} of ${MAXIMUM_ATTACHMENTS})`}
                  variant="plain"
                  glass={false}
                  size={isDesktop ? control.xs : sizes.tile.md}
                  disabled={disabled || attachments.length >= MAXIMUM_ATTACHMENTS}
                  onPress={onAttach}
                />
              </View>
            ) : null}
            <TextInput
              ref={attachField}
              {...(Platform.OS === "web" ? webTextareaRows : {})}
              accessibilityLabel={name}
              testID={name}
              autoFocus={autoFocus}
              editable={!disabled}
              multiline
              onBlur={() => setFocused(false)}
              onChangeText={(text) => {
                setCursor(Math.max(0, cursor + text.length - value.length));
                setSelection(undefined);
                setSuggestionIndex(0);
                setDismissedMention(null);
                onChangeText(text);
              }}
              selection={selection}
              onSelectionChange={(event) => setCursor(event.nativeEvent.selection.end)}
              onFocus={() => setFocused(true)}
              onKeyPress={Platform.OS === "web" ? (event) => {
                const key = event.nativeEvent as typeof event.nativeEvent & { shiftKey?: boolean; isComposing?: boolean };
                if (suggestions.length && !key.isComposing) {
                  if (key.key === "Escape") { event.preventDefault(); setDismissedMention(value); return; }
                  if (key.key === "ArrowDown" || key.key === "ArrowUp") {
                    event.preventDefault();
                    setSuggestionIndex((index) => (index + (key.key === "ArrowDown" ? 1 : suggestions.length - 1)) % suggestions.length);
                    return;
                  }
                  if (key.key === "Enter" && !key.shiftKey) {
                    event.preventDefault(); chooseMention(suggestions[suggestionIndex % suggestions.length]!.username); return;
                  }
                }
                if (key.key === "Escape" && reply && onCancelReply) { event.preventDefault(); onCancelReply(); return; }
                if (key.key === "Enter" && !key.shiftKey && !key.isComposing) {
                  event.preventDefault();
                  if (canSend) onSend();
                }
              } : undefined}
              placeholder={dropping ? "Drop to attach" : placeholder}
              placeholderTextColor={dropping ? colors.accent : colors.text3}
              selectionColor={colors.accent}
              style={[
                styles.composerInput,
                { maxHeight: composerCeiling(type.input.lineHeight) },
                !onAttach && styles.composerInputLead,
                disabled && styles.composerInputDisabled,
              ]}
              value={value}
            />
            {/* Solid inside glass: a tinted send button would be glass on glass. */}
            <Animated.View
              style={[
                styles.composerSend,
                {
                  opacity: ready.interpolate({ inputRange: [0, 1], outputRange: [0.38, 1] }),
                  transform: [
                    { scale: ready.interpolate({ inputRange: [0, 1], outputRange: [0.86, 1] }) },
                  ],
                },
              ]}
            >
              <IconButton
                name="arrowUp"
                label={sendLabel}
                variant="filled"
                size={isDesktop ? control.xs : sizes.tile.md}
                glass={false}
                disabled={!canSend}
                dimDisabled={false}
                onPress={onSend}
              />
            </Animated.View>
          </View>
        </Glass>
        <FocusRing progress={focus} radius={composerRadius + 1} />
      </View>
    </View>
  );
}

// A bubble in a group thread sits in a row with a gutter for the sender's
// avatar, which appears once per run of their messages, beside the last. The
// run's first bubble names them in their identity colour; the bubble itself
// is the same plain pane as in a conversation, so a busy thread reads as
// speech, not as a rainbow of cards. Your own messages need no name: they are
// the accent, on the right, as everywhere else.
// What a bubble shows for the file that came with its message. The thread
// decides what the file is doing (downloading, ready to save, failed) and
// what a tap does about it; the bubble only draws that.
export type BubbleAttachment = {
  id: string;
  filename: string;
  image: boolean;
  // The line under the name: size and the action a tap takes, or progress.
  status: string;
  busy: boolean;
  // A downloaded picture shows itself instead of a file tile.
  previewUri?: string;
  onPress: () => void;
  // Called once when the bubble first shows, for pictures worth fetching on sight.
  onAppear?: () => void;
};

// A downloaded picture, as wide as the bubble allows and shaped like itself
// once its size is known; until then it holds a photo's proportions.
function AttachmentPicture({ attachment, onLongPress }: { attachment: BubbleAttachment; onLongPress?: () => void }) {
  const styles = useStyles();
  const [aspectRatio, setAspectRatio] = useState(4 / 3);
  const [viewing, setViewing] = useState(false);
  return (
    <>
      <Tap label={`View ${attachment.filename}`} onPress={() => setViewing(true)} onLongPress={onLongPress} scaleTo={0.985} style={styles.bubblePictureWrap}>
        <Image
          source={{ uri: attachment.previewUri }}
          accessibilityIgnoresInvertColors
          resizeMode="cover"
          onLoad={(event) => {
            const { width, height } = event.nativeEvent.source ?? {};
            if (width && height) setAspectRatio(Math.min(Math.max(width / height, 0.6), 1.9));
          }}
          style={[styles.bubblePicture, { aspectRatio }]}
        />
      </Tap>
      <Dialog visible={viewing} label={attachment.filename} onClose={() => setViewing(false)} style={styles.attachmentViewer}>
        <Text numberOfLines={1} style={styles.attachmentViewerTitle}>{attachment.filename}</Text>
        <Image source={{ uri: attachment.previewUri }} accessibilityLabel={attachment.filename}
          accessibilityIgnoresInvertColors resizeMode="contain" style={styles.attachmentViewerImage} />
        <Text style={styles.bubbleFileMeta}>{attachment.status}</Text>
        <View style={styles.attachmentViewerDownload}>
          <IconButton name="download" label="Download" variant="tonal" glass={false}
            size={isDesktop ? control.xs : control.sm} disabled={attachment.busy} onPress={attachment.onPress} />
        </View>
      </Dialog>
    </>
  );
}

function AttachmentCard({ attachment, sent, onLongPress }: { attachment: BubbleAttachment; sent: boolean; onLongPress?: () => void }) {
  const { colors } = useTheme();
  const styles = useStyles();
  const ink = sent ? colors.onAccent : colors.accent;
  return (
    <Tap
      label={`${attachment.filename}. ${attachment.status}`}
      onPress={attachment.onPress}
      onLongPress={onLongPress}
      disabled={attachment.busy}
      dimDisabled={false}
      scaleTo={0.985}
      style={[styles.bubbleFile, sent ? styles.bubbleFileSent : styles.bubbleFileReceived]}
    >
      <View style={[styles.bubbleFileTile, sent ? styles.bubbleFileTileSent : styles.bubbleFileTileReceived]}>
        {attachment.busy ? (
          <ActivityIndicator size="small" color={ink} />
        ) : (
          <Icon name={attachment.image ? "image" : "file"} size={sizes.icon.lg} color={ink} strokeWidth={1.9} />
        )}
      </View>
      <View style={styles.bubbleFileText}>
        <Text numberOfLines={1} style={[styles.bubbleFileName, sent && styles.bubbleBodySent]}>
          {attachment.filename}
        </Text>
        <Text numberOfLines={1} style={[styles.bubbleFileMeta, { color: sent ? colors.onAccentMuted : colors.text3 }]}>
          {attachment.status}
        </Text>
      </View>
    </Tap>
  );
}

function highlightMentions(body: string, usernames: string[]): ReactNode[] {
  const output: ReactNode[] = [];
  let offset = 0;
  for (const span of mentionSpans(body, usernames)) {
    output.push(body.slice(offset, span.start));
    output.push(<Text key={span.start} style={{ fontWeight: "700", textDecorationLine: "underline" }}>{body.slice(span.start, span.end)}</Text>);
    offset = span.end;
  }
  output.push(body.slice(offset));
  return output;
}

// What a message's menu offers under its emojis.
type MessageAction = { icon: IconName; label: string; onPress: () => void };

// The menu a message opens: a bar of emojis over a short list of actions, in
// a layer above the thread, beside the bubble it belongs to. A long press
// opens it on a phone; on the desktop the bubble's hover controls or a right
// click do. It grows out of the bubble's corner, and anything outside closes it.
function MessageMenu({
  anchor,
  sent,
  mine,
  canReact,
  onReact,
  actions,
  onClose,
}: {
  anchor: Frame;
  sent: boolean;
  // The emoji this account has already given the message, if any.
  mine?: string;
  canReact: boolean;
  onReact?: (emoji: string) => void;
  actions: MessageAction[];
  onClose: () => void;
}) {
  const { colors, scheme } = useTheme();
  const styles = useStyles();
  const viewport = useWindowDimensions();
  const insets = initialWindowMetrics?.insets;
  // Eight emojis across, at a finger's width where the screen allows it.
  const cell = isDesktop
    ? control.md
    : Math.min(sizes.hit, Math.floor((viewport.width - 2 * (menuMargin + menuPadding)) / reactionEmojis.length));
  const width = reactionEmojis.length * cell + 2 * menuPadding;
  const height = (onReact ? cell + 2 * menuPadding : 0)
    + (onReact && actions.length ? space[2] : 0)
    + (actions.length ? actions.length * menuRowHeight + 2 * space[1] : 0);
  const place = placeMenu(
    {
      left: menuMargin,
      top: (insets?.top ?? 0) + menuMargin,
      right: viewport.width - menuMargin,
      bottom: viewport.height - (insets?.bottom ?? 0) - menuMargin,
    },
    anchor,
    { width, height },
    sent,
  );
  const above = place.top < anchor.y;
  const [progress] = useState(() => new Animated.Value(0));
  useEffect(() => {
    const animation = Animated.spring(progress, { toValue: 1, useNativeDriver: false, ...motion.springSnap });
    animation.start();
    return () => animation.stop();
  }, [progress]);
  return (
    <Modal visible transparent statusBarTranslucent animationType={isDesktop ? "none" : "fade"} onRequestClose={onClose}>
      {/* A phone dims the thread behind the menu, lightly enough that the
          message it belongs to still reads; a desktop popover dims nothing. */}
      <Pressable
        accessible={false}
        importantForAccessibility="no"
        onPress={onClose}
        style={[StyleSheet.absoluteFill, !isDesktop && { backgroundColor: withAlpha(colors.black, scheme === "dark" ? 0.4 : 0.2) }]}
      />
      <Animated.View
        role="dialog"
        accessibilityViewIsModal
        accessibilityLabel="Message actions"
        style={[
          styles.messageMenu,
          place,
          {
            width,
            opacity: progress,
            transformOrigin: `${sent ? "right" : "left"} ${above ? "bottom" : "top"}`,
            transform: [{ scale: progress.interpolate({ inputRange: [0, 1], outputRange: [0.9, 1] }) }],
          },
        ]}
      >
        {onReact ? (
          <View style={[styles.messageMenuPane, styles.messageMenuBar]}>
            {reactionEmojis.map(({ emoji, label }) => (
              <Pressable
                key={emoji}
                accessibilityRole="button"
                accessibilityLabel={label}
                accessibilityHint={mine === emoji ? "Removes your reaction" : undefined}
                accessibilityState={{ selected: mine === emoji, disabled: !canReact }}
                {...(Platform.OS === "web" ? { "aria-pressed": mine === emoji } : {})}
                disabled={!canReact}
                onPress={() => { onClose(); onReact(mine === emoji ? "" : emoji); }}
                style={({ pressed, hovered }: { pressed: boolean; hovered?: boolean }) => [
                  styles.messageMenuEmoji,
                  { width: cell, height: cell },
                  mine === emoji ? styles.reactionChoiceSelected : hovered && { backgroundColor: colors.highlight },
                  !canReact ? styles.disabled : pressed && { opacity: 0.6 },
                ]}
              >
                <Text style={styles.reactionChoiceEmoji}>{emoji}</Text>
              </Pressable>
            ))}
          </View>
        ) : null}
        {actions.length ? (
          <View style={[styles.messageMenuPane, styles.messageMenuActions, { alignSelf: sent ? "flex-end" : "flex-start" }]}>
            {actions.map(({ icon, label, onPress }) => (
              <Tap
                key={label}
                label={label}
                onPress={() => { onClose(); onPress(); }}
                feedback="highlight"
                style={styles.messageMenuRow}
              >
                <Text style={styles.messageMenuLabel}>{label}</Text>
                <Icon name={icon} size={isDesktop ? sizes.icon.md : sizes.icon.lg} color={colors.text2} strokeWidth={1.9} />
              </Tap>
            ))}
          </View>
        ) : null}
      </Animated.View>
    </Modal>
  );
}

// One of the desktop controls that appear beside a hovered bubble.
function AsideButton({
  icon,
  label,
  hint,
  disabled = false,
  onPress,
  onFocusChange,
}: {
  icon: IconName;
  label: string;
  hint: string;
  disabled?: boolean;
  onPress: () => void;
  // Focus keeps the controls shown for someone tabbing through the thread.
  onFocusChange: (focused: boolean) => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityHint={hint}
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      onFocus={() => onFocusChange(true)}
      onBlur={() => onFocusChange(false)}
      style={({ pressed, hovered }: { pressed: boolean; hovered?: boolean }) => [
        styles.reactAsideDisc,
        hovered && { backgroundColor: colors.highlight },
        disabled ? styles.disabled : pressed && { opacity: 0.6 },
      ]}
    >
      <Icon name={icon} size={sizes.icon.md} color={colors.text2} strokeWidth={2} />
    </Pressable>
  );
}

// On a phone, dragging a message to the right answers it, as in other chat
// apps: the row follows the finger while a reply glyph grows into the space it
// leaves, and lifting past the trigger point starts the reply. Only a clearly
// rightward drag is claimed, so the thread keeps its scroll; if the list takes
// the touch back, the row just settles.
function ReplySwipe({ onReply, children }: { onReply: () => void; children: ReactNode }) {
  const { colors } = useTheme();
  const styles = useStyles();
  const [offset] = useState(() => new Animated.Value(0));
  // The responder outlives renders; it answers with whatever reply is current.
  const latest = useRef(onReply);
  useEffect(() => {
    latest.current = onReply;
  }, [onReply]);
  const [responder] = useState(() => {
    const settle = () =>
      Animated.spring(offset, { toValue: 0, useNativeDriver: false, ...motion.spring }).start();
    return PanResponder.create({
      onMoveShouldSetPanResponder: (_, gesture) => startsReplySwipe(gesture.dx, gesture.dy),
      // Once the drag is a reply it stays one: a little vertical drift must
      // not hand it to the list.
      onPanResponderTerminationRequest: () => false,
      onPanResponderMove: (_, gesture) => offset.setValue(replySwipeOffset(gesture.dx)),
      onPanResponderRelease: (_, gesture) => {
        if (gesture.dx >= REPLY_SWIPE_TRIGGER) latest.current();
        settle();
      },
      onPanResponderTerminate: settle,
    });
  });
  const progress = offset.interpolate({ inputRange: [0, REPLY_SWIPE_TRIGGER], outputRange: [0, 1], extrapolate: "clamp" });
  return (
    <View {...responder.panHandlers}>
      {/* Centred in the gap the row leaves: the desktop's reply control in
          small. Its glyph turns accent once lifting would reply. */}
      <Animated.View
        pointerEvents="none"
        style={[
          styles.replySwipeGlyph,
          {
            opacity: progress,
            transform: [
              { translateX: offset.interpolate({ inputRange: [0, 1], outputRange: [-replySwipeGlyph / 2, (1 - replySwipeGlyph) / 2] }) },
              { scale: progress.interpolate({ inputRange: [0, 1], outputRange: [0.6, 1] }) },
            ],
          },
        ]}
      >
        <Icon name="reply" size={sizes.icon.sm} color={colors.text2} strokeWidth={2.2} />
        <Animated.View
          style={[
            styles.replySwipeGlyph,
            styles.replySwipeArmed,
            { opacity: offset.interpolate({ inputRange: [REPLY_SWIPE_TRIGGER - 8, REPLY_SWIPE_TRIGGER], outputRange: [0, 1], extrapolate: "clamp" }) },
          ]}
        >
          <Icon name="reply" size={sizes.icon.sm} color={colors.accent} strokeWidth={2.2} />
        </Animated.View>
      </Animated.View>
      <Animated.View style={{ transform: [{ translateX: offset }] }}>{children}</Animated.View>
    </View>
  );
}

// A phone's bubble answers a long press, so there it is pressable; the
// desktop's is a plain pane that watches the pointer instead.
const BubbleShell = (isDesktop ? Animated.View : Animated.createAnimatedComponent(Pressable)) as typeof Animated.View;

// The message a reply answers, as its bubble quotes it. Without a name the
// original is no longer on this device, and the text says so.
export type BubbleQuote = { name?: string; accountId?: string; text: string; onPress?: () => void };

export function MessageBubble({
  body,
  sender,
  timestamp,
  sent,
  status,
  disappearing = false,
  tail = true,
  spaced = true,
  enter = false,
  attachments = [],
  reactions = [],
  reactionSender = "",
  onReact,
  reactionsDisabled = false,
  reactor,
  mentionUsernames = [],
  quote,
  onReply,
  highlighted = false,
}: {
  body: string;
  sender?: { name: string; accountId: string; avatar?: string };
  timestamp: number;
  sent: boolean;
  // How far a sent message has got. Received messages carry none.
  status?: MessageStatus;
  disappearing?: boolean;
  tail?: boolean;
  spaced?: boolean;
  // Only messages that arrive while the thread is open rise into place;
  // history that was already there renders settled.
  enter?: boolean;
  attachments?: BubbleAttachment[];
  reactions?: Reaction[];
  // The sender ID your own reactions carry, so yours can be told apart.
  reactionSender?: string;
  onReact?: (emoji: string) => void;
  reactionsDisabled?: boolean;
  // Who a reaction's sender is, for the list of people who reacted.
  reactor?: (sender: string) => { name: string; avatar?: string; accountId?: string } | undefined;
  mentionUsernames?: string[];
  // The message this one answers, quoted above its words.
  quote?: BubbleQuote;
  // Starts a reply to this message; without it the bubble does not offer one.
  onReply?: () => void;
  // The thread has just jumped here from a quote: the bubble flashes once.
  highlighted?: boolean;
}) {
  const { colors, scheme, type } = useTheme();
  const styles = useStyles();
  const [choosingReaction, setChoosingReaction] = useState(false);
  // The menu opens beside the bubble, wherever the thread has scrolled it to.
  const shell = useRef<View>(null);
  const [menuAnchor, setMenuAnchor] = useState<Frame | null>(null);
  const openMenu = () =>
    shell.current?.measureInWindow((x, y, width, height) => setMenuAnchor({ x, y, width, height }));
  const actions: MessageAction[] = [
    ...(onReply ? [{ icon: "reply" as const, label: "Reply", onPress: onReply }] : []),
    // ponytail: core Clipboard is deprecated but ships on every platform; move
    // to expo-clipboard with the next native rebuild.
    ...(body ? [{ icon: "copy" as const, label: "Copy", onPress: () => Clipboard.setString(body) }] : []),
  ];
  const hasMenu = Boolean(onReact) || actions.length > 0;
  // On desktop the controls keep out of the way until the pointer rests on the
  // bubble (or one of them is focused), as in other chat apps.
  const [hovered, setHovered] = useState(false);
  const [focusedAside, setFocusedAside] = useState(false);
  const revealAside = isDesktop && Boolean(onReact || onReply) && (hovered || focusedAside || menuAnchor !== null);
  const asideOpacity = useTimed(revealAside ? 1 : 0, motion.quick);
  const flash = useTimed(highlighted ? 1 : 0, motion.enter);
  const canReact = Boolean(onReact) && !reactionsDisabled;
  const mine = reactions.find((reaction) => reaction.senders.includes(reactionSender))?.emoji;
  const summary = summarizeReactions(reactions);
  const chooseReaction = (emoji: string) => {
    if (!canReact) return;
    setChoosingReaction(false);
    onReact?.(mine === emoji ? "" : emoji);
  };
  const reactorOf = (id: string) => reactor?.(id) ?? { name: id === reactionSender ? "You" : "Someone" };
  const [landing] = useState(() => new Animated.Value(enter ? 0 : 1));
  const [entersOnMount] = useState(enter);
  useEffect(() => {
    if (!entersOnMount) return;
    Animated.spring(landing, {
      toValue: 1,
      useNativeDriver: false,
      ...motion.springSoft,
    }).start();
  }, [entersOnMount, landing]);
  // Once per bubble, on mount: the thread remembers what it has already fetched.
  const [appeared] = useState(() => attachments.map((attachment) => attachment.onAppear));
  useEffect(() => {
    for (const onAppear of appeared) onAppear?.();
  }, [appeared]);
  const metaColor = sent ? colors.onAccentMuted : colors.text3;
  // The name is set in the hue of the sender's avatar, which follows their account.
  const senderInk = sender ? avatarTone(sender.accountId, scheme).ink : colors.text2;
  const described = [body, ...attachments.map((attachment) => `Attachment ${attachment.filename}, ${attachment.status}`)].filter(Boolean).join(". ");
  // A picture sits in a thin frame; the words around it keep the usual inset.
  const framed = attachments.some((attachment) => attachment.previewUri !== undefined);
  const reacted = summary.total > 0;
  const longPress = !isDesktop && hasMenu ? openMenu : undefined;
  // VoiceOver and TalkBack reach the menu as an action on the message's text.
  const menuAction = longPress
    ? { accessibilityActions: [{ name: "longpress", label: "Message actions" }], onAccessibilityAction: openMenu }
    : {};
  const shellEvents = isDesktop
    ? {
        onPointerEnter: () => setHovered(true),
        onPointerLeave: () => setHovered(false),
        // A right click opens the menu, unless it is on selected text, which
        // keeps the system's menu and its Copy.
        onContextMenu: (event: { preventDefault: () => void }) => {
          if (!hasMenu || window.getSelection()?.toString()) return;
          event.preventDefault();
          openMenu();
        },
      }
    : { accessible: false, onLongPress: longPress, delayLongPress: longPressDelay };
  const quoteInk = quote?.accountId && !sent ? avatarTone(quote.accountId, scheme).ink : sent ? colors.onAccent : colors.accent;
  const bubble = (
    <BubbleShell
      ref={shell}
      accessibilityLabel={`${sender ? sender.name : sent ? "Sent" : "Received"} message: ${described}`}
      {...(shellEvents as object)}
      style={[
        styles.bubble,
        sent ? styles.bubbleSent : styles.bubbleReceived,
        tail && (sent ? styles.bubbleTailSent : styles.bubbleTailReceived),
        sender ? styles.bubbleInGroup : spaced && styles.bubbleSpaced,
        framed && styles.bubbleFramed,
        reacted && styles.bubbleReacted,
        reacted && !sender && styles.bubbleReactedSpace,
        {
          opacity: landing,
          transform: [
            { translateY: landing.interpolate({ inputRange: [0, 1], outputRange: [14, 0] }) },
            { scale: landing.interpolate({ inputRange: [0, 1], outputRange: [0.94, 1] }) },
          ],
        },
      ]}
    >
      {sender && !sent && spaced ? (
        <Text
          numberOfLines={1}
          style={[styles.bubbleSender, framed && styles.bubbleCaption, framed && styles.bubbleCaptionAbove, { color: senderInk }]}
        >
          {sender.name}
        </Text>
      ) : null}
      {quote ? (
        <Pressable
          accessibilityRole={quote.onPress ? "button" : undefined}
          accessibilityLabel={quote.name ? `Replying to ${quote.name}: ${quote.text}` : quote.text}
          accessibilityHint={quote.onPress ? "Shows the original message" : undefined}
          disabled={!quote.onPress}
          onPress={quote.onPress}
          onLongPress={longPress}
          delayLongPress={longPressDelay}
          style={({ pressed }) => [
            styles.bubbleQuote,
            sent ? styles.bubbleFileSent : styles.bubbleFileReceived,
            !framed && styles.bubbleQuoteOutset,
            pressed && { opacity: 0.7 },
          ]}
        >
          <View style={[styles.bubbleQuoteBar, { backgroundColor: quoteInk }]} />
          <View style={styles.bubbleQuoteText}>
            {quote.name ? <Text numberOfLines={1} style={[styles.bubbleQuoteName, { color: quoteInk }]}>{quote.name}</Text> : null}
            <Text numberOfLines={quote.name ? 2 : 1} style={[styles.bubbleQuoteBody, { color: sent ? colors.onAccentMuted : colors.text2 }]}>
              {quote.text}
            </Text>
          </View>
        </Pressable>
      ) : null}
      {attachments.map((attachment) => (
        <View key={attachment.id} style={attachments.length > 1 && { marginBottom: space[1] }}>
          {attachment.previewUri !== undefined ? (
            <AttachmentPicture attachment={attachment} onLongPress={longPress} />
          ) : (
            <AttachmentCard attachment={attachment} sent={sent} onLongPress={longPress} />
          )}
        </View>
      ))}
      <View style={framed && styles.bubbleCaption}>
        {body ? (
          // A phone's long press belongs to the menu, which carries Copy; the
          // desktop's pointer selects the words themselves.
          <Text selectable={isDesktop} {...menuAction} style={[styles.bubbleBody, sent && styles.bubbleBodySent]}>
            {highlightMentions(body, mentionUsernames)}
          </Text>
        ) : null}
        <View style={styles.bubbleMeta}>
          {disappearing ? <Icon name="timer" size={sizes.icon.xs} color={metaColor} strokeWidth={2.2} /> : null}
          <Text {...(body ? {} : menuAction)} style={[styles.bubbleTime, { color: metaColor }]}>{formatClock(timestamp)}</Text>
          {status ? (
            // The bubble is already the accent, so "read" inverts: accent ticks on a
            // light chip. The shape tells it from "delivered" without relying on hue.
            <View
              accessible
              accessibilityRole="image"
              accessibilityLabel={describeStatus(status)}
              style={status === "read" && styles.bubbleRead}
            >
              <Icon
                name={status === "pending" ? "clock" : status === "sent" ? "check" : status === "failed" ? "warning" : "checks"}
                size={sizes.icon.xs}
                color={status === "read" ? colors.accentDeep : metaColor}
                strokeWidth={2.4}
              />
            </View>
          ) : null}
        </View>
      </View>
      {reacted ? (
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={describeReactions(reactions)}
          accessibilityHint="Shows who reacted"
          onPress={() => setChoosingReaction(true)}
          hitSlop={space[1]}
          style={({ pressed }) => [
            styles.reactionPill,
            sent ? styles.reactionPillSent : styles.reactionPillReceived,
            mine !== undefined && styles.reactionPillMine,
            pressed && { opacity: 0.6 },
          ]}
        >
          {summary.emojis.map((emoji) => (
            <Text key={emoji} style={styles.reactionPillEmoji}>{emoji}</Text>
          ))}
          {summary.total > 1 ? (
            <Text style={[styles.reactionPillCount, mine !== undefined && { color: colors.accent }]}>{summary.total}</Text>
          ) : null}
        </Pressable>
      ) : null}
      {/* The jump from a quote lands here: a wash that rises and fades. */}
      <Animated.View
        pointerEvents="none"
        style={[
          styles.bubbleFlash,
          sent ? styles.bubbleFlashSent : styles.bubbleFlashReceived,
          tail && (sent ? styles.bubbleTailSent : styles.bubbleTailReceived),
          { opacity: flash },
        ]}
      />
      {(onReact || onReply) && isDesktop ? (
        <Animated.View
          pointerEvents={revealAside ? "auto" : "none"}
          style={[styles.reactAside, sent ? styles.reactAsideSent : styles.reactAsideReceived, { opacity: asideOpacity }]}
        >
          {/* React sits nearest the bubble on either side. */}
          <View style={[styles.reactAsideCapsule, sent && { flexDirection: "row-reverse" }]}>
            {onReact ? (
              <AsideButton icon="smile" label="React" hint="Choose an emoji for this message"
                disabled={reactionsDisabled} onPress={openMenu} onFocusChange={setFocusedAside} />
            ) : null}
            {onReply ? (
              <AsideButton icon="reply" label="Reply" hint="Quotes this message in your reply"
                onPress={onReply} onFocusChange={setFocusedAside} />
            ) : null}
          </View>
        </Animated.View>
      ) : null}
      {menuAnchor ? (
        <MessageMenu
          anchor={menuAnchor}
          sent={sent}
          mine={mine}
          canReact={canReact}
          onReact={onReact}
          actions={actions}
          onClose={() => setMenuAnchor(null)}
        />
      ) : null}
      {choosingReaction ? (
        <Dialog visible label={reacted ? "Reactions" : "React to message"} onClose={() => setChoosingReaction(false)}>
          <View style={styles.reactionSheet}>
            <Text accessibilityRole="header" style={[type.title2, styles.reactionSheetTitle]}>{reacted ? "Reactions" : "React"}</Text>
            <Text numberOfLines={2} style={type.subhead}>{body || "Attachment"}</Text>
            <View style={styles.reactionBar}>
              {reactionEmojis.map(({ emoji, label }) => (
                <Pressable
                  key={emoji}
                  accessibilityRole="button"
                  accessibilityLabel={label}
                  accessibilityHint={mine === emoji ? "Removes your reaction" : undefined}
                  accessibilityState={{ selected: mine === emoji, disabled: !canReact }}
                  {...(Platform.OS === "web" ? { "aria-pressed": mine === emoji } : {})}
                  disabled={!canReact}
                  onPress={() => chooseReaction(emoji)}
                  style={({ pressed }) => [
                    styles.reactionChoice,
                    mine === emoji && styles.reactionChoiceSelected,
                    !canReact ? styles.disabled : pressed && { opacity: 0.6 },
                  ]}
                >
                  <Text style={styles.reactionChoiceEmoji}>{emoji}</Text>
                </Pressable>
              ))}
            </View>
          </View>
          {reacted ? (
            <ScrollView style={styles.reactionList} contentContainerStyle={styles.reactionListContent}>
              {rankReactions(reactions).flatMap(({ emoji, senders }) => senders.map((id) => {
                const who = reactorOf(id);
                const own = id === reactionSender;
                return (
                  <Row
                    key={`${emoji} ${id}`}
                    leading={(
                      <Avatar
                        name={who.name}
                        colorSeed={who.accountId}
                        uri={who.avatar}
                        size={isDesktop ? sizes.avatar.sm : sizes.avatar.md}
                      />
                    )}
                    title={own ? "You" : who.name}
                    subtitle={own && canReact ? (isDesktop ? "Click to remove" : "Tap to remove") : undefined}
                    onPress={own && canReact ? () => chooseReaction(emoji) : undefined}
                    accessibilityLabel={own ? `Your reaction, ${reactionLabel(emoji)}. Removes it` : undefined}
                    trailing={<Text style={styles.reactionRowEmoji}>{emoji}</Text>}
                  />
                );
              }))}
            </ScrollView>
          ) : null}
        </Dialog>
      ) : null}
    </BubbleShell>
  );
  const row = !sender ? bubble : (
    <View
      style={[
        styles.bubbleRow,
        sent && styles.bubbleRowSent,
        spaced ? styles.bubbleRowSpaced : styles.bubbleRowTight,
        reacted && styles.bubbleReactedSpace,
      ]}
    >
      {sent ? null : (
        <View style={styles.bubbleGutter}>
          {tail ? <Avatar name={sender.name} colorSeed={sender.accountId} uri={sender.avatar} size={sizes.avatar.xs} /> : null}
        </View>
      )}
      {bubble}
    </View>
  );
  return !isDesktop && onReply ? <ReplySwipe onReply={onReply}>{row}</ReplySwipe> : row;
}

export function DayDivider({ label }: { label: string }) {
  const styles = useStyles();
  return (
    <View style={styles.dayDivider}>
      <View style={styles.dayChip}>
        <Text style={styles.dayChipText}>{label}</Text>
      </View>
    </View>
  );
}

export function Chip({
  label,
  selected,
  onPress,
  accessibilityLabel,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
  accessibilityLabel?: string;
}) {
  const styles = useStyles();
  const fill = useTimed(selected ? 1 : 0);
  return (
    <Tap
      label={accessibilityLabel ?? label}
      state={{ selected }}
      onPress={onPress}
      style={styles.chip}
    >
      <Animated.View pointerEvents="none" style={[styles.chipFill, { opacity: fill }]} />
      <Text style={[styles.chipText, selected && styles.chipTextSelected]}>{label}</Text>
    </Tap>
  );
}

// A conversation row's metrics, shared with the separator that lines up with
// its text rather than its avatar.
const conversationRow = {
  inset: isDesktop ? space[2] : space[2.5],
  // A capsule's trailing cap curves in over the time and the unread count, so
  // they sit a step further from the edge than the avatar does.
  trail: isDesktop ? space[4] : space[2.5],
  gap: isDesktop ? space[2.5] : space[3.5],
  avatar: isDesktop ? sizes.avatar.md : sizes.avatar.xl,
};

const unreadLabel = (count: number) => `${count} unread ${count === 1 ? "message" : "messages"}`;

function UnreadBadge({ count }: { count: number }) {
  const styles = useStyles();
  if (count <= 0) return null;
  return (
    <View style={styles.unreadBadge} accessible={false}>
      <Text style={styles.unreadBadgeText}>{count > 99 ? "99+" : count}</Text>
    </View>
  );
}

export function ConversationRow({
  name,
  avatar,
  colorSeed,
  preview,
  time,
  unread = 0,
  blocked,
  verified,
  keyChanged,
  selected = false,
  onPress,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  preview: string;
  time: string;
  unread?: number;
  blocked: boolean;
  verified: boolean;
  keyChanged: boolean;
  // The conversation open in the pane beside the list.
  selected?: boolean;
  onPress: () => void;
}) {
  const { colors, type } = useTheme();
  const styles = useStyles();
  const badge = sizes.icon.sm;
  return (
    <Tap
      accessible={false}
      onPress={onPress}
      style={[styles.conversation, selected && styles.conversationSelected]}
      feedback="highlight"
    >
      {/* One row-sized element carries the stable label while the preview stays readable. */}
      <View
        accessible
        accessibilityRole="button"
        accessibilityLabel={`Conversation with ${name}${unread ? `, ${unreadLabel(unread)}` : ""}`}
        accessibilityState={{ selected }}
        pointerEvents="none"
        style={StyleSheet.absoluteFill}
      />
      <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={conversationRow.avatar} />
      <View style={styles.conversationBody}>
        <View style={styles.conversationLine}>
          <Text numberOfLines={1} style={[type.headline, styles.conversationName, unread > 0 && styles.unreadName]}>
            {name}
          </Text>
          {verified ? <Icon name="shield" size={badge} color={colors.success} strokeWidth={2.3} /> : null}
          {keyChanged ? <Icon name="warning" size={badge} color={colors.warning} strokeWidth={2.3} /> : null}
          {blocked ? <Icon name="block" size={badge} color={colors.text3} strokeWidth={2.3} /> : null}
          <View style={layout.flex} />
          {time ? <Text style={[styles.conversationTime, unread > 0 && styles.unreadTime]}>{time}</Text> : null}
        </View>
        <View style={styles.conversationLine}>
          <Text numberOfLines={1} style={[styles.conversationPreview, layout.flex, unread > 0 && styles.unreadPreview]}>
            {preview}
          </Text>
          <UnreadBadge count={unread} />
        </View>
      </View>
    </Tap>
  );
}

export function RequestGroup({ count, children }: { count: number; children: ReactNode }) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.requestGroup}>
      <View style={styles.requestHeader}>
        <Icon name="inbox" size={sizes.icon.md} color={colors.accent} strokeWidth={2.2} />
        <Text style={styles.requestTitle}>Message requests</Text>
        <View style={styles.requestCount}>
          <Text style={styles.requestCountText}>{count}</Text>
        </View>
      </View>
      {Children.toArray(children).map((child, index) => (
        <Fragment key={index}>
          {index > 0 ? <View style={styles.requestDivider} /> : null}
          {child}
        </Fragment>
      ))}
    </View>
  );
}

// A request row's avatar wears an accent ring: a border and the same gap
// inside it. Its divider, like the conversation separator, starts at the text.
const requestRowMetrics = {
  inset: space[2],
  gap: isDesktop ? space[2.5] : space[3],
  avatar: isDesktop ? sizes.avatar.sm : sizes.avatar.lg,
  ring: space[0.5],
};

export function RequestRow({
  name,
  avatar,
  colorSeed,
  preview,
  unread = 0,
  onPress,
  onAccept,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  preview: string;
  unread?: number;
  onPress: () => void;
  onAccept: () => void;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <Tap accessible={false} onPress={onPress} style={styles.requestRow} feedback="highlight">
      <View
        accessible
        accessibilityRole="button"
        accessibilityLabel={`Conversation with ${name}, message request pending${unread ? `, ${unreadLabel(unread)}` : ""}`}
        pointerEvents="none"
        style={StyleSheet.absoluteFill}
      />
      <View style={styles.requestAvatar}>
        <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={requestRowMetrics.avatar} />
      </View>
      <View style={styles.conversationBody}>
        <Text numberOfLines={1} style={type.headline}>
          {name}
        </Text>
        <Text numberOfLines={2} style={styles.requestPreview}>
          {preview}
        </Text>
      </View>
      <UnreadBadge count={unread} />
      <Button
        label="Accept"
        accessibilityLabel={`Accept request from ${name}`}
        size="sm"
        onPress={onAccept}
      />
    </Tap>
  );
}

export function ListSeparator() {
  const styles = useStyles();
  return <View style={styles.listSeparator} />;
}

export function GroupRow({
  name,
  avatar,
  colorSeed,
  subtitle,
  label,
  unread = 0,
  selected = false,
  onPress,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  subtitle: string;
  label: string;
  unread?: number;
  selected?: boolean;
  onPress: () => void;
}) {
  const { colors, type } = useTheme();
  const styles = useStyles();
  return (
    <Tap
      label={`${label}${unread ? `, ${unreadLabel(unread)}` : ""}`}
      state={{ selected }}
      onPress={onPress}
      style={[styles.conversation, selected && styles.conversationSelected]}
      feedback="highlight"
    >
      <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={conversationRow.avatar} group />
      <View style={styles.conversationBody}>
        <Text numberOfLines={1} style={[type.headline, styles.conversationName, unread > 0 && styles.unreadName]}>
          {name}
        </Text>
        <Text numberOfLines={1} style={styles.conversationPreview}>
          {subtitle}
        </Text>
      </View>
      <UnreadBadge count={unread} />
      {/* A sidebar row opens beside the list, so it needs no disclosure arrow. */}
      {isDesktop ? null : <Icon name="chevron" size={sizes.icon.md} color={colors.text3} strokeWidth={2.4} />}
    </Tap>
  );
}

// The code's edge: large enough to scan from across a table, small enough to
// leave room for its caption on a phone.
const qrSize = 228;

export function QrCard({ value, caption }: { value: string; caption?: string }) {
  const { colors } = useTheme();
  const styles = useStyles();
  const [showText, setShowText] = useState(false);
  const frames = qrFrames(value);
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    setFrame(0);
    if (frames.length === 1) return;
    const timer = setInterval(
      () => setFrame((previous) => (previous + 1) % frames.length),
      650,
    );
    return () => clearInterval(timer);
  }, [value, frames.length]);
  const current = frame % frames.length;
  return (
    <View style={styles.qrCard}>
      <QRCode
        backgroundColor={colors.paper}
        color={colors.ink}
        quietZone={0}
        size={qrSize}
        value={frames[current]!}
      />
      {frames.length > 1 ? (
        <View style={layout.center}>
          <View style={styles.qrDots}>
            {frames.map((_, index) => (
              <FrameDot key={index} active={index === current} />
            ))}
          </View>
          <Text style={styles.qrCaption}>
            Code {current + 1} of {frames.length} · Keep scanning
          </Text>
        </View>
      ) : caption ? (
        <Text style={styles.qrCaption}>{caption}</Text>
      ) : null}
      <Button label={showText ? "Hide text code" : "Show text code"} variant="ghost" onPress={() => setShowText(!showText)} />
      {showText ? <TextCode value={value} /> : null}
    </View>
  );
}

// Codes have no break opportunities, so the text needs the QR's fixed width
// to wrap inside the card instead of stretching it. Desktop codes run to a
// thousand characters; there the block scrolls so the card keeps its height,
// and a triple-click still selects the whole code.
function TextCode({ value }: { value: string }) {
  const styles = useStyles();
  const text = (
    <Text selectable accessibilityLabel="Text code" style={styles.qrTextValue}>
      {value}
    </Text>
  );
  return isDesktop ? (
    <ScrollView style={styles.qrText}>{text}</ScrollView>
  ) : (
    <View style={styles.qrText}>{text}</View>
  );
}

function FrameDot({ active }: { active: boolean }) {
  const { colors } = useTheme();
  const styles = useStyles();
  const progress = useTimed(active ? 1 : 0);
  return (
    <Animated.View
      style={[
        styles.qrDot,
        {
          width: progress.interpolate({ inputRange: [0, 1], outputRange: [6, 16] }),
          backgroundColor: progress.interpolate({
            inputRange: [0, 1],
            outputRange: [withAlpha(colors.black, 0.15), colors.accent],
          }),
        },
      ]}
    />
  );
}

// The scanner's frame: a square the camera can fill, with four stroked
// corners whose arcs the scan line stops short of.
const reticleSize = 256;
const reticleCorner = { size: control.xl, stroke: space[1], radius: radius["4xl"] - space[0.5] };

export function Reticle({ hint }: { hint: string }) {
  const styles = useStyles();
  const sweep = useLoop((value) =>
    Animated.sequence([
      Animated.timing(value, {
        toValue: 1,
        duration: 1900,
        easing: motion.easeInOut,
        useNativeDriver: true,
      }),
      Animated.timing(value, {
        toValue: 0,
        duration: 1900,
        easing: motion.easeInOut,
        useNativeDriver: true,
      }),
    ]),
  );
  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <View style={styles.mask} />
      <View style={styles.reticleRow}>
        <View style={styles.mask} />
        <View style={styles.reticle}>
          <View style={[styles.corner, styles.cornerTopLeft]} />
          <View style={[styles.corner, styles.cornerTopRight]} />
          <View style={[styles.corner, styles.cornerBottomLeft]} />
          <View style={[styles.corner, styles.cornerBottomRight]} />
          <Animated.View
            style={[
              styles.sweep,
              {
                opacity: sweep.interpolate({
                  inputRange: [0, 0.1, 0.9, 1],
                  outputRange: [0, 1, 1, 0],
                }),
                transform: [
                  {
                    translateY: sweep.interpolate({
                      inputRange: [0, 1],
                      outputRange: [12, reticleSize - 14],
                    }),
                  },
                ],
              },
            ]}
          />
        </View>
        <View style={styles.mask} />
      </View>
      <View style={[styles.mask, styles.maskBottom]}>
        <Glass style={styles.reticleHint} fallback={styles.reticleHintSurface}>
          <Text style={styles.reticleHintText}>{hint}</Text>
        </Glass>
      </View>
    </View>
  );
}

// The status pill's lane: it opens above the screen on a phone and below the
// pane on the desktop, and the pill sits at the edge nearest the content.
const statusLane = isDesktop
  ? { near: space[2], far: space[4] }
  : { near: space[1.5], far: space[1.5] };

// Transient status shows as a compact pill in a lane of its own in the
// layout, so it never covers anything: the lane eases open to the pill's
// height and the screen moves out of its way. Errors stay until dismissed.
export function StatusPill({
  text,
  busy,
  error,
  onDismiss,
}: {
  text: string;
  busy: boolean;
  error: boolean;
  onDismiss?: () => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  // Quick operations finish before anyone needs progress; only work that
  // outlasts a beat earns a pill. Errors always show immediately.
  const [busyLongEnough, setBusyLongEnough] = useState(false);
  useEffect(() => {
    if (!busy) {
      setBusyLongEnough(false);
      return;
    }
    const timer = setTimeout(() => setBusyLongEnough(true), 350);
    return () => clearTimeout(timer);
  }, [busy]);
  const visible = text.length > 0 && (error || busyLongEnough);
  // Snapshot the last visible content so the pill exits showing what it said,
  // not the empty string that hid it.
  const [shown, setShown] = useState({ text, busy, error });
  useEffect(() => {
    if (visible) setShown({ text, busy, error });
  }, [busy, error, text, visible]);
  const display = visible ? { text, busy, error } : shown;
  const liquid = useLiquidGlass();
  const { mounted, progress } = usePresence(visible);
  const materialized = useMaterialized(visible);
  // The pill's own height, measured so the lane can be exactly as tall as
  // the text it holds, however many lines that takes.
  const [pillHeight, setPillHeight] = useState(0);
  if (!mounted) return null;
  const laneHeight = pillHeight ? pillHeight + statusLane.near + statusLane.far : 0;
  const content = (
    <>
      <View
        accessible
        accessibilityLiveRegion={display.error ? "assertive" : "polite"}
        style={styles.statusContent}
      >
        {display.busy ? (
          <ActivityIndicator size="small" color={colors.accent} />
        ) : (
          <Icon
            name={display.error ? "warning" : "check"}
            size={sizes.icon.lg}
            color={display.error ? colors.danger : colors.accent}
            strokeWidth={2.4}
          />
        )}
        <Text numberOfLines={3} style={styles.statusText}>
          {display.text}
        </Text>
      </View>
      {display.error && onDismiss ? (
        <Tap label="Dismiss" onPress={onDismiss} hitSlop={space[3]} pressedOpacity={0.55}>
          <Icon name="close" size={sizes.icon.md} color={colors.text2} />
        </Tap>
      ) : null}
    </>
  );
  // The pill is pinned to the lane's near edge, so it rises out of the
  // window's bottom edge on the desktop and drops in under the status bar on
  // a phone as the lane opens. Glass forms and dissolves through the system
  // effect, so only the content inside it fades; the opaque fallback fades
  // as a whole.
  return (
    <Animated.View
      pointerEvents={visible ? "box-none" : "none"}
      style={[
        styles.statusLane,
        { height: progress.interpolate({ inputRange: [0, 1], outputRange: [0, laneHeight] }) },
      ]}
    >
      <Animated.View
        onLayout={(event) => setPillHeight(event.nativeEvent.layout.height)}
        style={[
          styles.statusPillWrap,
          isDesktop ? { top: statusLane.near } : { bottom: statusLane.near },
          {
            opacity: liquid ? 1 : progress,
            transform: [{ scale: progress.interpolate({ inputRange: [0, 1], outputRange: [0.94, 1] }) }],
          },
        ]}
      >
        <Pressable
          accessible={false}
          disabled={!display.error || !onDismiss}
          onPress={onDismiss}
        >
          <Glass
            materialized={materialized}
            tint={display.error ? withAlpha(colors.danger, 0.2) : undefined}
            fallback={[styles.statusPillSurface, display.error && styles.statusPillError]}
            style={[styles.statusPill, display.error && styles.statusPillErrorGlass]}
          >
            <Animated.View style={[styles.statusContentRow, liquid && { opacity: progress }]}>
              {content}
            </Animated.View>
          </Glass>
        </Pressable>
      </Animated.View>
    </Animated.View>
  );
}

export function TabBar<T extends string>({
  tabs,
  current,
  onSelect,
}: {
  tabs: readonly { key: T; title: string; icon: IconName; badge?: number }[];
  current: T;
  onSelect: (key: T) => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const liquid = useLiquidGlass();
  const index = Math.max(0, tabs.findIndex((tab) => tab.key === current));
  const position = useSprung(index);
  return (
    <View style={[styles.tabBarWrap, { paddingBottom: tabBarPadding }]}>
      <ScrollEdge side="bottom" height={chrome.tabBar + tabBarPadding + 40} />
      <Glass style={styles.tabPill} fallback={styles.tabPillSurface}>
        <Animated.View
          pointerEvents="none"
          style={[
            styles.tabIndicator,
            liquid && styles.tabIndicatorGlass,
            { transform: [{ translateX: Animated.multiply(position, tabHeight + tabGap) }] },
          ]}
        />
        {tabs.map((tab) => {
          const active = tab.key === current;
          return (
            <Pressable
              key={tab.key}
              testID={`tab-${tab.key}`}
              accessibilityRole="tab"
              accessibilityLabel={`${tab.title}${tab.badge ? `, ${tab.badge} needing attention` : ""}`}
              accessibilityState={{ selected: active }}
              onPress={() => onSelect(tab.key)}
              // The gaps and the pill's rim still belong to the nearest tab.
              hitSlop={{ left: tabGap / 2, right: tabGap / 2, top: tabPillPadding, bottom: tabPillPadding }}
              style={({ pressed }) => [styles.tabItem, pressed && !active && styles.tabItemPressed]}
            >
              <View>
                <Icon
                  name={tab.icon}
                  size={sizes.icon.xl}
                  color={active ? colors.accent : colors.text2}
                  strokeWidth={active ? 2.3 : 1.9}
                />
                {tab.badge ? <View style={styles.tabBadge}><UnreadBadge count={tab.badge} /></View> : null}
              </View>
            </Pressable>
          );
        })}
      </Glass>
    </View>
  );
}

// The sidebar's switch between its lists: a compact segmented control of
// glyphs with a sliding thumb, sized to its contents the way a toolbar's view
// switch is. A dot leads icons needing attention; counts remain in their
// accessible labels. The web shell transitions the widths and thumb together.
const segmentPadding = space[0.5];
const segmentWidth = control.md;
const segmentDotSpace = space[1.5] + space[1];
export function SegmentedControl<T extends string>({
  segments,
  current,
  onSelect,
}: {
  segments: readonly { key: T; title: string; icon: IconName; badge?: number }[];
  current: T;
  onSelect: (key: T) => void;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const liquid = useLiquidGlass();
  const index = Math.max(0, segments.findIndex((segment) => segment.key === current));
  const widths = segments.map((segment) => segmentWidth + (segment.badge ? segmentDotSpace : 0));
  const offset = widths.slice(0, index).reduce((sum, width) => sum + width, 0);
  // The thumb is the only thing marking the selection, so on glass the glyph
  // takes the tone the scheme gives that pane rather than plain body text.
  const activeGlyph = liquid ? colors.glassGlyph : colors.text;
  return (
    <Glass
      accessibilityRole="tablist"
      interactive
      style={styles.segmented}
      fallback={styles.segmentedSurface}
    >
      <View
        testID="segment-thumb"
        pointerEvents="none"
        style={[
          styles.segmentThumb,
          liquid && styles.segmentThumbGlass,
          { width: widths[index], transform: [{ translateX: offset }] },
        ]}
      />
      {segments.map((segment, segmentIndex) => {
        const active = segment.key === current;
        return (
          <Pressable
            key={segment.key}
            testID={`segment-${segment.key}`}
            accessibilityRole="tab"
            accessibilityLabel={`${segment.title}${segment.badge ? `, ${segment.badge} needing attention` : ""}`}
            accessibilityState={{ selected: active }}
            onPress={() => onSelect(segment.key)}
            hitSlop={{ top: space[1], bottom: space[1] }}
            style={[styles.segment, { width: widths[segmentIndex] }]}
          >
            <View
              testID="segment-dot"
              aria-hidden
              pointerEvents="none"
              style={[
                styles.segmentDot,
                { width: segment.badge ? space[1.5] : 0, marginRight: segment.badge ? space[1] : 0, opacity: segment.badge ? 1 : 0 },
              ]}
            />
            <Icon
              name={segment.icon}
              size={sizes.icon.sm}
              color={active ? activeGlyph : colors.text2}
              strokeWidth={active ? 2.2 : 1.9}
            />
          </Pressable>
        );
      })}
    </Glass>
  );
}

// The signed-in account at the foot of the sidebar, with the way into settings.
export function AccountBar({
  name,
  avatar,
  colorSeed,
  active,
  onSettings,
}: {
  name: string;
  avatar?: string;
  colorSeed?: string;
  active: boolean;
  onSettings: () => void;
}) {
  const styles = useStyles();
  return (
    <View style={styles.accountBar}>
      <Avatar name={name} uri={avatar} colorSeed={colorSeed} size={sizes.avatar.xs} />
      <Text numberOfLines={1} style={[styles.accountName, layout.flex]}>
        @{name}
      </Text>
      <IconButton
        name="sliders"
        label="Settings"
        variant={active ? "tonal" : "plain"}
        glass={false}
        onPress={onSettings}
      />
    </View>
  );
}

export function FeatureRow({
  icon,
  title,
  body,
}: {
  icon: IconName;
  title: string;
  body: string;
}) {
  const { colors, type } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.feature}>
      <View style={styles.featureIcon}>
        <Icon name={icon} size={sizes.icon.xl} color={colors.accent} strokeWidth={2} />
      </View>
      <View style={[layout.flex, { gap: space[0.5] }]}>
        <Text style={type.headline}>{title}</Text>
        <Text style={type.subhead}>{body}</Text>
      </View>
    </View>
  );
}

export function KeyValue({ label, value }: { label: string; value: string }) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.keyValue}>
      <Text style={type.caption}>{label}</Text>
      <Text selectable style={type.mono}>
        {value}
      </Text>
    </View>
  );
}

export function CodeDisplay({ value }: { value: string }) {
  const styles = useStyles();
  return (
    <Text selectable accessibilityLabel={`Code ${value}`} style={styles.code}>
      {value}
    </Text>
  );
}

// A short code to compare across two screens, with the words that say what to
// do with it. Centred as a phone would show it; set flush left on desktop,
// where it sits in a column of text.
export function CodeBlock({
  label,
  value,
  note,
}: {
  label: string;
  value: string;
  note?: string;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.codeBlock}>
      <Text style={type.sectionTitle}>{label}</Text>
      <CodeDisplay value={value} />
      {note ? <Text style={[type.caption, !isDesktop && layout.centerText]}>{note}</Text> : null}
    </View>
  );
}

// The buttons that finish a form. A phone stacks them edge to edge; a desktop
// sets them side by side at their natural width, the primary action first.
export function Actions({
  children,
  style,
}: {
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
}) {
  const styles = useStyles();
  return <View style={[styles.actions, style]}>{children}</View>;
}

// A QR code and the words that go with it. A phone reads top to bottom:
// intro, code, details, actions. A desktop window is wider than it is tall,
// so the code sits beside the copy, with both centred vertically in the pane.
export function QrLayout({
  intro,
  qr,
  details,
  actions,
}: {
  intro: ReactNode;
  qr: ReactNode;
  details?: ReactNode;
  actions?: ReactNode;
}) {
  const styles = useStyles();
  if (!isDesktop) {
    return (
      <>
        {intro}
        {qr}
        {details}
        {actions}
      </>
    );
  }
  return (
    <View style={styles.qrSpread}>
      <View style={styles.qrSpreadText}>
        {intro}
        {details}
        {actions}
      </View>
      {qr}
    </View>
  );
}

// Content containers start below the floating header and end above the
// floating tab bar, so rows scroll under both edges.
// A desktop pane can be far wider than a column of text should be, so page
// content keeps to a reading column centred in the pane, and a thread to a
// wider one. Every header spans the pane independently of its content column.
export const columns = {
  reading: { maxWidth: 760, padding: space[8] },
  thread: { maxWidth: 900, padding: space[6] },
} as const;
const centred = (column: { maxWidth: number; padding: number }) =>
  ({ width: "100%", maxWidth: column.maxWidth, alignSelf: "center", paddingHorizontal: column.padding }) as const;
const readingContent = {
  ...centred(columns.reading),
  paddingTop: paneContentTop,
  paddingBottom: space[10],
};
const threadContent = { ...centred(columns.thread), paddingTop: paneContentTop };

// Layout alone, with no colour in it, so it can stay one static sheet.
export const layout = StyleSheet.create({
  flex: { flex: 1 },
  threadContent,
  content: desk(
    {
      flexGrow: 1,
      paddingHorizontal: screenInset,
      paddingTop: chrome.header + space[3],
      paddingBottom: space[8],
      gap: space[5],
    },
    { ...readingContent, gap: space[6] },
  ),
  contentTight: desk(
    {
      flexGrow: 1,
      paddingHorizontal: screenInset,
      paddingTop: chrome.largeHeader + space[1.5],
      paddingBottom: chrome.tabBarSpace,
      gap: space[4],
    },
    { ...readingContent, gap: space[5] },
  ),
  // Content of a desktop screen shown without the sidebar, such as linking a
  // device before there is an account: centred in the window like a sheet,
  // with the toolbar's height mirrored below so the centre is optical.
  sheet: desk({}, { justifyContent: "center", paddingBottom: paneContentTop }),
  // A screen that is one centred block under a floating header: the block
  // fills the height so it can centre itself, and scrolls if it cannot.
  centredScreen: { flexGrow: 1, paddingTop: chrome.header },
  stack: { gap: space[3] },
  stackLoose: { gap: space[5] },
  row: { flexDirection: "row", alignItems: "center", gap: space[3] },
  rowBetween: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: space[3],
  },
  wrap: { flexDirection: "row", flexWrap: "wrap", gap: space[2] },
  center: { alignItems: "center", gap: space[2] },
  centerText: { textAlign: "center" },
  list: desk(
    {
      flexGrow: 1,
      paddingHorizontal: space[2.5],
      paddingTop: chrome.largeHeader + space[1.5],
      paddingBottom: chrome.tabBarSpace,
    },
    { paddingHorizontal: space[2], paddingBottom: space[3] },
  ),
  // Sidebar rows scroll under the toolbar and stop above the account bar. They
  // start past its fade, so the first row is whole rather than half dissolved.
  sidebarList: {
    flexGrow: 1,
    paddingHorizontal: space[2],
    paddingTop: SIDEBAR_LIST_TOP,
    paddingBottom: space[3],
  },
  // Inverted thread: `paddingBottom` is the visual top, under the chat header.
  // The screen adds the composer's measured height at the visual bottom.
  messages: desk(
    {
      flexGrow: 1,
      paddingHorizontal: space[3],
      paddingTop: space[3],
      paddingBottom: chrome.chatHeader + space[3],
    },
    { ...threadContent, paddingTop: space[4] },
  ),
  inset: { paddingHorizontal: screenInset },
});

// A single-line field draws its text without a line height: with one, the
// caret and text sit off-centre on Android.
const singleLine = { lineHeight: undefined } as const;

// The height a text field's own input takes inside a bordered shell.
const inner = (height: number) => height - 2;

const useStyles = themed(({ colors, type, elevation }) =>
  StyleSheet.create({
  disabled: { opacity: opacities.disabled },
  wash: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: colors.highlight,
  },
  veil: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: colors.canvas,
  },
  glow: { position: "absolute" },
  glyph: elevation.glyph,
  chrome: { position: "absolute", top: 0, left: 0, right: 0 },
  frost: { position: "absolute", top: 0, left: 0, right: scrollbarGutter },
  // Lets the pointer fall through to the drag region beneath a toolbar label.
  passive: { pointerEvents: "none" },
  dragStrip: { position: "absolute", top: 0, left: 0, right: 0, height: TOOLBAR_HEIGHT },
  scrollEdge: { position: "absolute", left: 0, right: scrollbarGutter },
  scrollEdgeTop: { top: 0 },
  scrollEdgeBottom: { bottom: 0 },
  // Sits a pixel outside the control so it rings the border, not the fill.
  focusRing: {
    position: "absolute",
    top: -1,
    left: -1,
    right: -1,
    bottom: -1,
    borderWidth: 1.5,
    borderColor: colors.accent,
  },

  button: desk(
    {
      minHeight: control["3xl"],
      borderRadius: radius.pill,
      flexDirection: "row",
      alignItems: "center",
      justifyContent: "center",
      gap: space[2],
      paddingHorizontal: space[5],
      paddingVertical: space[3],
    },
    {
      minHeight: control.md,
      borderRadius: radius.xs,
      gap: space[1.5],
      paddingHorizontal: space[3.5],
      paddingVertical: space[1.5],
    },
  ),
  buttonWithIcon: { paddingLeft: isDesktop ? space[3] : space[5] },
  buttonSmall: desk(
    { minHeight: control.md, paddingHorizontal: space[3.5], paddingVertical: space[1.5], gap: space[1.5] },
    { minHeight: control.xs, paddingHorizontal: space[2.5], paddingVertical: space[0.5] },
  ),
  buttonSmallWithIcon: { paddingLeft: isDesktop ? space[2] : space[3] },
  buttonPrimary: { backgroundColor: colors.accent },
  buttonSecondary: desk(
    { backgroundColor: colors.raised },
    { borderWidth: 1, borderColor: colors.lineStrong },
  ),
  buttonDanger: { backgroundColor: colors.dangerSoft },
  buttonText: {
    ...type.body,
    ...singleLine,
    fontFamily: fonts.semibold,
    letterSpacing: isDesktop ? -0.1 : -0.2,
    textAlign: "center",
  },
  buttonTextSmall: { fontSize: type.label.fontSize },

  iconButton: {
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  iconButtonTonal: desk(
    { backgroundColor: colors.raised },
    { borderWidth: 1, borderColor: colors.line },
  ),
  iconButtonFilled: { backgroundColor: colors.accent },
  iconButtonSoft: { backgroundColor: colors.accentSoft },

  headerRow: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
  },
  header: { paddingHorizontal: space[3], gap: space[3] },
  largeHeader: { paddingHorizontal: screenInset, gap: space[3] },
  chatHeader: { paddingHorizontal: space[2.5], gap: space[2.5] },
  // Either side reserves an icon button's width so the title stays centred.
  headerSide: { minWidth: control.xl, alignItems: "flex-start" },
  headerSideEnd: { alignItems: "flex-end" },
  headerTitle: { ...type.headline, flex: 1, textAlign: "center" },
  // Desktop pane titles sit at toolbar weight rather than as a large title.
  toolbarTitle: type.headline,
  headerActions: { flexDirection: "row", alignItems: "center", gap: isDesktop ? space[1] : space[2.5] },
  sidebarHeader: {
    height: TOOLBAR_HEIGHT,
    flexDirection: "row",
    alignItems: "center",
    gap: space[2],
    paddingRight: space[2.5],
  },
  chatTitle: { flex: 1, flexDirection: "row", alignItems: "center", gap: space[1.5] },
  chatName: { flexShrink: 1 },

  avatarOverlay: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    alignItems: "center",
    justifyContent: "center",
  },
  hero: { alignItems: "center", gap: space[2.5], paddingTop: space[1.5] },
  heroDesktop: { flexDirection: "row", alignItems: "center", gap: space[4], paddingVertical: space[1] },
  heroDesktopText: { flex: 1, alignItems: "flex-start", gap: space[1] },
  heroDesktopBadge: { marginTop: space[1] },
  heroActions: {
    flexDirection: "row",
    flexWrap: "wrap",
    alignItems: "center",
    gap: space[2],
    marginTop: isDesktop ? space[2] : space[1],
  },
  heroActionsCentred: { justifyContent: "center" },
  // The camera sits on the picture's lower shoulder, ringed in the pane
  // colour so it reads as resting on the photo rather than cut into it.
  photoBadge: {
    position: "absolute",
    right: 0,
    bottom: 0,
    backgroundColor: colors.accent,
    borderWidth: 2,
    borderColor: colors.canvas,
    alignItems: "center",
    justifyContent: "center",
  },

  badge: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[1],
    borderRadius: radius.pill,
    paddingHorizontal: space[2.5],
    paddingVertical: space[1],
  },
  badgeText: { ...type.caption, fontFamily: fonts.semibold, letterSpacing: 0.1 },

  field: { gap: isDesktop ? space[1.5] : space[2] },
  inputShell: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: space[0.5],
      backgroundColor: colors.surface,
      borderRadius: radius.lg,
      borderWidth: 1,
      borderColor: colors.line,
      minHeight: control["3xl"],
      paddingHorizontal: space[4],
    },
    {
      borderRadius: radius.xs,
      borderColor: colors.lineStrong,
      minHeight: control.md,
      paddingHorizontal: space[3],
    },
  ),
  inputShellMultiline: { alignItems: "flex-start", paddingVertical: space[1] },
  inputPrefix: { ...type.input, ...singleLine, fontFamily: fonts.medium, color: colors.text3 },
  input: desk(
    { ...type.input, ...singleLine, flex: 1, minHeight: inner(control["3xl"]), paddingVertical: 0 },
    { minHeight: inner(control.md) },
  ),
  // Room for roughly four lines before the field scrolls.
  inputMultiline: desk(
    { minHeight: type.input.lineHeight * 4 + space[4], paddingTop: space[3], textAlignVertical: "top" },
    { minHeight: type.input.lineHeight * 4 + space[2], paddingTop: space[2] },
  ),

  // The shell takes the composer's height and corner on each platform, so the
  // two fields of a new message read as a pair. It spans the empty state's
  // width on a phone and a field's measure on the desktop.
  recipient: desk(
    {
      width: "100%",
      flexDirection: "row",
      alignItems: "center",
      gap: space[0.5],
      minHeight: control["2xl"],
      paddingHorizontal: space[4],
      borderRadius: radius.pill,
      backgroundColor: colors.surface,
      borderWidth: 1,
      borderColor: colors.line,
    },
    {
      maxWidth: 360,
      minHeight: control.lg,
      paddingHorizontal: space[3],
      borderRadius: radius.md,
      borderColor: colors.lineStrong,
    },
  ),
  recipientLabel: { ...type.label, ...singleLine, marginRight: space[2] },
  recipientPrefix: { ...type.input, ...singleLine, fontFamily: fonts.medium, color: colors.text3 },
  recipientInput: { ...type.input, ...singleLine, flex: 1, paddingVertical: 0 },

  card: desk(
    {
      backgroundColor: colors.surface,
      borderRadius: radius["2xl"],
      overflow: "hidden",
    },
    { borderRadius: radius.md, borderWidth: 1, borderColor: colors.line },
  ),
  cardPadded: desk({ padding: space[5], gap: space[3] }, { padding: space[4], gap: space[2.5] }),
  cardAccent: {
    backgroundColor: colors.accentSoft,
    borderWidth: 1,
    borderColor: withAlpha(colors.accent, 0.25),
  },

  section: { gap: space[2] },
  sectionHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: space[1.5],
  },
  sectionFooter: { ...type.footnote, paddingHorizontal: space[1.5], paddingTop: space[0.5] },

  rowGroup: { padding: rowGroupInset },
  // The row's corner is the card's less the inset, so a lit row stays
  // concentric with the card around it.
  row: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: space[3.5],
      paddingHorizontal: space[4] - rowGroupInset,
      paddingVertical: space[3],
      minHeight: control["4xl"],
      borderRadius: radius["2xl"] - rowGroupInset,
    },
    {
      gap: space[3],
      paddingHorizontal: space[3.5] - rowGroupInset,
      paddingVertical: space[2],
      minHeight: control["2xl"],
      borderRadius: radius.md - rowGroupInset,
    },
  ),
  rowPlain: desk(
    { minHeight: control["3xl"], paddingVertical: space[2.5] },
    { minHeight: control.xl, paddingVertical: space[2] },
  ),
  rowIcon: desk(
    {
      width: sizes.tile.md,
      height: sizes.tile.md,
      borderRadius: radius.sm,
      alignItems: "center",
      justifyContent: "center",
    },
    { width: sizes.tile.sm, height: sizes.tile.sm, borderRadius: radius.xs },
  ),
  rowCheck: { width: sizes.badge.lg, alignItems: "center" },

  // A row's segmented choice borrows the sidebar switch's track and thumb
  // colours, on a track a finger can use: a phone's is taller and its glyph
  // segments are a full hit target wide.
  choiceTrack: { height: isDesktop ? control.xs : control.lg },
  // The track stretches the pressable; the segment inside fills it, so the
  // thumb is as tall as the track allows whatever the glyph or word measures.
  choiceSegment: {
    flex: 1,
    minWidth: isDesktop ? segmentWidth : sizes.hit,
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radius.pill,
  },
  // Four words and a title share a 360-point phone row only if each word
  // gives a little of the target's width back.
  choiceSegmentWord: desk({ minWidth: control.xl, paddingHorizontal: space[2] }, { minWidth: segmentWidth, paddingHorizontal: space[2.5] }),
  choiceThumb: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    borderRadius: radius.pill,
    backgroundColor: colors.thumb,
    ...elevation.thumb,
  },
  choiceWord: { ...type.label, fontFamily: fonts.medium, color: colors.text2 },
  choiceWordSelected: { color: colors.text },
  toggle: { ...toggleTrack, borderRadius: radius.pill },
  // The accent floods the whole track, its hairline included.
  toggleOn: {
    position: "absolute",
    top: -1,
    right: -1,
    bottom: -1,
    left: -1,
    borderRadius: radius.pill,
    backgroundColor: colors.accent,
  },
  // Inset evenly from the track's outer edge, a pixel of which is its hairline.
  toggleThumb: {
    position: "absolute",
    top: space[0.5] - 1,
    left: space[0.5] - 1,
    ...toggleThumb,
    borderRadius: radius.pill,
    backgroundColor: colors.white,
    ...elevation.thumb,
  },
  // The well is cut into the card and spans it, so the number sits in a band
  // aligned with the rows around it rather than on a plaque adrift in the
  // middle. Lines wrap as wholes: two to a row where they fit, else one.
  safetyWell: desk(
    {
      flexDirection: "row",
      flexWrap: "wrap",
      justifyContent: "center",
      columnGap: space[8],
      rowGap: space[1.5],
      marginHorizontal: space[3],
      marginTop: space[1],
      marginBottom: space[3],
      paddingVertical: space[4],
      paddingHorizontal: space[3],
      borderRadius: radius.lg,
      borderWidth: 1,
      borderColor: colors.line,
      backgroundColor: colors.canvas,
    },
    {
      columnGap: space[10],
      rowGap: space[1],
      marginHorizontal: space[2.5],
      marginBottom: space[2.5],
      paddingVertical: space[3.5],
      borderRadius: radius.sm,
    },
  ),
  safetyWellVerified: { backgroundColor: colors.successSoft, borderColor: withAlpha(colors.success, 0.22) },
  safetyWellChanged: { backgroundColor: colors.warningSoft, borderColor: withAlpha(colors.warning, 0.28) },
  // The gap between groups is a space step, so a line fits a narrow phone
  // beside the card's and the well's insets: four groups and three gaps.
  safetyLine: { flexDirection: "row", gap: isDesktop ? space[5] : space[4] },
  safetyDigits: { ...type.monoLarge, includeFontPadding: false },
  safetyDigitsSetBack: { color: colors.text2 },

  notice: desk(
    {
      flexDirection: "row",
      alignItems: "flex-start",
      gap: space[2.5],
      borderRadius: radius.lg,
      padding: space[3.5],
      backgroundColor: colors.surface,
    },
    { borderRadius: radius.sm, padding: space[3], borderWidth: 1, borderColor: colors.line },
  ),
  noticeText: { ...type.footnote, flex: 1 },

  dialogScrim: desk(
    { flex: 1, justifyContent: "flex-end", backgroundColor: colors.scrim },
    { alignItems: "center", justifyContent: "center", padding: space[6] },
  ),
  // The sheet's top corners take the largest radius; it rests on the home
  // indicator's inset. The desktop card is an alert's width and lifted.
  dialog: desk(
    {
      maxHeight: "85%",
      paddingTop: space[3],
      paddingBottom: Math.max(initialWindowMetrics?.insets.bottom ?? 0, space[5]),
      borderTopLeftRadius: radius["4xl"],
      borderTopRightRadius: radius["4xl"],
      backgroundColor: colors.raised,
    },
    {
      width: "100%",
      maxWidth: 420,
      maxHeight: "85%",
      paddingTop: space[5],
      paddingBottom: space[4],
      borderRadius: radius["2xl"],
      borderWidth: 1,
      borderColor: colors.lineStrong,
      ...elevation.raised,
    },
  ),
  // The close disc: a step lighter than the pane, in the corner the sheet's
  // and the card's padding leave free.
  dialogClose: { position: "absolute", top: space[3], right: space[3] },
  dialogCloseDisc: {
    width: isDesktop ? control.xs : control.sm,
    height: isDesktop ? control.xs : control.sm,
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.elevated,
  },

  // Grows into whatever space is empty, and past it if its content is taller,
  // so a scrolling parent can still reach the ends.
  empty: {
    flexGrow: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: space[8],
    paddingVertical: space[10],
    // The title and the sentence beneath it are the closest pair in the state
    // and read as one block, so the gap is set for those two. Everything else
    // stands further off and adds its own margin on top of this.
    gap: space[1],
  },
  sidebarEmptyText: { ...type.footnote, color: colors.text2, textAlign: "center" },
  // Further from the title than the title is from its sentence, so the two
  // lines of copy group together under the glyph rather than beside it.
  emptyIconWrap: { marginBottom: space[2.5] },
  emptyTitle: { ...type.title2, textAlign: "center" },
  // A comfortable measure for a sentence or two of centred copy.
  emptyBody: { ...type.subhead, textAlign: "center", maxWidth: 280 },
  // The control spans the state's width so it can take a measure of its own.
  emptyControl: { alignSelf: "stretch", alignItems: "center", marginTop: space[4] },
  emptyAction: { marginTop: space[4], alignItems: "center", gap: space[1.5] },

  // On desktop the bar is docked, not floating: the pane colour behind it
  // and a hairline above, like a message field in a native window.
  composerBar: desk(
    {
      position: "absolute",
      left: 0,
      right: 0,
      bottom: 0,
      paddingHorizontal: space[3],
      paddingTop: space[2],
      paddingBottom: space[1.5],
    },
    {
      right: scrollbarGutter,
      paddingHorizontal: columns.thread.padding,
      paddingTop: space[2.5],
      paddingBottom: space[3.5],
      backgroundColor: colors.canvas,
      borderTopWidth: StyleSheet.hairlineWidth,
      borderTopColor: colors.line,
    },
  ),
  composerBarFloating: { backgroundColor: "transparent", borderTopWidth: 0 },
  // The field spans the thread's column between its paddings.
  composerShellWrap: desk(
    {},
    { width: "100%", maxWidth: columns.thread.maxWidth - 2 * columns.thread.padding, alignSelf: "center" },
  ),
  // A capsule at one line, keeping that corner as it grows: the radius is
  // half the one-line height on each platform, since a pill radius would
  // round the whole of a taller field. The field inside grows to its ceiling
  // (composerCeiling) before it scrolls; a staged file sits above it.
  composerShell: {
    minHeight: composerHeight,
    borderRadius: composerRadius,
  },
  composerRow: desk(
    {
      flexDirection: "row",
      alignItems: "flex-end",
      paddingLeft: space[1.5],
      paddingRight: space[1.5],
    },
    { paddingLeft: space[1], paddingRight: space[1] },
  ),
  composerShellSurface: desk(
    {
      backgroundColor: colors.thumb,
      borderWidth: 1,
      borderColor: colors.lineStrong,
      ...elevation.raised,
    },
    { backgroundColor: colors.surface, boxShadow: undefined },
  ),
  composerAttach: { paddingBottom: isDesktop ? space[1] : space[1.5] },
  composerInput: desk(
    {
      ...type.input,
      flex: 1,
      paddingTop: composerPadding,
      paddingBottom: composerPadding,
      paddingLeft: space[1.5],
      paddingRight: space[2],
    },
    { paddingTop: composerPadding, paddingBottom: composerPadding, paddingLeft: space[1] },
  ),
  // Without an attach button the text starts where the capsule's curve ends.
  composerInputLead: { paddingLeft: isDesktop ? space[2] : space[2.5] },
  composerInputDisabled: { color: colors.text3 },
  composerSend: { paddingBottom: isDesktop ? space[1] : space[1.5] },
  // The staged file: a row above the field, inset to the capsule's curve,
  // parted from the field by a hairline.
  composerAttachment: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: space[2.5],
      paddingLeft: space[2.5],
      paddingRight: space[1.5],
      paddingTop: space[2.5],
      paddingBottom: space[2],
      borderBottomWidth: StyleSheet.hairlineWidth,
      borderBottomColor: colors.line,
    },
    { gap: space[2], paddingLeft: space[2], paddingRight: space[1], paddingTop: space[2], paddingBottom: space[1.5] },
  ),
  composerAttachmentThumb: {
    width: sizes.avatar.lg,
    height: sizes.avatar.lg,
    borderRadius: radius.sm,
    backgroundColor: colors.surface,
  },
  composerAttachmentTile: {
    width: sizes.avatar.lg,
    height: sizes.avatar.lg,
    borderRadius: radius.sm,
    backgroundColor: colors.accentSoft,
    alignItems: "center",
    justifyContent: "center",
  },
  composerAttachmentText: { flex: 1, gap: space[0.5] },
  // The message being answered: a quiet pane set into the top of the shell,
  // its corner concentric with the capsule's, quoting as a bubble will.
  composerReply: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: composerReplyInset,
    marginHorizontal: composerReplyInset,
    borderRadius: composerRadius - composerReplyInset,
    backgroundColor: colors.highlight,
  },
  // The bar stands clear of the pane's curve, so the curve never clips it.
  composerReplyBar: {
    width: 3,
    alignSelf: "stretch",
    marginVertical: isDesktop ? space[1.5] : space[2],
    marginLeft: isDesktop ? space[2] : space[2.5],
    borderRadius: radius.pill,
  },
  composerReplyText: {
    flex: 1,
    paddingVertical: isDesktop ? space[1] : space[1.5],
    paddingLeft: space[2],
    paddingRight: space[1],
  },
  composerReplyClose: {
    width: isDesktop ? sizes.tile.sm : sizes.tile.md,
    height: isDesktop ? sizes.tile.sm : sizes.tile.md,
    marginRight: isDesktop ? space[1] : space[1.5],
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  composerAttachmentName: { ...type.label, color: colors.text },
  composerAttachmentMeta: type.caption,

  bubble: desk(
    {
      maxWidth: "78%",
      borderRadius: radius["3xl"],
      paddingHorizontal: space[3.5],
      paddingTop: space[2],
      paddingBottom: space[1.5],
      marginTop: space[0.5],
    },
    {
      maxWidth: "70%",
      borderRadius: radius.xl,
      paddingHorizontal: space[3],
      paddingTop: space[1.5],
      paddingBottom: space[1],
    },
  ),
  bubbleSpaced: { marginTop: isDesktop ? space[2] : space[2.5] },
  bubbleSent: { alignSelf: "flex-end", backgroundColor: colors.accentDeep },
  bubbleReceived: { alignSelf: "flex-start", backgroundColor: colors.raised },
  bubbleTailSent: { borderBottomRightRadius: isDesktop ? space[1] : space[1.5] },
  bubbleTailReceived: { borderBottomLeftRadius: isDesktop ? space[1] : space[1.5] },
  // In a group the row spaces the runs, and the gutter takes some of the
  // width a lone bubble could have had.
  bubbleInGroup: { flexShrink: 1, maxWidth: isDesktop ? "70%" : "82%", marginTop: 0 },
  bubbleRow: { flexDirection: "row", alignItems: "flex-end", gap: space[2] },
  bubbleRowSent: { flexDirection: "row-reverse" },
  bubbleRowSpaced: { marginTop: isDesktop ? space[2] : space[2.5] },
  bubbleRowTight: { marginTop: space[0.5] },
  bubbleGutter: { width: sizes.avatar.xs },
  bubbleSender: { ...type.label, fontFamily: fonts.semibold, marginBottom: space[0.5] },
  bubbleBody: { ...type.body, color: colors.text },
  // A sent bubble is the accent in either scheme, so its words stay white.
  bubbleBodySent: { color: colors.onAccent },
  bubbleMeta: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "flex-end",
    gap: space[1],
    marginTop: space[0.5],
  },
  bubbleTime: { ...type.micro, fontVariant: ["tabular-nums"] },
  bubbleRead: { backgroundColor: colors.onAccent, borderRadius: radius.pill, paddingHorizontal: space[0.5] },
  // The desktop's react and reply controls: a capsule beside the bubble, on
  // the side facing the thread's centre, shown while the pointer rests on the
  // bubble. Its box abuts the bubble so moving onto it keeps the bubble
  // hovered. A phone has no such controls; a long press opens the menu.
  reactAside: {
    position: "absolute",
    top: "50%",
    marginTop: -control.xs / 2,
    width: 2 * control.xs + space[1.5],
    height: control.xs,
    justifyContent: "center",
  },
  reactAsideReceived: { right: -(2 * control.xs + space[1.5]), alignItems: "flex-end" },
  reactAsideSent: { left: -(2 * control.xs + space[1.5]), alignItems: "flex-start" },
  reactAsideCapsule: { flexDirection: "row", borderRadius: radius.pill, backgroundColor: colors.elevated },
  reactAsideDisc: {
    width: control.xs,
    height: control.xs,
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  replySwipeGlyph: {
    position: "absolute",
    left: 0,
    top: "50%",
    marginTop: -replySwipeGlyph / 2,
    width: replySwipeGlyph,
    height: replySwipeGlyph,
    borderRadius: radius.pill,
    backgroundColor: colors.elevated,
    alignItems: "center",
    justifyContent: "center",
  },
  // The same disc over itself, with the glyph in the accent.
  replySwipeArmed: { top: 0, marginTop: 0 },
  // The menu's panes float over the thread: the emoji bar is a capsule, the
  // actions under it a short card on the bubble's side.
  messageMenu: { position: "absolute", gap: space[2] },
  messageMenuPane: {
    backgroundColor: colors.thumb,
    borderWidth: 1,
    borderColor: colors.lineStrong,
    ...elevation.raised,
  },
  messageMenuBar: { flexDirection: "row", padding: menuPadding - 1, borderRadius: radius.pill },
  messageMenuEmoji: { borderRadius: radius.pill, alignItems: "center", justifyContent: "center" },
  messageMenuActions: {
    minWidth: isDesktop ? 168 : 200,
    padding: space[1] - 1,
    borderRadius: isDesktop ? radius.md : radius.xl,
    overflow: "hidden",
  },
  messageMenuRow: {
    height: menuRowHeight,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: space[4],
    paddingHorizontal: isDesktop ? space[2.5] : space[3.5],
    borderRadius: isDesktop ? radius.xs : radius.md,
    overflow: "hidden",
  },
  messageMenuLabel: { ...type.bodyStrong, fontFamily: fonts.regular },
  // The message a reply answers: a pane set into the bubble, as wide as a
  // file card, with a bar and a name in the quoted sender's colour.
  bubbleQuote: {
    flexDirection: "row",
    borderRadius: isDesktop ? radius.xs : radius.sm,
    overflow: "hidden",
    marginTop: space[0.5],
    marginBottom: space[1],
  },
  bubbleQuoteOutset: { marginHorizontal: isDesktop ? -space[1.5] : -space[2] },
  bubbleQuoteBar: { width: 3 },
  bubbleQuoteText: { flexShrink: 1, paddingVertical: space[1], paddingLeft: space[2], paddingRight: space[2.5] },
  bubbleQuoteName: { ...type.label, fontFamily: fonts.semibold },
  bubbleQuoteBody: type.footnote,
  bubbleFlash: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    borderRadius: isDesktop ? radius.xl : radius["3xl"],
  },
  // White lifts the accent of a sent bubble; the accent tints a plain one,
  // where white would vanish in the light scheme.
  bubbleFlashSent: { backgroundColor: withAlpha(colors.white, 0.24) },
  bubbleFlashReceived: { backgroundColor: withAlpha(colors.accent, 0.26) },
  // The pill hangs from the bubble's bottom edge on the tail's side, as in
  // other chat apps. A reacted bubble keeps its time clear of the overlap and
  // leaves room below for the part that hangs. A ring in the canvas colour
  // cuts the pill out of the bubble; the ring turns accent when you are in it.
  bubbleReacted: { paddingBottom: (isDesktop ? space[1] : space[1.5]) + space[1] },
  bubbleReactedSpace: { marginBottom: reactionHang + space[0.5] },
  reactionPill: {
    position: "absolute",
    bottom: -reactionHang,
    flexDirection: "row",
    alignItems: "center",
    gap: space[0.5],
    height: reactionPillHeight,
    paddingHorizontal: space[1.5],
    borderRadius: radius.pill,
    borderWidth: 1.5,
    borderColor: colors.canvas,
    backgroundColor: colors.thumb,
    ...elevation.thumb,
  },
  reactionPillReceived: { left: space[2] },
  reactionPillSent: { right: space[2] },
  reactionPillMine: { borderColor: colors.accent },
  reactionPillEmoji: { fontSize: isDesktop ? 13 : 14, lineHeight: isDesktop ? 16 : 18, includeFontPadding: false },
  reactionPillCount: {
    ...type.caption,
    color: colors.text2,
    fontFamily: fonts.semibold,
    fontVariant: ["tabular-nums"],
    marginLeft: space[0.5],
  },
  // The sheet: the message's words, a bar of emojis to pick from, and who has
  // reacted with what. The title leaves room for the close disc.
  reactionSheet: { paddingHorizontal: space[5], gap: space[2] },
  reactionSheetTitle: { paddingRight: control.sm },
  reactionBar: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: space[1],
    marginTop: space[2],
    paddingBottom: space[2],
  },
  reactionChoice: {
    width: isDesktop ? sizes.well.xs : sizes.well.sm,
    height: isDesktop ? sizes.well.xs : sizes.well.sm,
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  reactionChoiceSelected: { backgroundColor: colors.accentSoft },
  reactionChoiceEmoji: { fontSize: isDesktop ? 22 : 26, lineHeight: isDesktop ? 28 : 32, includeFontPadding: false },
  reactionList: { flexGrow: 0 },
  reactionListContent: { paddingHorizontal: space[2] },
  reactionRowEmoji: { fontSize: isDesktop ? 18 : 22, lineHeight: isDesktop ? 24 : 28, includeFontPadding: false },
  // A picture fills the bubble to a thin frame; the corner inside is the
  // bubble's less that frame, so the curves stay concentric. The words
  // above and below it take the inset the frame gave up.
  bubbleFramed: { paddingHorizontal: space[1], paddingTop: space[1] },
  bubbleCaption: { paddingHorizontal: (isDesktop ? space[3] : space[3.5]) - space[1] },
  bubbleCaptionAbove: { paddingTop: (isDesktop ? space[1.5] : space[2]) - space[1], paddingBottom: space[1] },
  attachmentViewer: { width: "100%", maxWidth: 1100, height: "90%", maxHeight: "95%", paddingHorizontal: space[4] },
  attachmentViewerTitle: { ...type.label, color: colors.text, paddingRight: control.lg * 2 },
  attachmentViewerImage: { flex: 1, width: "100%", minHeight: 0, marginVertical: space[3] },
  attachmentViewerDownload: { position: "absolute", top: space[3], right: space[3] + (isDesktop ? control.xs : control.sm) + space[2] },
  bubblePictureWrap: { borderRadius: isDesktop ? radius.xl - space[1] : radius["3xl"] - space[1], overflow: "hidden" },
  bubblePicture: {
    width: isDesktop ? 300 : 240,
    maxWidth: "100%",
    borderRadius: isDesktop ? radius.xl - space[1] : radius["3xl"] - space[1],
    backgroundColor: colors.surface,
  },
  // A file in a bubble: a tile for its kind, its name, and what a tap does.
  bubbleFile: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[2.5],
    borderRadius: isDesktop ? radius.sm : radius.md,
    paddingVertical: space[1.5],
    paddingLeft: space[1.5],
    paddingRight: space[2.5],
    marginTop: space[0.5],
    marginBottom: space[1],
    marginLeft: isDesktop ? -space[1.5] : -space[2],
    marginRight: isDesktop ? -space[1.5] : -space[2],
    minWidth: isDesktop ? 200 : 210,
  },
  bubbleFileSent: { backgroundColor: withAlpha(colors.black, 0.12) },
  bubbleFileReceived: { backgroundColor: colors.surface },
  bubbleFileTile: {
    width: sizes.well.xs,
    height: sizes.well.xs,
    borderRadius: radius.xs,
    alignItems: "center",
    justifyContent: "center",
  },
  bubbleFileTileSent: { backgroundColor: withAlpha(colors.black, 0.14) },
  bubbleFileTileReceived: { backgroundColor: colors.accentSoft },
  bubbleFileText: { flex: 1, gap: space[0.5] },
  bubbleFileName: { ...type.bodyStrong, color: colors.text },
  bubbleFileMeta: type.caption,
  dayDivider: { alignItems: "center", marginVertical: isDesktop ? space[3] : space[3.5] },
  dayChip: {
    borderRadius: radius.pill,
    paddingHorizontal: space[2.5],
    paddingVertical: space[1],
    backgroundColor: colors.surface,
  },
  dayChipText: { ...type.caption, color: colors.text2 },

  chip: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[1.5],
    minHeight: control.xl,
    borderRadius: radius.pill,
    paddingHorizontal: space[4],
    justifyContent: "center",
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.lineStrong,
  },
  // Overshoots the hairline by a pixel so the fill swallows the border too.
  chipFill: {
    position: "absolute",
    top: -1,
    left: -1,
    right: -1,
    bottom: -1,
    borderRadius: radius.pill,
    backgroundColor: colors.accent,
  },
  chipText: { ...type.subhead, ...singleLine, fontFamily: fonts.medium, color: colors.text },
  chipTextSelected: { color: colors.onAccent },

  // The sidebar's rows are capsules: the inset above and below the avatar is
  // the one that leads it, so the open row's fill rings the round avatar with
  // an even margin. Rows hold the border unselected for layout, not for show.
  conversation: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: conversationRow.gap,
      paddingLeft: conversationRow.inset,
      paddingRight: conversationRow.trail,
      paddingVertical: space[2.5],
      borderRadius: radius["2xl"],
    },
    {
      paddingVertical: conversationRow.inset,
      borderRadius: radius.pill,
      borderWidth: 1,
      borderColor: "transparent",
    },
  ),
  conversationSelected: { backgroundColor: colors.accentSoft, borderColor: colors.accentLine },
  conversationBody: { flex: 1, gap: isDesktop ? 0 : space[0.5] },
  conversationLine: { flexDirection: "row", alignItems: "center", gap: space[1] },
  conversationName: desk({ flexShrink: 1, fontFamily: fonts.medium }, { fontSize: type.body.fontSize }),
  conversationTime: { ...type.footnote, color: colors.text3, fontVariant: ["tabular-nums"] },
  conversationPreview: type.subhead,
  unreadName: { fontFamily: fonts.bold },
  unreadPreview: { color: colors.text, fontFamily: fonts.medium },
  unreadTime: { color: colors.accent, fontFamily: fonts.semibold },
  unreadBadge: {
    minWidth: sizes.badge.lg,
    height: sizes.badge.lg,
    paddingHorizontal: space[1.5],
    borderRadius: radius.pill,
    backgroundColor: colors.accent,
    alignItems: "center",
    justifyContent: "center",
  },
  unreadBadgeText: { ...type.micro, color: colors.onAccent, fontFamily: fonts.bold, fontVariant: ["tabular-nums"] },
  tabBadge: { position: "absolute", top: -space[1.5], left: sizes.icon.lg - space[1] },
  // The separator starts where a row's text does, past its avatar.
  listSeparator: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.lineStrong,
    marginLeft: conversationRow.inset + conversationRow.avatar + conversationRow.gap,
    marginRight: space[2.5],
  },

  requestGroup: desk(
    {
      borderRadius: radius["4xl"],
      backgroundColor: withAlpha(colors.accent, 0.07),
      borderWidth: 1,
      borderColor: withAlpha(colors.accent, 0.22),
      marginBottom: space[2],
      overflow: "hidden",
    },
    { borderRadius: radius.md },
  ),
  requestHeader: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: space[2],
      paddingHorizontal: space[4],
      paddingTop: space[3],
      paddingBottom: space[0.5],
    },
    { gap: space[1.5], paddingHorizontal: space[3], paddingTop: space[2.5] },
  ),
  requestTitle: { ...type.sectionTitle, fontFamily: fonts.semibold, color: colors.accent },
  requestCount: desk(
    {
      minWidth: sizes.badge.lg,
      height: sizes.badge.lg,
      borderRadius: radius.pill,
      paddingHorizontal: space[1.5],
      backgroundColor: colors.accent,
      alignItems: "center",
      justifyContent: "center",
    },
    { minWidth: sizes.badge.md, height: sizes.badge.md, paddingHorizontal: space[1] },
  ),
  requestCountText: {
    ...type.micro,
    fontFamily: fonts.bold,
    color: colors.onAccent,
    fontVariant: ["tabular-nums"],
  },
  requestRow: desk(
    {
      flexDirection: "row",
      alignItems: "center",
      gap: requestRowMetrics.gap,
      paddingHorizontal: requestRowMetrics.inset,
      paddingVertical: space[2.5],
    },
    { gap: requestRowMetrics.gap, paddingHorizontal: requestRowMetrics.inset, paddingVertical: space[2] },
  ),
  requestAvatar: {
    padding: requestRowMetrics.ring,
    borderRadius: radius.pill,
    borderWidth: requestRowMetrics.ring,
    borderColor: colors.accent,
  },
  requestPreview: { ...type.subhead, fontFamily: fonts.medium, color: colors.text },
  requestDivider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: withAlpha(colors.accent, 0.25),
    marginLeft:
      requestRowMetrics.inset +
      requestRowMetrics.avatar +
      4 * requestRowMetrics.ring +
      requestRowMetrics.gap,
    marginRight: space[3],
  },

  segmented: {
    flexDirection: "row",
    padding: segmentPadding,
    height: chrome.sidebarControl,
    borderRadius: radius.pill,
  },
  segmentedSurface: {
    backgroundColor: colors.raised,
    borderWidth: 1,
    borderColor: colors.line,
  },
  // The thumb stands proud of the track, inset by the track's padding and border.
  segmentThumb: {
    position: "absolute",
    top: segmentPadding,
    left: segmentPadding,
    width: segmentWidth,
    height: chrome.sidebarControl - 2 * (segmentPadding + 1),
    borderRadius: radius.pill,
    backgroundColor: colors.thumb,
    ...elevation.thumb,
  },
  // On glass the thumb is drawn in the material's own fill, so it needs no
  // shadow to sit on the pane; the palette decides what that fill is made of.
  segmentThumbGlass: { backgroundColor: colors.glassFill, boxShadow: undefined },
  segment: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: radius.pill,
  },
  segmentDot: {
    height: space[1.5],
    borderRadius: radius.pill,
    backgroundColor: colors.accent,
  },

  accountBar: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[2.5],
    paddingLeft: space[3.5],
    paddingRight: space[2],
    paddingVertical: space[2],
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.line,
  },
  accountName: { ...type.label, color: colors.text },

  // Keep the card vertically centred beside its copy on desktop.
  qrCard: desk(
    {
      alignSelf: "center",
      alignItems: "center",
      backgroundColor: colors.paper,
      borderRadius: radius["4xl"],
      padding: space[5],
      gap: space[4],
      ...elevation.raised,
    },
    { borderRadius: radius.xl, gap: space[3] },
  ),
  qrDots: { flexDirection: "row", gap: space[1], marginBottom: space[2] },
  qrDot: { height: space[1.5], borderRadius: radius.pill },
  qrCaption: { ...type.label, color: colors.inkFaint, fontVariant: ["tabular-nums"] },
  // On desktop the text form scrolls within the height of the code beside it.
  qrText: desk({ width: qrSize }, { maxHeight: type.monoSmall.lineHeight * 11 }),
  qrTextValue: { ...type.monoSmall, color: colors.inkSoft, textAlign: "left" },

  // Over a live camera feed, whatever the scheme.
  mask: { flex: 1, backgroundColor: withAlpha(colors.black, 0.6) },
  maskBottom: { alignItems: "center", paddingTop: space[7] },
  reticleRow: { flexDirection: "row", height: reticleSize },
  reticle: { width: reticleSize, height: reticleSize },
  corner: {
    position: "absolute",
    width: reticleCorner.size,
    height: reticleCorner.size,
    borderColor: colors.white,
  },
  cornerTopLeft: {
    top: 0,
    left: 0,
    borderTopWidth: reticleCorner.stroke,
    borderLeftWidth: reticleCorner.stroke,
    borderTopLeftRadius: reticleCorner.radius,
  },
  cornerTopRight: {
    top: 0,
    right: 0,
    borderTopWidth: reticleCorner.stroke,
    borderRightWidth: reticleCorner.stroke,
    borderTopRightRadius: reticleCorner.radius,
  },
  cornerBottomLeft: {
    bottom: 0,
    left: 0,
    borderBottomWidth: reticleCorner.stroke,
    borderLeftWidth: reticleCorner.stroke,
    borderBottomLeftRadius: reticleCorner.radius,
  },
  cornerBottomRight: {
    bottom: 0,
    right: 0,
    borderBottomWidth: reticleCorner.stroke,
    borderRightWidth: reticleCorner.stroke,
    borderBottomRightRadius: reticleCorner.radius,
  },
  // The scan line stops short of the corners' curves.
  sweep: {
    position: "absolute",
    top: 0,
    left: reticleCorner.radius - reticleCorner.stroke,
    right: reticleCorner.radius - reticleCorner.stroke,
    height: space[0.5],
    borderRadius: radius.pill,
    backgroundColor: colors.accent,
    shadowColor: colors.accent,
    shadowOpacity: 0.9,
    shadowRadius: space[2],
    shadowOffset: { width: 0, height: 0 },
  },
  reticleHint: {
    borderRadius: radius.pill,
    paddingHorizontal: space[4],
    paddingVertical: space[2.5],
  },
  reticleHintSurface: { backgroundColor: withAlpha(colors.surface, 0.9) },
  reticleHintText: { ...type.subhead, fontFamily: fonts.medium, color: colors.text },

  statusLane: { overflow: "hidden" },
  statusPillWrap: {
    position: "absolute",
    left: space[4],
    right: space[4],
    alignItems: "center",
  },
  statusPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[2.5],
    maxWidth: "100%",
    borderRadius: radius.pill,
    paddingLeft: space[3.5],
    paddingRight: space[3.5],
    paddingVertical: space[2.5],
  },
  // The pill has a lane of its own, so it is never lifted over content (and
  // the lane would clip a shadow).
  statusPillSurface: {
    backgroundColor: colors.thumb,
    borderWidth: 1,
    borderColor: colors.lineStrong,
  },
  statusPillError: {
    backgroundColor: colors.dangerSurface,
    borderColor: withAlpha(colors.danger, 0.32),
    paddingRight: space[3],
  },
  statusPillErrorGlass: { paddingRight: space[3] },
  statusContentRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[2.5],
    flexShrink: 1,
  },
  statusContent: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[2.5],
    flexShrink: 1,
  },
  statusText: { ...type.subhead, flexShrink: 1, fontFamily: fonts.medium, color: colors.text },

  tabBarWrap: {
    position: "absolute",
    left: 0,
    right: 0,
    bottom: 0,
    paddingHorizontal: screenInset,
    paddingTop: space[2.5],
  },
  // Sized to its icon-only tabs, the end circles concentric with its ends.
  tabPill: {
    flexDirection: "row",
    alignSelf: "center",
    gap: tabGap,
    padding: tabPillPadding,
    borderRadius: radius.pill,
  },
  // Where there is no glass, floating chrome is the lifted thumb pane: white
  // over light content, as glass reads there, rather than a grey slab.
  tabPillSurface: {
    backgroundColor: colors.thumb,
    borderWidth: 1,
    borderColor: colors.line,
    ...elevation.raised,
  },
  tabIndicatorGlass: { backgroundColor: colors.glassFill },
  tabIndicator: {
    position: "absolute",
    top: tabPillPadding,
    left: tabPillPadding,
    width: tabHeight,
    height: tabHeight,
    borderRadius: radius.pill,
    backgroundColor: colors.accentSoft,
  },
  tabItem: {
    width: tabHeight,
    height: tabHeight,
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  tabItemPressed: { backgroundColor: colors.highlight },

  feature: { flexDirection: "row", alignItems: "center", gap: space[4] },
  featureIcon: {
    width: sizes.well.sm,
    height: sizes.well.sm,
    borderRadius: radius.pill,
    backgroundColor: colors.accentSoft,
    alignItems: "center",
    justifyContent: "center",
  },

  keyValue: { gap: space[1] },
  // On desktop the code sits in a recessed well so it reads as one object to
  // compare, like the safety number, rather than as oversized prose.
  code: desk(
    { ...type.code, textAlign: "center" },
    {
      textAlign: "left",
      paddingHorizontal: space[3.5],
      paddingVertical: space[2],
      borderRadius: radius.xs,
      borderWidth: 1,
      borderColor: colors.line,
      backgroundColor: colors.surface,
    },
  ),
  codeBlock: desk({ alignItems: "center", gap: space[2] }, { alignItems: "flex-start" }),
  actions: desk(
    { gap: space[3] },
    { flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: space[2] },
  ),
  qrSpread: { flexGrow: 1, flexDirection: "row", alignItems: "center", gap: space[10] },
  qrSpreadText: { flex: 1, minWidth: 240, gap: space[6] },
  }),
);
