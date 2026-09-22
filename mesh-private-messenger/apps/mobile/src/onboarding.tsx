// What only onboarding draws: the conversation that opens on the welcome
// screen, the facts beside it, and the numbered steps of linking a device.

import { useEffect, useState, type ReactNode } from "react";
import { AccessibilityInfo, Animated, StyleSheet, Text, View } from "react-native";

import { formatClock } from "./format";
import { fonts, isDesktop, motion, radius, size as sizes, space, themed, useTheme, withAlpha } from "./theme";
import { Glow, Icon, type IconName } from "./ui";

// Null until the setting has been read, so nothing starts moving early.
function useReducedMotion(): boolean | null {
  const [reduced, setReduced] = useState<boolean | null>(null);
  useEffect(() => {
    let active = true;
    void AccessibilityInfo.isReduceMotionEnabled().then(
      (value) => { if (active) setReduced(value); },
      () => { if (active) setReduced(true); },
    );
    const subscription = AccessibilityInfo.addEventListener("reduceMotionChanged", setReduced);
    return () => {
      active = false;
      subscription.remove();
    };
  }, []);
  return reduced;
}

// The landing page's conversation, drawn the way a thread draws it. The other
// side's messages land sealed and open into words, as they do on arrival;
// your own reply was never sealed to you. `at` is when each one lands.
const thread = [
  { sent: false, text: "Dinner on Friday?", minute: 31, at: 250 },
  { sent: true, text: "Yes! I’ll book the place by the river.", minute: 32, at: 1250 },
  { sent: false, text: "Perfect. See you at 7.", minute: 33, at: 2050 },
] as const;
// A sealed message rests a beat before it opens, then opens left to right.
const openAfter = 420;
const openFor = 720;

// Seeded noise in the rhythm of Morse code, one group per word, so a sealed
// message keeps the shape of its words without spelling any of them.
function Noise({ text, color }: { text: string; color: string }) {
  const styles = useStyles();
  return (
    <View style={styles.noise}>
      {text.split(" ").map((word, index) => (
        <View key={index} style={styles.noiseWord}>
          {Array.from({ length: Math.max(1, Math.round(word.length * 0.75)) }, (_, at) => (
            <View
              key={at}
              style={[
                styles.symbol,
                (word.charCodeAt(at % word.length) + at * 7) % 3 === 0 && styles.dash,
                { backgroundColor: color },
              ]}
            />
          ))}
        </View>
      ))}
    </View>
  );
}

function ArtBubble({ sent, text, minute, at, still }: {
  sent: boolean;
  text: string;
  minute: number;
  at: number;
  still: boolean;
}) {
  const { colors } = useTheme();
  const styles = useStyles();
  const [landed] = useState(() => new Animated.Value(still ? 1 : 0));
  const [opened] = useState(() => new Animated.Value(still || sent ? 1 : 0));
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (still) return;
    const animation = Animated.parallel([
      Animated.timing(landed, { toValue: 1, delay: at, duration: motion.enter, easing: motion.easeOut, useNativeDriver: false }),
      Animated.timing(opened, { toValue: 1, delay: at + openAfter, duration: openFor, easing: motion.easeInOut, useNativeDriver: false }),
    ]);
    animation.start();
    return () => animation.stop();
  }, [at, landed, opened, still]);
  // The words show from the left edge up to the wipe and the noise from the
  // wipe on; each layer's clip moves while what it holds stays put.
  const wipe = Animated.multiply(opened, width);
  const metaColor = sent ? colors.onAccentMuted : colors.text3;
  return (
    <Animated.View
      style={[
        styles.bubble,
        sent ? styles.sent : styles.received,
        {
          opacity: landed,
          transform: [
            { translateY: landed.interpolate({ inputRange: [0, 1], outputRange: [space[3], 0] }) },
            { scale: landed.interpolate({ inputRange: [0, 1], outputRange: [0.96, 1] }) },
          ],
        },
      ]}
    >
      <View onLayout={(event) => setWidth(event.nativeEvent.layout.width)}>
        <Animated.View style={[styles.clip, { transform: [{ translateX: Animated.subtract(wipe, width) }] }]}>
          <Animated.View style={{ transform: [{ translateX: Animated.subtract(width, wipe) }] }}>
            <Text style={[styles.body, sent && styles.bodySent]}>{text}</Text>
          </Animated.View>
        </Animated.View>
        {sent ? null : (
          <Animated.View style={[StyleSheet.absoluteFill, styles.clip, { transform: [{ translateX: wipe }] }]}>
            <Animated.View style={{ transform: [{ translateX: Animated.multiply(wipe, -1) }] }}>
              <Noise text={text} color={withAlpha(colors.text, 0.32)} />
            </Animated.View>
          </Animated.View>
        )}
      </View>
      <View style={styles.meta}>
        <Text style={[styles.time, { color: metaColor }]}>{formatClock(new Date().setHours(9, minute, 0, 0))}</Text>
        {sent ? <Icon name="checks" size={sizes.icon.xs} color={metaColor} strokeWidth={2.4} /> : null}
      </View>
    </Animated.View>
  );
}

// The welcome screen's picture: a short exchange whose incoming messages
// arrive as noise and open into words, over the accent's glow. It is only
// decoration, so it drops out of the accessibility tree, and it steps aside
// entirely where the screen is too short to hold it.
export function SealedChat() {
  const styles = useStyles();
  const still = useReducedMotion();
  const [room, setRoom] = useState(0);
  const [need, setNeed] = useState(0);
  return (
    <View
      aria-hidden
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
      pointerEvents="none"
      style={styles.art}
      onLayout={(event) => setRoom(event.nativeEvent.layout.height)}
    >
      <Glow size={glowSize} style={styles.glow} />
      {still === null ? null : (
        <View
          style={[styles.thread, need + 2 * artPadding > room && styles.hidden]}
          onLayout={(event) => setNeed(event.nativeEvent.layout.height)}
        >
          {thread.map((message) => (
            <ArtBubble key={message.minute} {...message} still={still} />
          ))}
        </View>
      )}
    </View>
  );
}

// One thing worth knowing before signing up, in a line.
export function Fact({ icon, children }: { icon: IconName; children: string }) {
  const { colors } = useTheme();
  const styles = useStyles();
  return (
    <View style={styles.fact}>
      <Icon name={icon} size={isDesktop ? sizes.icon.md : sizes.icon.lg} color={colors.accent} strokeWidth={2.1} />
      <Text style={styles.factText}>{children}</Text>
    </View>
  );
}

// Instructions carried out across two devices, numbered so each screen can
// point at the step it is on.
export function Steps({ children }: { children: ReactNode[] }) {
  const styles = useStyles();
  return (
    <View style={styles.steps}>
      {children.map((step, index) => (
        <View key={index} style={styles.step}>
          <View style={styles.stepNumber}>
            <Text style={styles.stepDigit}>{index + 1}</Text>
          </View>
          <Text style={styles.stepText}>{step}</Text>
        </View>
      ))}
    </View>
  );
}

// A control's or place's name inside a step.
export function Strong({ children }: { children: ReactNode }) {
  const styles = useStyles();
  return <Text style={styles.strong}>{children}</Text>;
}

const glowSize = isDesktop ? 520 : 440;
// The space kept clear above and below the thread on a phone.
const artPadding = isDesktop ? 0 : space[4];
const stepNumber = isDesktop ? space[5] : space[6];

const useStyles = themed(({ colors, type }) =>
  StyleSheet.create({
    // A phone gives the picture whatever height the words leave; the desktop
    // sets it beside them as a column of its own.
    art: isDesktop
      ? { flexGrow: 1, flexBasis: 0, maxWidth: 360, alignSelf: "stretch", justifyContent: "center" }
      : { flexGrow: 1, flexBasis: 0, justifyContent: "center", paddingVertical: artPadding },
    glow: { top: "50%", marginTop: -glowSize / 2 },
    thread: { width: "100%", maxWidth: 400, alignSelf: "center", gap: isDesktop ? space[2] : space[2.5] },
    hidden: { opacity: 0 },
    // The thread's own bubble, at rest: the same corners, padding and fills.
    bubble: isDesktop
      ? { maxWidth: "82%", borderRadius: radius.xl, paddingHorizontal: space[3], paddingTop: space[1.5], paddingBottom: space[1] }
      : { maxWidth: "82%", borderRadius: radius["3xl"], paddingHorizontal: space[3.5], paddingTop: space[2], paddingBottom: space[1.5] },
    sent: {
      alignSelf: "flex-end",
      backgroundColor: colors.accentDeep,
      borderBottomRightRadius: isDesktop ? space[1] : space[1.5],
    },
    received: {
      alignSelf: "flex-start",
      backgroundColor: colors.raised,
      borderBottomLeftRadius: isDesktop ? space[1] : space[1.5],
    },
    clip: { overflow: "hidden" },
    body: { ...type.body, color: colors.text },
    bodySent: { color: colors.onAccent },
    meta: { flexDirection: "row", alignItems: "center", justifyContent: "flex-end", gap: space[1], marginTop: space[0.5] },
    time: { ...type.micro, fontVariant: ["tabular-nums"] },
    noise: { flexDirection: "row", flexWrap: "wrap", columnGap: space[2] },
    noiseWord: { height: type.body.lineHeight, flexDirection: "row", alignItems: "center", gap: space[1] - 1 },
    symbol: { width: space[1], height: space[1], borderRadius: space[0.5] },
    dash: { width: space[3] },
    fact: { flexDirection: "row", alignItems: "center", gap: space[3] },
    factText: { ...type.subhead, color: colors.text, flexShrink: 1 },
    steps: { gap: isDesktop ? space[3] : space[4] },
    step: { flexDirection: "row", alignItems: "flex-start", gap: space[3] },
    // The disc sits on the first line of its step, however many lines follow.
    stepNumber: {
      width: stepNumber,
      height: stepNumber,
      marginTop: (type.body.lineHeight - stepNumber) / 2,
      borderRadius: radius.pill,
      backgroundColor: colors.accentSoft,
      alignItems: "center",
      justifyContent: "center",
    },
    stepDigit: { ...type.caption, fontFamily: fonts.semibold, color: colors.accent },
    stepText: { ...type.body, flex: 1 },
    strong: { fontFamily: fonts.medium, color: colors.text },
  }),
);
