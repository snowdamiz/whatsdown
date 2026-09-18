import { Children, Fragment, useEffect, useState, type ReactNode } from "react";
import {
  ActivityIndicator,
  Animated,
  Easing,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type AccessibilityRole,
  type AccessibilityState,
  type StyleProp,
  type ViewStyle,
} from "react-native";
import QRCode from "react-native-qrcode-svg";
import { SafeAreaView } from "react-native-safe-area-context";
import Svg, { Circle, Defs, LinearGradient, Path, Rect, Stop } from "react-native-svg";

import { formatClock } from "./format";
import { qrFrames } from "./qr";
import { avatarTone, colors, fonts, radius, shadow, type } from "./theme";

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
  close: "m6.5 6.5 11 11M17.5 6.5l-11 11",
  shield:
    "M12 3.5 4.5 6.5v5.2c0 4.3 3.2 7.4 7.5 8.8 4.3-1.4 7.5-4.5 7.5-8.8V6.5L12 3.5ZM8.8 12.2l2.2 2.2 4.4-4.6",
  clock: "M12 7.5V12l3 2M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0Z",
  info: "M12 11v5.5M12 7.8h.01M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0Z",
  search: "m20 20-4.2-4.2M17 10.5a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0Z",
  warning: "M12 4.5 2.8 19.5h18.4L12 4.5ZM12 10v4.5M12 17.5h.01",
  link: "m10.5 13.5 3-3M8.5 15.5l-1.2 1.2a3.2 3.2 0 0 1-4.5-4.5l3-3a3.2 3.2 0 0 1 4.5 0M15.5 8.5l1.2-1.2a3.2 3.2 0 0 1 4.5 4.5l-3 3a3.2 3.2 0 0 1-4.5 0",
  camera:
    "M4 8.5A1.5 1.5 0 0 1 5.5 7H8l1.5-2h5L16 7h2.5A1.5 1.5 0 0 1 20 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 17.5v-9ZM15 12.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z",
  block: "M20.5 12a8.5 8.5 0 1 1-17 0 8.5 8.5 0 0 1 17 0ZM6 6l12 12",
  timer: "M12 8v4.5l2.8 1.7M9.5 3h5M12 21a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z",
  key: "M14.5 9.5 21 3M18.5 5.5 21 8M9 21a6 6 0 1 0 0-12 6 6 0 0 0 0 12Zm0-8.5v.01",
};
export type IconName = keyof typeof paths | "qr";

export function Icon({
  name,
  size = 22,
  color = colors.text,
  strokeWidth = 2,
}: {
  name: IconName;
  size?: number;
  color?: string;
  strokeWidth?: number;
}) {
  return (
    <Svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
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
}: {
  children: ReactNode;
  onPress: () => void;
  label?: string;
  role?: AccessibilityRole;
  state?: AccessibilityState;
  disabled?: boolean;
  accessible?: boolean;
  testID?: string;
  style?: StyleProp<ViewStyle>;
  containerStyle?: StyleProp<ViewStyle>;
  hitSlop?: number;
  scaleTo?: number;
}) {
  const [scale] = useState(() => new Animated.Value(1));
  const animate = (toValue: number) =>
    Animated.spring(scale, {
      toValue,
      useNativeDriver: true,
      speed: 50,
      bounciness: 2,
    }).start();
  return (
    <Pressable
      accessibilityRole={accessible === false ? undefined : role}
      accessibilityLabel={accessible === false ? undefined : label}
      accessibilityState={
        accessible === false ? undefined : { ...state, disabled }
      }
      accessible={accessible}
      testID={testID}
      disabled={disabled}
      hitSlop={hitSlop}
      onPress={onPress}
      onPressIn={() => animate(scaleTo)}
      onPressOut={() => animate(1)}
      style={containerStyle}
    >
      {({ pressed }) => (
        <Animated.View
          style={[
            style,
            { transform: [{ scale }] },
            pressed && styles.pressed,
            disabled && styles.disabled,
          ]}
        >
          {children}
        </Animated.View>
      )}
    </Pressable>
  );
}

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
  const [progress] = useState(() => new Animated.Value(0));
  useEffect(() => {
    // JS driver on purpose: native-driven opacity was left at 0 when the
    // keyboard resized the layout mid-animation on screens with autoFocus.
    const animation = Animated.timing(progress, {
      toValue: 1,
      duration: 420,
      delay,
      easing: Easing.out(Easing.cubic),
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
          opacity: progress,
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

export function Button({
  label,
  onPress,
  variant = "primary",
  size = "md",
  icon,
  disabled = false,
  testID,
}: {
  label: string;
  onPress: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "md" | "sm";
  icon?: IconName;
  disabled?: boolean;
  testID?: string;
}) {
  const textColor =
    variant === "primary"
      ? colors.onAccent
      : variant === "danger"
        ? colors.danger
        : variant === "ghost"
          ? colors.accent
          : colors.text;
  return (
    <Tap
      label={label}
      onPress={onPress}
      disabled={disabled}
      testID={testID}
      containerStyle={size === "sm" ? styles.buttonInline : undefined}
      style={[
        styles.button,
        size === "sm" && styles.buttonSmall,
        variant === "primary" && styles.buttonPrimary,
        variant === "secondary" && styles.buttonSecondary,
        variant === "danger" && styles.buttonDanger,
      ]}
    >
      {icon ? <Icon name={icon} size={size === "sm" ? 16 : 18} color={textColor} /> : null}
      <Text
        style={[
          styles.buttonText,
          size === "sm" && styles.buttonTextSmall,
          { color: textColor },
        ]}
      >
        {label}
      </Text>
    </Tap>
  );
}

export function IconButton({
  name,
  label,
  onPress,
  variant = "plain",
  disabled = false,
  size = 42,
  testID,
}: {
  name: IconName;
  label: string;
  onPress: () => void;
  variant?: "plain" | "tonal" | "filled";
  disabled?: boolean;
  size?: number;
  testID?: string;
}) {
  return (
    <Tap
      label={label}
      onPress={onPress}
      disabled={disabled}
      testID={testID}
      scaleTo={0.9}
      containerStyle={{ width: size, height: size }}
      style={[
        styles.iconButton,
        { width: size, height: size },
        variant === "tonal" && styles.iconButtonTonal,
        variant === "filled" && styles.iconButtonFilled,
      ]}
    >
      <Icon
        name={name}
        size={size * 0.5}
        color={variant === "filled" ? colors.onAccent : variant === "plain" ? colors.accent : colors.text}
        strokeWidth={2.1}
      />
    </Tap>
  );
}

export function Header({
  title,
  onBack,
  backLabel = "Back",
  action,
}: {
  title: string;
  onBack?: () => void;
  backLabel?: string;
  action?: ReactNode;
}) {
  return (
    <View style={styles.header}>
      <View style={styles.headerSide}>
        {onBack ? (
          <IconButton name="back" label={backLabel} onPress={onBack} variant="tonal" size={38} />
        ) : null}
      </View>
      <Text accessibilityRole="header" numberOfLines={1} style={styles.headerTitle}>
        {title}
      </Text>
      <View style={[styles.headerSide, styles.headerSideEnd]}>{action}</View>
    </View>
  );
}

export function LargeHeader({
  title,
  actions,
}: {
  title: string;
  actions?: ReactNode;
}) {
  return (
    <View style={styles.largeHeader}>
      <Text accessibilityRole="header" style={[type.largeTitle, layout.flex]}>
        {title}
      </Text>
      {actions ? <View style={styles.headerActions}>{actions}</View> : null}
    </View>
  );
}

export function ChatHeader({
  name,
  group = false,
  status,
  statusIcon,
  statusColor = colors.text2,
  onBack,
  backLabel,
  onInfo,
  infoLabel,
}: {
  name: string;
  group?: boolean;
  status: string;
  statusIcon?: IconName;
  statusColor?: string;
  onBack: () => void;
  backLabel: string;
  onInfo: () => void;
  infoLabel: string;
}) {
  return (
    <View style={styles.chatHeader}>
      <IconButton name="back" label={backLabel} onPress={onBack} size={38} />
      <Avatar name={name} size={38} group={group} />
      <View style={layout.flex}>
        <Text numberOfLines={1} style={type.headline}>
          {group ? name : `@${name}`}
        </Text>
        <View style={styles.statusLine}>
          {statusIcon ? <Icon name={statusIcon} size={12} color={statusColor} /> : null}
          <Text numberOfLines={1} style={[type.caption, { color: statusColor }]}>
            {status}
          </Text>
        </View>
      </View>
      <IconButton name="info" label={infoLabel} onPress={onInfo} size={38} />
    </View>
  );
}

const initials = (name: string): string => {
  const parts = name.split(/[._\-\s]+/).filter(Boolean);
  const letters =
    parts.length >= 2 ? `${parts[0]![0]}${parts[1]![0]}` : name.slice(0, 2);
  return letters.toUpperCase();
};

export function Avatar({
  name,
  size = 48,
  group = false,
}: {
  name: string;
  size?: number;
  group?: boolean;
}) {
  const tone = avatarTone(name);
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

export function AppGlyph({ size = 72 }: { size?: number }) {
  return (
    <View style={{ width: size, height: size }}>
      <Svg width={size} height={size} viewBox="0 0 100 100">
        <Defs>
          <LinearGradient id="glyph" x1="0" y1="0" x2="1" y2="1">
            <Stop offset="0" stopColor="#6AA6FF" />
            <Stop offset="1" stopColor={colors.accentDeep} />
          </LinearGradient>
        </Defs>
        <Rect x={0} y={0} width={100} height={100} rx={26} fill="url(#glyph)" />
      </Svg>
      <View style={styles.avatarOverlay}>
        <Icon name="lock" size={size * 0.5} color={colors.white} strokeWidth={2.3} />
      </View>
    </View>
  );
}

export function Hero({
  name,
  group = false,
  title,
  subtitle,
  badge,
}: {
  name: string;
  group?: boolean;
  title: string;
  subtitle?: string;
  badge?: ReactNode;
}) {
  return (
    <View style={styles.hero}>
      <Avatar name={name} size={92} group={group} />
      <Text style={type.title2}>{title}</Text>
      {subtitle ? <Text style={[type.subhead, layout.centerText]}>{subtitle}</Text> : null}
      {badge}
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
      {icon ? <Icon name={icon} size={12} color={color} strokeWidth={2.4} /> : null}
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
}: {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  placeholder: string;
  multiline?: boolean;
  prefix?: string;
  hint?: string;
  autoFocus?: boolean;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <View style={styles.field}>
      <Text style={type.label}>{label}</Text>
      <View
        style={[
          styles.inputShell,
          multiline && styles.inputShellMultiline,
          focused && styles.inputShellFocused,
        ]}
      >
        {prefix ? <Text style={styles.inputPrefix}>{prefix}</Text> : null}
        <TextInput
          accessibilityLabel={label}
          testID={label}
          autoCapitalize="none"
          autoCorrect={false}
          autoFocus={autoFocus}
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
      </View>
      {hint ? <Text style={type.caption}>{hint}</Text> : null}
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
}: {
  title: string;
  children: ReactNode;
  trailing?: ReactNode;
}) {
  return (
    <View style={styles.section}>
      <View style={styles.sectionHeader}>
        <Text style={type.sectionTitle}>{title}</Text>
        {trailing}
      </View>
      {children}
    </View>
  );
}

export function RowGroup({ children }: { children: ReactNode }) {
  return (
    <Card padded={false}>
      {Children.toArray(children).map((child, index) => (
        <Fragment key={index}>
          {index > 0 ? <View style={styles.rowDivider} /> : null}
          {child}
        </Fragment>
      ))}
    </Card>
  );
}

const tileColors = {
  accent: colors.accent,
  success: colors.success,
  warning: colors.warning,
  danger: colors.danger,
  muted: colors.elevated,
  violet: "#8B5CF6",
  pink: "#EC4899",
  teal: "#14B8A6",
};
export type TileTone = keyof typeof tileColors;

export function Row({
  icon,
  title,
  subtitle,
  onPress,
  trailing,
  tone = "accent",
}: {
  icon: IconName;
  title: string;
  subtitle?: string;
  onPress?: () => void;
  trailing?: ReactNode;
  tone?: TileTone;
}) {
  const content = (
    <>
      <View style={[styles.rowIcon, { backgroundColor: tileColors[tone] }]}>
        <Icon name={icon} size={18} color={colors.white} strokeWidth={2.2} />
      </View>
      <View style={layout.flex}>
        <Text numberOfLines={1} style={type.bodyStrong}>
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
      ) : onPress ? (
        <Icon name="chevron" size={16} color={colors.text3} strokeWidth={2.4} />
      ) : null}
    </>
  );
  if (!onPress) return <View style={styles.row}>{content}</View>;
  return (
    <Tap label={title} onPress={onPress} style={styles.row} scaleTo={0.99}>
      {content}
    </Tap>
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
      <Icon name={tone === "info" ? "shield" : "warning"} color={color} size={18} />
      <Text style={[styles.noticeText, tone !== "info" && { color }]}>{text}</Text>
      {onDismiss ? (
        <Tap label="Dismiss" onPress={onDismiss} hitSlop={8}>
          <Icon name="close" size={16} color={color} />
        </Tap>
      ) : null}
    </View>
  );
}

export function EmptyState({
  icon,
  title,
  body,
  action,
}: {
  icon: IconName;
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <Reveal style={styles.empty}>
      <View style={styles.emptyIcon}>
        <Icon name={icon} size={30} color={colors.accent} strokeWidth={1.9} />
      </View>
      <Text style={styles.emptyTitle}>{title}</Text>
      <Text style={styles.emptyBody}>{body}</Text>
      {action ? <View style={styles.emptyAction}>{action}</View> : null}
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
}) {
  const name = label ?? (group ? "Group message" : "Message");
  return (
    <View style={styles.composerBar}>
      <View style={[styles.composerShell, disabled && styles.composerShellDisabled]}>
        <TextInput
          accessibilityLabel={name}
          testID={name}
          editable={!disabled}
          multiline
          onChangeText={onChangeText}
          placeholder={placeholder}
          placeholderTextColor={colors.text3}
          selectionColor={colors.accent}
          style={styles.composerInput}
          value={value}
        />
        <View style={styles.composerSend}>
          <IconButton
            name="arrowUp"
            label={sendLabel}
            variant="filled"
            size={32}
            disabled={disabled || sendDisabled || !value.trim()}
            onPress={onSend}
          />
        </View>
      </View>
    </View>
  );
}

export function MessageBubble({
  body,
  timestamp,
  sent,
  disappearing = false,
  tail = true,
  spaced = true,
}: {
  body: string;
  timestamp: number;
  sent: boolean;
  disappearing?: boolean;
  tail?: boolean;
  spaced?: boolean;
}) {
  const metaColor = sent ? "rgba(255,255,255,0.72)" : colors.text3;
  return (
    <View
      accessibilityLabel={`${sent ? "Sent" : "Received"} message: ${body}`}
      style={[
        styles.bubble,
        sent ? styles.bubbleSent : styles.bubbleReceived,
        tail && (sent ? styles.bubbleTailSent : styles.bubbleTailReceived),
        spaced && styles.bubbleSpaced,
      ]}
    >
      <Text selectable style={styles.bubbleBody}>
        {body}
      </Text>
      <View style={styles.bubbleMeta}>
        {disappearing ? <Icon name="timer" size={11} color={metaColor} strokeWidth={2.2} /> : null}
        <Text style={[styles.bubbleTime, { color: metaColor }]}>{formatClock(timestamp)}</Text>
      </View>
    </View>
  );
}

export function DayDivider({ label }: { label: string }) {
  return (
    <View style={styles.dayDivider}>
      <View style={styles.dayChip}>
        <Text style={styles.dayChipText}>{label}</Text>
      </View>
    </View>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: readonly { key: T; label: string; accessibilityLabel?: string; count?: number }[];
  value: T;
  onChange: (key: T) => void;
}) {
  return (
    <View style={styles.segmented}>
      {options.map((option) => {
        const active = option.key === value;
        return (
          <Tap
            key={option.key}
            label={option.accessibilityLabel ?? option.label}
            state={{ selected: active }}
            onPress={() => onChange(option.key)}
            scaleTo={0.96}
            style={[styles.segment, active && styles.segmentActive]}
          >
            <Text style={[styles.segmentText, active && styles.segmentTextActive]}>
              {option.label}
            </Text>
            {option.count ? (
              <View style={[styles.count, active && styles.countActive]}>
                <Text style={[styles.countText, active && styles.countTextActive]}>
                  {option.count}
                </Text>
              </View>
            ) : null}
          </Tap>
        );
      })}
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
  return (
    <Tap
      label={accessibilityLabel ?? label}
      state={{ selected }}
      onPress={onPress}
      style={[styles.chip, selected && styles.chipSelected]}
    >
      {selected ? <Icon name="check" size={14} color={colors.onAccent} strokeWidth={2.6} /> : null}
      <Text style={[styles.chipText, selected && styles.chipTextSelected]}>{label}</Text>
    </Tap>
  );
}

export function ConversationRow({
  name,
  preview,
  time,
  requestPending,
  blocked,
  verified,
  keyChanged,
  onPress,
}: {
  name: string;
  preview: string;
  time: string;
  requestPending: boolean;
  blocked: boolean;
  verified: boolean;
  keyChanged: boolean;
  onPress: () => void;
}) {
  const label = `Conversation with ${name}${requestPending ? ", message request pending" : ""}`;
  return (
    <Tap accessible={false} onPress={onPress} style={styles.conversation} scaleTo={0.985}>
      {/* One row-sized element carries the stable label while the preview stays readable. */}
      <View
        accessible
        accessibilityRole="button"
        accessibilityLabel={label}
        pointerEvents="none"
        style={StyleSheet.absoluteFill}
      />
      <Avatar name={name} size={54} />
      <View style={styles.conversationBody}>
        <View style={styles.conversationLine}>
          <Text numberOfLines={1} style={[type.headline, layout.flex]}>
            {name}
          </Text>
          {time ? (
            <Text style={[styles.conversationTime, requestPending && { color: colors.accent }]}>
              {time}
            </Text>
          ) : null}
        </View>
        <View style={styles.conversationLine}>
          {verified ? <Icon name="shield" size={13} color={colors.success} strokeWidth={2.3} /> : null}
          {keyChanged ? <Icon name="warning" size={13} color={colors.warning} strokeWidth={2.3} /> : null}
          {blocked ? <Icon name="block" size={13} color={colors.text3} strokeWidth={2.3} /> : null}
          <Text
            numberOfLines={1}
            style={[
              styles.conversationPreview,
              requestPending && styles.conversationPreviewStrong,
              layout.flex,
            ]}
          >
            {preview}
          </Text>
          {requestPending ? <View style={styles.unreadDot} /> : null}
        </View>
      </View>
    </Tap>
  );
}

export function GroupRow({
  name,
  subtitle,
  label,
  onPress,
}: {
  name: string;
  subtitle: string;
  label: string;
  onPress: () => void;
}) {
  return (
    <Tap label={label} onPress={onPress} style={styles.conversation} scaleTo={0.985}>
      <Avatar name={name} size={54} group />
      <View style={styles.conversationBody}>
        <Text numberOfLines={1} style={type.headline}>
          {name}
        </Text>
        <Text numberOfLines={1} style={styles.conversationPreview}>
          {subtitle}
        </Text>
      </View>
      <Icon name="chevron" size={16} color={colors.text3} strokeWidth={2.4} />
    </Tap>
  );
}

export function SearchField({
  value,
  onChangeText,
  label,
  placeholder,
}: {
  value: string;
  onChangeText: (value: string) => void;
  label: string;
  placeholder: string;
}) {
  return (
    <View style={styles.search}>
      <Icon name="search" size={17} color={colors.text3} />
      <TextInput
        accessibilityLabel={label}
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor={colors.text3}
        selectionColor={colors.accent}
        style={styles.searchInput}
        autoCapitalize="none"
        autoCorrect={false}
        returnKeyType="search"
      />
      {value ? (
        <Tap label="Clear search" onPress={() => onChangeText("")} hitSlop={8}>
          <View style={styles.clearDot}>
            <Icon name="close" size={11} color={colors.canvas} strokeWidth={3} />
          </View>
        </Tap>
      ) : null}
    </View>
  );
}

export function QrCard({ value, caption }: { value: string; caption?: string }) {
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
        backgroundColor={colors.white}
        color="#0B0B10"
        quietZone={0}
        size={228}
        value={frames[current]!}
      />
      {frames.length > 1 ? (
        <View style={layout.center}>
          <View style={styles.qrDots}>
            {frames.map((_, index) => (
              <View
                key={index}
                style={[styles.qrDot, index === current && styles.qrDotActive]}
              />
            ))}
          </View>
          <Text style={styles.qrCaption}>
            Code {current + 1} of {frames.length} · Keep scanning
          </Text>
        </View>
      ) : caption ? (
        <Text style={styles.qrCaption}>{caption}</Text>
      ) : null}
    </View>
  );
}

export function Reticle({ hint }: { hint: string }) {
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
        </View>
        <View style={styles.mask} />
      </View>
      <View style={[styles.mask, styles.maskBottom]}>
        <View style={styles.reticleHint}>
          <Text style={styles.reticleHintText}>{hint}</Text>
        </View>
      </View>
    </View>
  );
}

export function Toast({
  text,
  busy = false,
  error = false,
  onDismiss,
}: {
  text: string;
  busy?: boolean;
  error?: boolean;
  onDismiss?: () => void;
}) {
  return (
    <Reveal distance={8} style={styles.toastWrap}>
      <View
        accessibilityLiveRegion={error ? "assertive" : "polite"}
        style={[styles.toast, error && styles.toastError]}
      >
        {busy ? (
          <ActivityIndicator size="small" color={colors.accent} />
        ) : (
          <Icon
            name={error ? "warning" : "check"}
            size={17}
            color={error ? colors.danger : colors.accent}
            strokeWidth={2.4}
          />
        )}
        <Text style={styles.toastText}>{text}</Text>
        {onDismiss ? (
          <Tap label="Dismiss" onPress={onDismiss} hitSlop={10}>
            <Icon name="close" size={16} color={colors.text2} />
          </Tap>
        ) : null}
      </View>
    </Reveal>
  );
}

export function TabBar<T extends string>({
  tabs,
  current,
  onSelect,
}: {
  tabs: readonly { key: T; title: string; icon: IconName }[];
  current: T;
  onSelect: (key: T) => void;
}) {
  return (
    <SafeAreaView edges={["bottom"]} style={styles.tabBar}>
      {tabs.map((tab) => {
        const active = tab.key === current;
        return (
          <Pressable
            key={tab.key}
            testID={`tab-${tab.key}`}
            accessibilityRole="tab"
            accessibilityLabel={tab.title}
            accessibilityState={{ selected: active }}
            onPress={() => onSelect(tab.key)}
            style={styles.tab}
          >
            <Icon
              name={tab.icon}
              size={25}
              color={active ? colors.accent : colors.text3}
              strokeWidth={active ? 2.2 : 1.9}
            />
            <Text style={[styles.tabText, active && styles.tabTextActive]}>{tab.title}</Text>
          </Pressable>
        );
      })}
    </SafeAreaView>
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
  return (
    <View style={styles.feature}>
      <View style={styles.featureIcon}>
        <Icon name={icon} size={22} color={colors.accent} strokeWidth={2} />
      </View>
      <View style={[layout.flex, { gap: 2 }]}>
        <Text style={type.headline}>{title}</Text>
        <Text style={type.subhead}>{body}</Text>
      </View>
    </View>
  );
}

export function KeyValue({ label, value }: { label: string; value: string }) {
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
  return (
    <Text selectable accessibilityLabel={`Code ${value}`} style={styles.code}>
      {value}
    </Text>
  );
}

export const layout = StyleSheet.create({
  flex: { flex: 1 },
  screen: { flex: 1, backgroundColor: colors.canvas },
  content: {
    flexGrow: 1,
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 32,
    gap: 20,
  },
  contentTight: {
    flexGrow: 1,
    paddingHorizontal: 20,
    paddingTop: 6,
    paddingBottom: 32,
    gap: 18,
  },
  stack: { gap: 12 },
  stackLoose: { gap: 20 },
  row: { flexDirection: "row", alignItems: "center", gap: 12 },
  rowBetween: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 12,
  },
  wrap: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  center: { alignItems: "center", gap: 8 },
  centerText: { textAlign: "center" },
  list: { flexGrow: 1, paddingHorizontal: 10, paddingTop: 6, paddingBottom: 24 },
  messages: { flexGrow: 1, paddingHorizontal: 12, paddingVertical: 12 },
  inset: { paddingHorizontal: 20 },
});

const styles = StyleSheet.create({
  pressed: { opacity: 0.75 },
  disabled: { opacity: 0.4 },

  button: {
    minHeight: 52,
    borderRadius: radius.pill,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
    paddingHorizontal: 22,
    paddingVertical: 12,
  },
  buttonInline: { alignSelf: "flex-start" },
  buttonSmall: { minHeight: 36, paddingHorizontal: 14, paddingVertical: 6, gap: 6 },
  buttonPrimary: { backgroundColor: colors.accent },
  buttonSecondary: { backgroundColor: colors.raised },
  buttonDanger: { backgroundColor: colors.dangerSoft },
  buttonText: {
    fontFamily: fonts.semibold,
    fontSize: 16,
    letterSpacing: -0.2,
    textAlign: "center",
  },
  buttonTextSmall: { fontSize: 14 },

  iconButton: {
    borderRadius: radius.pill,
    alignItems: "center",
    justifyContent: "center",
  },
  iconButtonTonal: { backgroundColor: colors.raised },
  iconButtonFilled: { backgroundColor: colors.accent },

  header: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    minHeight: 54,
    gap: 8,
  },
  headerSide: { minWidth: 42, alignItems: "flex-start" },
  headerSideEnd: { alignItems: "flex-end" },
  headerTitle: {
    flex: 1,
    fontFamily: fonts.semibold,
    fontSize: 17,
    letterSpacing: -0.3,
    color: colors.text,
    textAlign: "center",
  },
  largeHeader: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 20,
    paddingTop: 10,
    paddingBottom: 10,
    gap: 12,
  },
  headerActions: { flexDirection: "row", alignItems: "center", gap: 10 },
  chatHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    paddingHorizontal: 10,
    paddingVertical: 8,
    backgroundColor: colors.canvas,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.lineStrong,
  },
  statusLine: { flexDirection: "row", alignItems: "center", gap: 4, marginTop: 1 },

  avatarOverlay: {
    position: "absolute",
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
    alignItems: "center",
    justifyContent: "center",
  },
  hero: { alignItems: "center", gap: 10, paddingTop: 6 },

  badge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 5,
    borderRadius: radius.pill,
    paddingHorizontal: 10,
    paddingVertical: 4,
  },
  badgeText: { fontFamily: fonts.semibold, fontSize: 12, letterSpacing: 0.1 },

  field: { gap: 8 },
  inputShell: {
    flexDirection: "row",
    alignItems: "center",
    gap: 2,
    backgroundColor: colors.surface,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: colors.line,
    minHeight: 52,
    paddingHorizontal: 16,
  },
  inputShellMultiline: { alignItems: "flex-start", paddingVertical: 4 },
  inputShellFocused: { borderColor: colors.accent, backgroundColor: colors.raised },
  inputPrefix: { fontFamily: fonts.medium, fontSize: 17, color: colors.text3 },
  input: {
    flex: 1,
    minHeight: 50,
    fontFamily: fonts.regular,
    fontSize: 17,
    color: colors.text,
    paddingVertical: 0,
  },
  inputMultiline: { minHeight: 104, paddingTop: 12, textAlignVertical: "top" },

  card: {
    backgroundColor: colors.surface,
    borderRadius: radius.lg,
    overflow: "hidden",
  },
  cardPadded: { padding: 18, gap: 12 },
  cardAccent: {
    backgroundColor: colors.accentSoft,
    borderWidth: 1,
    borderColor: "rgba(76,141,255,0.25)",
  },

  section: { gap: 8 },
  sectionHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 6,
  },

  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
    paddingHorizontal: 16,
    paddingVertical: 12,
    minHeight: 60,
  },
  rowIcon: {
    width: 32,
    height: 32,
    borderRadius: 9,
    alignItems: "center",
    justifyContent: "center",
  },
  rowDivider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: colors.lineStrong,
    marginLeft: 62,
  },

  notice: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 10,
    borderRadius: radius.md,
    padding: 14,
    backgroundColor: colors.surface,
  },
  noticeText: { flex: 1, ...type.footnote, lineHeight: 19, color: colors.text2 },

  empty: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingHorizontal: 32,
    paddingVertical: 40,
    gap: 8,
  },
  emptyIcon: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: colors.accentSoft,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 10,
  },
  emptyTitle: { ...type.title2, textAlign: "center" },
  emptyBody: { ...type.subhead, textAlign: "center", maxWidth: 280 },
  emptyAction: { marginTop: 14, alignItems: "center", gap: 6 },

  composerBar: {
    paddingHorizontal: 12,
    paddingTop: 8,
    paddingBottom: 8,
    backgroundColor: colors.canvas,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.lineStrong,
  },
  composerShell: {
    flexDirection: "row",
    alignItems: "flex-end",
    minHeight: 44,
    maxHeight: 150,
    borderRadius: 22,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.lineStrong,
    paddingLeft: 16,
    paddingRight: 6,
  },
  composerShellDisabled: { opacity: 0.6 },
  composerInput: {
    flex: 1,
    fontFamily: fonts.regular,
    fontSize: 16.5,
    lineHeight: 21,
    color: colors.text,
    paddingTop: 11,
    paddingBottom: 11,
    paddingRight: 8,
  },
  composerSend: { paddingBottom: 5 },

  bubble: {
    maxWidth: "78%",
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingTop: 8,
    paddingBottom: 6,
    marginTop: 2,
  },
  bubbleSpaced: { marginTop: 10 },
  bubbleSent: { alignSelf: "flex-end", backgroundColor: colors.accentDeep },
  bubbleReceived: { alignSelf: "flex-start", backgroundColor: colors.raised },
  bubbleTailSent: { borderBottomRightRadius: 6 },
  bubbleTailReceived: { borderBottomLeftRadius: 6 },
  bubbleBody: {
    fontFamily: fonts.regular,
    fontSize: 16.5,
    lineHeight: 22,
    letterSpacing: -0.1,
    color: colors.text,
  },
  bubbleMeta: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "flex-end",
    gap: 4,
    marginTop: 2,
  },
  bubbleTime: { fontFamily: fonts.medium, fontSize: 11 },
  dayDivider: { alignItems: "center", marginVertical: 14 },
  dayChip: {
    borderRadius: radius.pill,
    paddingHorizontal: 10,
    paddingVertical: 4,
    backgroundColor: colors.surface,
  },
  dayChipText: { ...type.caption, color: colors.text2 },

  segmented: {
    flexDirection: "row",
    gap: 8,
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 6,
  },
  segment: {
    flexDirection: "row",
    alignItems: "center",
    gap: 7,
    minHeight: 34,
    borderRadius: radius.pill,
    paddingHorizontal: 14,
    backgroundColor: colors.surface,
  },
  segmentActive: { backgroundColor: colors.accentSoft },
  segmentText: { fontFamily: fonts.medium, fontSize: 14, color: colors.text2 },
  segmentTextActive: { color: colors.accent, fontFamily: fonts.semibold },
  count: {
    minWidth: 20,
    height: 20,
    borderRadius: 10,
    paddingHorizontal: 6,
    backgroundColor: colors.elevated,
    alignItems: "center",
    justifyContent: "center",
  },
  countActive: { backgroundColor: colors.accent },
  countText: { fontFamily: fonts.bold, fontSize: 11.5, color: colors.text },
  countTextActive: { color: colors.onAccent },

  chip: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    minHeight: 40,
    borderRadius: radius.pill,
    paddingHorizontal: 16,
    justifyContent: "center",
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.lineStrong,
  },
  chipSelected: { backgroundColor: colors.accent, borderColor: colors.accent },
  chipText: { fontFamily: fonts.medium, fontSize: 14.5, color: colors.text },
  chipTextSelected: { color: colors.onAccent, fontFamily: fonts.semibold },

  conversation: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
    paddingHorizontal: 10,
    paddingVertical: 10,
    borderRadius: radius.lg,
  },
  conversationBody: { flex: 1, gap: 3 },
  conversationLine: { flexDirection: "row", alignItems: "center", gap: 6 },
  conversationTime: { fontFamily: fonts.regular, fontSize: 13, color: colors.text3 },
  conversationPreview: {
    fontFamily: fonts.regular,
    fontSize: 15,
    lineHeight: 20,
    color: colors.text2,
  },
  conversationPreviewStrong: { fontFamily: fonts.medium, color: colors.text },
  unreadDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: colors.accent,
    marginLeft: 4,
  },

  search: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    marginHorizontal: 20,
    marginTop: 2,
    paddingHorizontal: 12,
    minHeight: 40,
    borderRadius: radius.sm,
    backgroundColor: colors.surface,
  },
  searchInput: {
    flex: 1,
    fontFamily: fonts.regular,
    fontSize: 16,
    color: colors.text,
    paddingVertical: 0,
  },
  clearDot: {
    width: 18,
    height: 18,
    borderRadius: 9,
    backgroundColor: colors.text3,
    alignItems: "center",
    justifyContent: "center",
  },

  qrCard: {
    alignSelf: "center",
    alignItems: "center",
    backgroundColor: colors.white,
    borderRadius: radius.xl,
    padding: 22,
    gap: 16,
    ...shadow,
  },
  qrDots: { flexDirection: "row", gap: 5, marginBottom: 8 },
  qrDot: { width: 6, height: 6, borderRadius: 3, backgroundColor: "rgba(0,0,0,0.15)" },
  qrDotActive: { backgroundColor: colors.accent, width: 16 },
  qrCaption: { fontFamily: fonts.medium, fontSize: 13, color: "#6B6B75" },

  mask: { flex: 1, backgroundColor: colors.scrim },
  maskBottom: { alignItems: "center", paddingTop: 28 },
  reticleRow: { flexDirection: "row", height: 256 },
  reticle: { width: 256, height: 256 },
  corner: {
    position: "absolute",
    width: 40,
    height: 40,
    borderColor: colors.white,
  },
  cornerTopLeft: { top: 0, left: 0, borderTopWidth: 4, borderLeftWidth: 4, borderTopLeftRadius: 22 },
  cornerTopRight: { top: 0, right: 0, borderTopWidth: 4, borderRightWidth: 4, borderTopRightRadius: 22 },
  cornerBottomLeft: { bottom: 0, left: 0, borderBottomWidth: 4, borderLeftWidth: 4, borderBottomLeftRadius: 22 },
  cornerBottomRight: { bottom: 0, right: 0, borderBottomWidth: 4, borderRightWidth: 4, borderBottomRightRadius: 22 },
  reticleHint: {
    backgroundColor: "rgba(21,21,26,0.9)",
    borderRadius: radius.pill,
    paddingHorizontal: 16,
    paddingVertical: 10,
  },
  reticleHintText: { fontFamily: fonts.medium, fontSize: 14, color: colors.text },

  toastWrap: { paddingHorizontal: 16, paddingBottom: 10 },
  toast: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    borderRadius: radius.md,
    paddingHorizontal: 14,
    paddingVertical: 12,
    backgroundColor: colors.elevated,
    ...shadow,
  },
  toastError: { backgroundColor: "#2B1B1E" },
  toastText: {
    flex: 1,
    fontFamily: fonts.medium,
    fontSize: 14,
    lineHeight: 19,
    color: colors.text,
  },

  tabBar: {
    flexDirection: "row",
    backgroundColor: colors.surface,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.lineStrong,
    paddingTop: 8,
    paddingHorizontal: 12,
  },
  tab: { flex: 1, alignItems: "center", gap: 4, paddingBottom: 4, minHeight: 50 },
  tabText: { fontFamily: fonts.medium, fontSize: 10.5, color: colors.text3 },
  tabTextActive: { color: colors.accent },

  feature: { flexDirection: "row", alignItems: "center", gap: 16 },
  featureIcon: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: colors.accentSoft,
    alignItems: "center",
    justifyContent: "center",
  },

  keyValue: { gap: 4 },
  code: {
    fontFamily: fonts.mono,
    fontSize: 30,
    lineHeight: 40,
    letterSpacing: 4,
    color: colors.text,
    textAlign: "center",
  },
});
