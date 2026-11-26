import * as SplashScreen from "expo-splash-screen";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { AppState, Platform, StyleSheet, Text, View } from "react-native";

import { lockNative } from "../modules/mesh-messenger/lock";
import { lockDue, lockOptions, onLockSetting, publishLockSetting, type LockSetting } from "./app-lock";
import { loadLockSetting, saveLockSetting } from "./ephemeral-native";
import { databasePath } from "./storage";
import { space, themed, useAppFonts, useTheme } from "./theme";
import { AppGlyph, Button, Row, Segmented, Wallpaper } from "./ui";

// App lock (Settings → Privacy): nothing of the app is mounted until the owner
// unlocks at launch, and after it has been away for the chosen time it is covered
// and hidden from assistive technology until they unlock again. The app switcher
// never shows it either way (MeshMessengerDataProtection, FLAG_SECURE).
export function LockGate({ children }: { children: ReactNode }) {
  const styles = useStyles();
  const [setting, setSetting] = useState<LockSetting | undefined>(undefined);
  const [locked, setLocked] = useState(true);
  const [opened, setOpened] = useState(false);
  const current = useRef<LockSetting>(null);
  const leftAt = useRef<number | undefined>(undefined);
  // The owner check itself can take the app to the background (Android's
  // confirmation screen); that is not the app being away.
  const asking = useRef(false);

  async function unlock(): Promise<void> {
    if (asking.current) return;
    asking.current = true;
    try {
      if (await lockNative.lockAuthenticate("Unlock Morse")) {
        setLocked(false);
        setOpened(true);
      }
    } catch {
      // Still locked; the button asks again.
    } finally {
      asking.current = false;
    }
  }

  useEffect(() => {
    let active = true;
    const settle = (value: LockSetting) => {
      if (!active) return;
      current.current = value;
      setSetting(value);
      if (value === null) {
        setLocked(false);
        setOpened(true);
      } else void unlock();
    };
    // A database that can't be read yet (a new install) has no lock to honour.
    loadLockSetting(databasePath).then(settle, () => settle(null));
    const unsubscribe = onLockSetting((value) => {
      current.current = value;
      setSetting(value);
    });
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "background" && !asking.current) leftAt.current ??= Date.now();
      if (state !== "active") return;
      const left = leftAt.current;
      leftAt.current = undefined;
      if (left !== undefined && lockDue(current.current, left, Date.now())) {
        setLocked(true);
        void unlock();
      }
    });
    return () => {
      active = false;
      unsubscribe();
      subscription.remove();
    };
  }, []);

  // Until the setting is read, the launch screen stays up.
  if (setting === undefined) return <View style={styles.fill} />;
  return (
    <View style={styles.fill}>
      {opened ? (
        <View
          style={styles.fill}
          accessibilityElementsHidden={locked}
          importantForAccessibility={locked ? "no-hide-descendants" : "auto"}
        >
          {children}
        </View>
      ) : null}
      {locked ? <LockScreen onUnlock={() => void unlock()} /> : null}
    </View>
  );
}

// The app's own launch cover never mounted, so the lock takes the OS's (or the
// desktop page's) launch screen down itself.
function hideLaunchScreen(): void {
  if (Platform.OS === "web") document.getElementById("morse-launch")?.remove();
  else void SplashScreen.hideAsync().catch(() => undefined);
}

function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const { type } = useTheme();
  const styles = useStyles();
  // At launch the app, which loads the fonts, isn't mounted yet.
  useAppFonts();
  return (
    <View style={styles.cover} accessibilityViewIsModal onLayout={hideLaunchScreen}>
      <Wallpaper />
      <AppGlyph />
      <Text accessibilityRole="header" style={type.title}>Morse is locked</Text>
      <Text style={[type.body, styles.note]}>
        {Platform.OS === "web"
          ? "Unlock with Touch ID or your Mac’s password."
          : "Unlock with Face ID, your fingerprint or your passcode."}
      </Text>
      <Button label="Unlock" icon="lock" onPress={onUnlock} />
    </View>
  );
}

// Settings → Privacy. Shown where the device has a passcode or screen lock to ask
// for; turning the lock on asks for it once, so no one locks themselves out.
export function AppLockRow({ disabled = false }: { disabled?: boolean }) {
  const [available, setAvailable] = useState(false);
  const [setting, setSetting] = useState<LockSetting>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    lockNative.lockAvailable().then(setAvailable, () => setAvailable(false));
    loadLockSetting(databasePath).then(setSetting, () => undefined);
    return onLockSetting(setSetting);
  }, []);
  if (!available && setting === null) return null;
  async function choose(value: number): Promise<void> {
    const next = value < 0 ? null : value;
    try {
      if (next !== null && setting === null && !(await lockNative.lockAuthenticate("Turn on app lock"))) return;
      await saveLockSetting(databasePath, next);
      setFailed(false);
      publishLockSetting(next);
    } catch {
      setFailed(true);
    }
  }
  const subtitle = failed ? "Couldn’t be saved. Try again."
    : setting === null ? "Off"
      : setting === 0 ? "Every time Morse opens"
        : `${lockOptions.find((option) => option.value === setting)?.label} away`;
  return (
    <Row
      icon="lock"
      title="App lock"
      subtitle={subtitle}
      trailing={
        <Segmented
          label="App lock"
          options={lockOptions}
          value={setting ?? -1}
          onSelect={(value) => { if (!disabled) void choose(value); }}
        />
      }
    />
  );
}

const useStyles = themed(({ colors }) => StyleSheet.create({
  fill: { flex: 1 },
  cover: {
    ...StyleSheet.absoluteFill,
    alignItems: "center",
    justifyContent: "center",
    gap: space[4],
    padding: space[6],
    backgroundColor: colors.canvas,
    zIndex: 200,
  },
  note: { color: colors.text2, textAlign: "center", maxWidth: 320 },
}));
