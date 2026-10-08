import { CameraView, useCameraPermissions } from "expo-camera";
import { useRef, useState } from "react";
import { Image, Platform, ScrollView, StyleSheet, Text, View } from "react-native";

import { describeSafetyCheck, viewOnceCaution, type SafetyOutcome } from "./ephemeral";
import { radius, space, themed, useTheme } from "./theme";
import { Actions, Button, Dialog, Field, Notice, QrCard, Reticle } from "./ui";

// What a view-once message showed when it was opened: its words and pictures,
// decrypted for this look only. Closing the dialog is the end of them.
export type ViewOnceOpened = { body: string; images: string[]; loading: boolean };

export function ViewOnceDialog({ opened, onClose }: { opened: ViewOnceOpened | null; onClose: () => void }) {
  const { type } = useTheme();
  const styles = useStyles();
  return (
    <Dialog visible={opened !== null} label="View once message" onClose={onClose}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text accessibilityRole="header" style={type.headline}>View once</Text>
        {opened?.loading ? <Text style={type.body}>Opening…</Text> : null}
        {opened?.body ? <Text selectable={false} style={type.body}>{opened.body}</Text> : null}
        {opened?.images.map((uri) => (
          <Image key={uri} source={{ uri }} resizeMode="contain" style={styles.image} accessibilityLabel="View once photo" />
        ))}
        <Text style={styles.note}>
          This was its one look: it’s already gone from this device. Morse can’t stop a screenshot or a photo of the screen.
        </Text>
        <Actions>
          <Button label="Done" onPress={onClose} />
        </Actions>
      </ScrollView>
    </Dialog>
  );
}

// The chat's safety number as a code: shown for the other side to scan, and read
// from theirs, by camera on a phone or pasted on any device. The core compares.
export function SafetyCodeDialog({
  visible,
  username,
  code,
  onCheck,
  onClose,
}: {
  visible: boolean;
  username: string;
  code: string | null;
  onCheck: (text: string) => Promise<SafetyOutcome>;
  onClose: () => void;
}) {
  const { type } = useTheme();
  const styles = useStyles();
  const [mode, setMode] = useState<"show" | "scan" | "paste">("show");
  const [pasted, setPasted] = useState("");
  const [outcome, setOutcome] = useState<SafetyOutcome | null>(null);
  const [failure, setFailure] = useState("");
  const [permission, requestPermission] = useCameraPermissions();
  const checking = useRef(false);
  const camera = Platform.OS !== "web";
  const close = () => {
    setMode("show");
    setPasted("");
    setOutcome(null);
    setFailure("");
    onClose();
  };
  async function check(text: string): Promise<void> {
    if (checking.current) return;
    checking.current = true;
    try {
      setOutcome(await onCheck(text));
      setFailure("");
      setMode("show");
    } catch (caught) {
      setFailure(caught instanceof Error ? caught.message : String(caught));
    } finally {
      checking.current = false;
    }
  }
  const result = outcome ? describeSafetyCheck(outcome, username) : null;
  return (
    <Dialog visible={visible} label="Verify with a code" onClose={close}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text accessibilityRole="header" style={type.headline}>Verify @{username}</Text>
        {result ? <Notice tone={result.tone === "success" ? "info" : result.tone} text={result.text} /> : null}
        {failure ? <Notice tone="error" text={failure} /> : null}
        {mode === "show" ? (
          <>
            <Text style={type.body}>
              {camera
                ? `Scan the code @${username} shows in their chat with you, or let them scan yours.`
                : `Let @${username} scan this code from their chat with you, or paste the code their device shows.`}
            </Text>
            {code ? <QrCard value={code} caption="Your code for this chat" /> : <Text style={type.body}>Preparing the code…</Text>}
            <Actions>
              {camera ? <Button label="Scan their code" icon="scan" onPress={() => setMode("scan")} /> : null}
              <Button label="Paste their code" variant={camera ? "ghost" : "primary"} onPress={() => setMode("paste")} />
            </Actions>
          </>
        ) : mode === "paste" ? (
          <>
            <Field
              label="Their code"
              placeholder="morse-verify:1:…"
              value={pasted}
              onChangeText={setPasted}
              multiline
            />
            <Actions>
              <Button label="Check code" disabled={!pasted.trim()} onPress={() => void check(pasted)} />
              <Button label="Back" variant="ghost" onPress={() => setMode("show")} />
            </Actions>
          </>
        ) : !permission?.granted ? (
          <>
            <Text style={type.body}>Camera frames never leave your device.</Text>
            <Actions>
              <Button label="Allow camera" onPress={() => void requestPermission()} />
              <Button label="Back" variant="ghost" onPress={() => setMode("show")} />
            </Actions>
          </>
        ) : (
          <>
            <View style={styles.camera}>
              <CameraView
                barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                onBarcodeScanned={({ data }) => void check(data)}
                style={StyleSheet.absoluteFill}
              />
              <Reticle hint="Hold their code inside the frame" />
            </View>
            <Actions>
              <Button label="Back" variant="ghost" onPress={() => setMode("show")} />
            </Actions>
          </>
        )}
      </ScrollView>
    </Dialog>
  );
}

// The line a view-once toggle adds under the composer's intent.
export const viewOnceNote = viewOnceCaution;

const useStyles = themed(({ colors, type }) => StyleSheet.create({
  content: { gap: space[3], paddingTop: space[1], paddingHorizontal: space[5] },
  image: { width: "100%", aspectRatio: 1, borderRadius: radius.lg, backgroundColor: colors.black },
  note: { ...type.caption, color: colors.text3 },
  camera: { height: 320, borderRadius: radius.lg, overflow: "hidden", backgroundColor: colors.black },
}));
