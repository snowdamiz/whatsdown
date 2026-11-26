import { useEffect, useState } from "react";
import { ScrollView, Text, View } from "react-native";

import { applyRestoredAppState, backUpNow, scheduledBackupProblem } from "./backup-app-state";
import { beginBackups, confirmBackups, disableBackups, loadBackupStatus, recoverAccount, restoreBackup } from "./backup.ts";
import { holdsAccountKey } from "./network";
import { backupErrorMessage, backupLine, type AppState, type BackupStatus } from "./backup-model.ts";
import { formatRecoveryCode, parseRecoveryCode } from "./recovery-code.ts";
import { databasePath } from "./storage";
import { useTheme } from "./theme";
import { Actions, Button, CodeBlock, Dialog, Field, Header, Notice, Page, Row, RowGroup, Section, layout } from "./ui";

// Settings -> Backups (protocol/backup-wire-v1.md, version 2): chats, groups'
// history and settings, sealed under a recovery code that is shown once and
// kept nowhere. A backup is made each day and kept six days. A backup from the
// device that created the account also brings the account back on a new
// install with nothing but the code; any backup restores onto a linked device.

type Step =
  | { kind: "status" }
  | { kind: "code"; code: Uint8Array }
  | { kind: "confirm"; code: Uint8Array }
  | { kind: "restore" }
  | { kind: "recover" }
  | { kind: "recovered"; username: string; conversations: number };

function useBackupStatus(): [BackupStatus | null, () => void] {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const reload = () => { loadBackupStatus(databasePath).then(setStatus, () => setStatus({ on: false, lastBackupAt: 0 })); };
  useEffect(reload, []);
  return [status, reload];
}

export function BackupsRow({ onPress }: { onPress: () => void }) {
  const [status] = useBackupStatus();
  return (
    <Row
      icon="lock"
      title="Backups"
      subtitle={status ? backupLine(status, Date.now()) : "Encrypted with a code only you hold"}
      onPress={onPress}
    />
  );
}

const restoredLine = (conversations: number, groups: number): string =>
  `Restored ${conversations} ${conversations === 1 ? "chat" : "chats"}` +
  (groups ? ` and the history of ${groups} ${groups === 1 ? "group" : "groups"}` : "") + ".";

export function BackupsScreen({ onBack, start = "status", onRestored, onRecovered, onReviewDevices, onLinkInstead }: {
  onBack: () => void;
  start?: "status" | "restore" | "recover";
  onRestored: (settings: AppState | null) => void;
  // A fresh install got its account back; the app takes on the profile.
  onRecovered?: () => Promise<void>;
  onReviewDevices?: () => void;
  onLinkInstead?: () => void;
}) {
  const { type } = useTheme();
  const [status, reload] = useBackupStatus();
  const [step, setStep] = useState<Step>({ kind: start });
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [confirmingOff, setConfirmingOff] = useState(false);
  const [recoversAccount, setRecoversAccount] = useState(false);
  const [needsLink, setNeedsLink] = useState(false);
  const scheduled = scheduledBackupProblem();
  useEffect(() => {
    if (start !== "recover") holdsAccountKey(databasePath).then(setRecoversAccount, () => {});
  }, [start]);

  const run = (label: string, task: () => Promise<void>) => {
    setBusy(label);
    setProblem(null);
    setDone(null);
    task().catch((error) => setProblem(backupErrorMessage(error))).finally(() => { setBusy(null); reload(); });
  };
  const go = (next: Step) => { setTyped(""); setProblem(null); setStep(next); };

  const toStatus = () => go({ kind: "status" });
  const feedback = (
    <>
      {busy ? <Notice text={busy} /> : null}
      {problem ? <Notice text={problem} tone="error" /> : null}
      {done ? <Notice text={done} /> : null}
    </>
  );

  if (step.kind === "code") {
    return (
      <Page header={<Header title="Your recovery code" onBack={toStatus} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stackLoose}>
            <Text style={type.body}>
              Write this code down and keep it somewhere safe. It is the only way to open your backups, and Morse
              can’t show it again or recover it for you.
            </Text>
            <CodeBlock label="Recovery code" value={formatRecoveryCode(step.code)} />
            <Text style={type.footnote}>
              {recoversAccount
                ? "This code brings your whole account back on a new phone, even if you lose every device. Keep it like a password: anyone who has it can read your backed-up chats and take over your account."
                : "Anyone with this code and a device on your account can read your backed-up chats. This device doesn’t hold the account key, so its backups can’t bring the account back on their own."}
            </Text>
            <Actions>
              <Button label="I’ve written it down" onPress={() => go({ kind: "confirm", code: step.code })} />
            </Actions>
          </View>
        </ScrollView>
      </Page>
    );
  }

  if (step.kind === "confirm") {
    const entered = parseRecoveryCode(typed);
    return (
      <Page header={<Header title="Check your code" onBack={() => go({ kind: "code", code: step.code })} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stackLoose}>
            <Text style={type.body}>Type the code you wrote down. Backups start once it matches.</Text>
            <Field label="Recovery code" value={typed} onChangeText={setTyped} placeholder="XXXX XXXX XXXX …"
              autoFocus multiline error={!entered && typed.replace(/[\s-]/g, "").length >= 52
                ? "That isn’t a whole recovery code." : undefined} />
            {feedback}
            <Actions>
              <Button label="Turn on backups" disabled={!entered || busy !== null} onPress={() => run("Checking the code…", async () => {
                await confirmBackups(databasePath, entered!);
                setStep({ kind: "status" });
                setTyped("");
                setBusy("Making the first backup…");
                await backUpNow();
                setDone("Backups are on. The first backup is stored.");
              })} />
            </Actions>
          </View>
        </ScrollView>
      </Page>
    );
  }

  if (step.kind === "recovered") {
    return (
      <Page header={<Header title="Welcome back" onBack={onBack} backLabel="Done" />}>
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stackLoose}>
            <Text style={type.title}>{`@${step.username} is back on this device.`}</Text>
            <Text style={type.body}>
              {`${restoredLine(step.conversations, 0)} Your contacts reach this device from their next message, and groups show their history again once a member adds it.`}
            </Text>
            <Notice text="Your old devices are still in your account. Remove the ones you no longer have, so that no one can read or send as you from them." tone="warning" />
            <Text style={type.footnote}>Backups are off on this device. Turn them on in Settings → Backups for a new recovery code.</Text>
            <Actions>
              <Button label="Remove devices you no longer have" icon="device" onPress={() => onReviewDevices?.()} />
              <Button label="Done" variant="secondary" onPress={onBack} />
            </Actions>
          </View>
        </ScrollView>
      </Page>
    );
  }

  if (step.kind === "recover") {
    const entered = parseRecoveryCode(typed);
    return (
      <Page header={<Header title="Restore from a backup" onBack={onBack} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stackLoose}>
            <Text style={type.body}>
              Enter the recovery code you wrote down when you turned on backups. Your account, chats and settings
              come back on this device, even if you no longer have any other.
            </Text>
            <Field label="Recovery code" value={typed} onChangeText={(value) => { setTyped(value); setNeedsLink(false); }}
              placeholder="XXXX XXXX XXXX …" autoFocus multiline />
            {feedback}
            <Actions>
              {needsLink && onLinkInstead
                ? <Button label="Link this device" icon="link" onPress={onLinkInstead} />
                : <Button label="Restore my account" icon="download" disabled={!entered || busy !== null} onPress={() => {
                  setBusy("Finding your backup…");
                  setProblem(null);
                  void (async () => {
                    try {
                      const recovered = await recoverAccount(databasePath, entered!, (completed, total) =>
                        setBusy(`Restoring… ${Math.round((completed / total) * 100)}%`));
                      setBusy("Setting up this device…");
                      await onRecovered?.();
                      await applyRestoredAppState(recovered).then(onRestored, () => {});
                      setTyped("");
                      setStep({ kind: "recovered", username: recovered.username, conversations: recovered.conversations });
                    } catch (error) {
                      if (String(error).includes("backup_has_no_account_key")) setNeedsLink(true);
                      setProblem(backupErrorMessage(error));
                    } finally {
                      setBusy(null);
                    }
                  })();
                }} />}
            </Actions>
          </View>
        </ScrollView>
      </Page>
    );
  }

  if (step.kind === "restore") {
    const entered = parseRecoveryCode(typed);
    return (
      <Page header={<Header title="Restore from a backup" onBack={start === "restore" ? onBack : toStatus} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stackLoose}>
            <Text style={type.body}>
              Enter the recovery code of a backup made on a device of this account in the past week. Its chats,
              the history of its groups, names and settings are added to this device.
            </Text>
            <Text style={type.footnote}>
              Groups show their history again once a member adds this device.
            </Text>
            <Field label="Recovery code" value={typed} onChangeText={setTyped} placeholder="XXXX XXXX XXXX …"
              autoFocus multiline />
            {feedback}
            <Actions>
              <Button label="Restore" icon="download" disabled={!entered || busy !== null} onPress={() => run("Finding your backup…", async () => {
                const restored = await restoreBackup(databasePath, entered!, (completed, total) =>
                  setBusy(`Restoring… ${Math.round((completed / total) * 100)}%`));
                onRestored(await applyRestoredAppState(restored));
                setTyped("");
                setStep({ kind: "status" });
                setDone(restoredLine(restored.conversations, restored.groups));
              })} />
            </Actions>
          </View>
        </ScrollView>
      </Page>
    );
  }

  return (
    <Page header={<Header title="Backups" onBack={onBack} />}>
      <ScrollView contentContainerStyle={layout.contentTight}>
        <Section
          footer={status?.on
            ? "A backup is made once a day and kept for six days. Messages with a timer, view-once content and attachments are never backed up."
            : "Back up your chats, the history of your groups and your settings, encrypted with a recovery code that only you hold."}
        >
          <RowGroup>
            <Row icon="lock" title="Backups" subtitle={status ? backupLine(status, Date.now()) : "…"} trailing={null} />
          </RowGroup>
        </Section>
        {scheduled && status?.on ? <Notice text={`The last daily backup failed. ${backupErrorMessage(scheduled)}`} tone="warning" /> : null}
        {feedback}
        <Actions>
          {status?.on ? (
            <>
              <Button label="Back up now" icon="refresh" disabled={busy !== null} onPress={() => run("Backing up…", async () => {
                await backUpNow();
                setDone("Backup stored.");
              })} />
              <Button label="Turn off backups" variant="danger" disabled={busy !== null} onPress={() => setConfirmingOff(true)} />
            </>
          ) : (
            <Button label="Turn on backups" disabled={busy !== null || !status} onPress={() => run("Making your recovery code…", async () => {
              go({ kind: "code", code: await beginBackups(databasePath) });
            })} />
          )}
          <Button label="Restore from a backup" variant="ghost" icon="download" disabled={busy !== null}
            onPress={() => go({ kind: "restore" })} />
        </Actions>
      </ScrollView>
      <Dialog visible={confirmingOff} label="Turn off backups" onClose={() => setConfirmingOff(false)}>
        <View style={layout.stack}>
          <Text style={type.title2}>Turn off backups?</Text>
          <Text style={type.body}>Your stored backups are deleted and this recovery code stops working.</Text>
          <Actions>
            <Button label="Turn off" variant="danger" onPress={() => {
              setConfirmingOff(false);
              run("Deleting your backups…", async () => {
                const unreachable = await disableBackups(databasePath);
                setDone(unreachable
                  ? `Backups are off. ${unreachable} couldn’t be reached and will expire within six days.`
                  : "Backups are off and deleted.");
              });
            }} />
            <Button label="Keep backups" variant="secondary" onPress={() => setConfirmingOff(false)} />
          </Actions>
        </View>
      </Dialog>
    </Page>
  );
}
