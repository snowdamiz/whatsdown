import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

import type { Translate } from "./i18n";
import { useI18n } from "./language";
import { Button, Row, RowGroup, Section } from "./ui";

type Status =
  | { step: "idle" | "checking" | "current" }
  | { step: "available" | "installing"; version: string }
  | { step: "failed"; message: string };

const describe = (status: Status, t: Translate) =>
  status.step === "idle" ? t("Look for a newer release")
  : status.step === "checking" ? t("Checking…")
  : status.step === "current" ? t("Up to date")
  : status.step === "available" ? t("Morse {version} is available", { version: status.version })
  : status.step === "failed" ? status.message
  : t("Downloading. Morse restarts when it’s done.");

// Release builds only: the desktop shell refuses to update a development or
// preview build. The latest release is installed whole, after the shell checks
// its signature.
export function DesktopUpdates() {
  const { t } = useI18n();
  const [current, setCurrent] = useState("");
  const [status, setStatus] = useState<Status>({ step: "idle" });
  useEffect(() => { void getVersion().then(setCurrent).catch(() => undefined); }, []);

  const check = async () => {
    setStatus({ step: "checking" });
    try {
      const version = await invoke<string | null>("check_update");
      setStatus(version ? { step: "available", version } : { step: "current" });
    } catch {
      setStatus({ step: "failed", message: t("Couldn’t check for updates. Try again.") });
    }
  };
  // Installing restarts the app, so only a failure comes back.
  const install = async (version: string) => {
    setStatus({ step: "installing", version });
    try { await invoke("install_update"); }
    catch { setStatus({ step: "failed", message: t("Couldn’t install the update. Try again.") }); }
  };

  const busy = status.step === "checking" || status.step === "installing";
  return (
    <Section title={t("Updates")} footer={t("Morse checks only when you ask. GitHub, which hosts the releases, sees your IP address when it does.")}>
      <RowGroup>
        <Row
          icon="download"
          title={current ? `Morse ${current}` : "Morse"}
          subtitle={describe(status, t)}
          tone={status.step === "failed" ? "danger" : status.step === "available" ? "accent" : "muted"}
          trailing={
            status.step === "available" ? (
              <Button label={t("Install and restart")} size="sm" onPress={() => void install(status.version)} />
            ) : (
              <Button
                label={status.step === "checking" ? t("Checking…") : status.step === "installing" ? t("Installing…") : t("Check for updates")}
                variant="secondary"
                size="sm"
                disabled={busy}
                onPress={() => void check()}
              />
            )
          }
        />
      </RowGroup>
    </Section>
  );
}
