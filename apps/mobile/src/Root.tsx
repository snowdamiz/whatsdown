import { useEffect, useState } from "react";
import App from "./App";
import { LockGate } from "./LockGate";
import type { Appearance } from "./appearance";
import { loadAppearance, saveAppearance } from "./appearance-store";
import { AppearanceProvider } from "./theme";

export default function Root() {
  // An erased account restarts the app, so nothing of it stays in memory.
  const [session, setSession] = useState<{ generation: number; notice?: string }>({ generation: 0 });
  // The choice is sealed in the database, so it comes back a moment after launch.
  // The launch screen stays up until then, and the first frame is in its scheme.
  const [appearance, setAppearance] = useState<Appearance>();
  useEffect(() => { void loadAppearance().then(setAppearance); }, []);
  if (appearance === undefined) return null;
  return (
    <AppearanceProvider load={() => appearance} save={saveAppearance}>
      <LockGate>
        <App key={session.generation} notice={session.notice}
          onAccountErased={(notice) => setSession(({ generation }) => ({ generation: generation + 1, notice }))} />
      </LockGate>
    </AppearanceProvider>
  );
}
