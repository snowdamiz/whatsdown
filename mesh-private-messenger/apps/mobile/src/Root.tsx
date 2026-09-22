import { useState } from "react";
import App from "./App";
import { loadAppearance, saveAppearance } from "./appearance-store";
import { AppearanceProvider } from "./theme";

export default function Root() {
  // An erased account restarts the app, so nothing of it stays in memory.
  const [session, setSession] = useState<{ generation: number; notice?: string }>({ generation: 0 });
  return (
    <AppearanceProvider load={loadAppearance} save={saveAppearance}>
      <App key={session.generation} notice={session.notice}
        onAccountErased={(notice) => setSession(({ generation }) => ({ generation: generation + 1, notice }))} />
    </AppearanceProvider>
  );
}
