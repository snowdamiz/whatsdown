import { invoke } from "@tauri-apps/api/core";

import { parseAppearance, type Appearance } from "./appearance";

// The desktop shell keeps the choice: it needs it before the web view has
// loaded, to open the window with the right theme and canvas, and it applies
// each change to the window as it is saved.
export function loadAppearance(): Promise<Appearance> {
  return invoke<string>("appearance").then(parseAppearance);
}

export function saveAppearance(appearance: Appearance): void {
  void invoke("set_appearance", { appearance }).catch(() => undefined);
}
