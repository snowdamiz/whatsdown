import { File, Paths } from "expo-file-system";

import { parseAppearance, type Appearance } from "./appearance";
import { settings } from "./sealed-journals";

// Sealed by the core in the app's database, like the other settings, so it
// lives and dies with the app's data. The `appearance` file beside it is where
// an older build kept the choice in the clear: moved in once, then removed.
const file = new File(Paths.document, "appearance");

export async function loadAppearance(): Promise<Appearance> {
  try {
    return parseAppearance(await settings.load("appearance", {
      read: () => (file.exists ? file.textSync() : null),
      remove: () => { if (file.exists) file.delete(); },
    }));
  } catch {
    return "system";
  }
}

export function saveAppearance(appearance: Appearance): void {
  // A choice that cannot be kept still applies for this session.
  void settings.save("appearance", appearance).catch(() => undefined);
}
