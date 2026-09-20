import { File, Paths } from "expo-file-system";

import { parseAppearance, type Appearance } from "./appearance";

// Kept beside the database so it lives and dies with the app's data. Read
// synchronously so the very first frame is drawn in the chosen scheme.
const file = new File(Paths.document, "appearance");

export function loadAppearance(): Appearance {
  try {
    return parseAppearance(file.exists ? file.textSync() : null);
  } catch {
    return "system";
  }
}

export function saveAppearance(appearance: Appearance): void {
  try {
    if (!file.exists) file.create();
    file.write(appearance);
  } catch {
    // A choice that cannot be kept still applies for this session.
  }
}
