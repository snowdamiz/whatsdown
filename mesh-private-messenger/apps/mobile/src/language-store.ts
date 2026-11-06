import { File, Paths } from "expo-file-system";
import { getLocales } from "expo-localization";

import { parseLanguageChoice, type LanguageChoice } from "./i18n";

// Kept beside the appearance, per device rather than per account, since it
// is chosen before there is an account. Read synchronously so the first
// frame, and a notification shown while the app is closed, are already in it.
const file = new File(Paths.document, "language");

export function loadLanguageChoice(): LanguageChoice {
  try {
    return parseLanguageChoice(file.exists ? file.textSync() : null);
  } catch {
    return "system";
  }
}

export function saveLanguageChoice(choice: LanguageChoice): void {
  try {
    if (!file.exists) file.create();
    file.write(choice);
  } catch {
    // A choice that cannot be kept still applies for this session.
  }
}

// The phone's languages, most preferred first.
export function deviceLocales(): string[] {
  try {
    return getLocales().map((locale) => locale.languageTag);
  } catch {
    return [];
  }
}
