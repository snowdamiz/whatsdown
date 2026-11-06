import { parseLanguageChoice, type LanguageChoice } from "./i18n";

// The desktop keeps the choice in its web view's own storage; nothing outside
// the window needs it before the page has loaded.
const key = "morse.language";

export function loadLanguageChoice(): LanguageChoice {
  try {
    return parseLanguageChoice(globalThis.localStorage?.getItem(key));
  } catch {
    return "system";
  }
}

export function saveLanguageChoice(choice: LanguageChoice): void {
  try {
    globalThis.localStorage?.setItem(key, choice);
  } catch {
    // A choice that cannot be kept still applies for this session.
  }
}

// The system's languages, most preferred first, as the web view reports them.
export function deviceLocales(): string[] {
  return typeof navigator === "undefined" ? [] : [...(navigator.languages ?? [navigator.language])];
}
