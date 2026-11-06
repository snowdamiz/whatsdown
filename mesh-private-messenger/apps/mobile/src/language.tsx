// The language everything renders in, handed to components through
// `useI18n`, as theme.ts hands out the theme.

import { Fragment, createContext, createElement, useContext, useState, type ReactNode } from "react";

import {
  english,
  resolveLanguage,
  resolveLocale,
  setCurrentLanguage,
  templateParts,
  type Language,
  type LanguageChoice,
  type Translate,
} from "./i18n";
import { deviceLocales, loadLanguageChoice, saveLanguageChoice } from "./language-store";

type I18n = {
  t: Translate;
  // The region dates and times are formatted for.
  locale: string;
  // What the user picked, and what the phone's own language resolves to.
  choice: LanguageChoice;
  systemLanguage: Language;
  setChoice: (next: LanguageChoice) => void;
};

const I18nContext = createContext<I18n>({
  t: english,
  locale: "en-US",
  choice: "system",
  systemLanguage: "en",
  setChoice: () => undefined,
});

export function useI18n(): I18n {
  return useContext(I18nContext);
}

// The phone's language is read once, at launch: changing it restarts the app
// on both phones.
export function LanguageProvider({ children }: { children: ReactNode }) {
  const [choice, setStored] = useState(loadLanguageChoice);
  const [locales] = useState(deviceLocales);
  const language = resolveLanguage(choice, locales);
  const locale = resolveLocale(language, locales);
  const value: I18n = {
    t: setCurrentLanguage(language, locale),
    locale,
    choice,
    systemLanguage: resolveLanguage("system", locales),
    setChoice: (next) => {
      setStored(next);
      saveLanguageChoice(next);
    },
  };
  return createElement(I18nContext.Provider, { value }, children);
}

// A translated sentence with parts set apart in it, such as a bold name:
// each `{part}` left in the text becomes the element given for it, so the
// translation decides where the parts go.
export function richText(text: string, parts: Record<string, ReactNode>): ReactNode[] {
  return templateParts(text).map((piece, index) =>
    typeof piece === "string"
      ? piece
      : createElement(Fragment, { key: index }, piece.part in parts ? parts[piece.part] : `{${piece.part}}`));
}
