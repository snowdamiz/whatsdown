// The languages Morse speaks, and the words it uses in each.
//
// English is the source: every string the app shows is written in English in
// the code, wrapped in `t("…")` (or `msg("…")` where it is defined outside a
// component), and that English is the key it is looked up by. The English
// catalog is generated from those calls (`npm run messages`); each other
// language's catalog maps the same keys to its own words. Kept free of React
// so the choice, the rules and the catalogs can be tested.

import { de } from './locales/de.ts';
import { en } from './locales/en.ts';
import { es } from './locales/es.ts';
import { fr } from './locales/fr.ts';
import { pt } from './locales/pt.ts';
import { ru } from './locales/ru.ts';

export type Language = 'en' | 'es' | 'pt' | 'fr' | 'de' | 'ru';
// What the user picked: a language, or whatever the phone is set to.
export type LanguageChoice = Language | 'system';

// Each language is named in itself, so anyone can find their own in the list,
// and greets in itself in the picker. `locale` is the region dates are set
// in when the phone names no other.
export const languages: readonly { code: Language; name: string; greeting: string; locale: string }[] = [
  { code: 'en', name: 'English', greeting: 'Hello', locale: 'en-US' },
  { code: 'es', name: 'Español', greeting: 'Hola', locale: 'es-ES' },
  { code: 'pt', name: 'Português (Brasil)', greeting: 'Olá', locale: 'pt-BR' },
  { code: 'fr', name: 'Français', greeting: 'Bonjour', locale: 'fr-FR' },
  { code: 'de', name: 'Deutsch', greeting: 'Hallo', locale: 'de-DE' },
  { code: 'ru', name: 'Русский', greeting: 'Привет', locale: 'ru-RU' },
];

const isLanguage = (value: string): value is Language => languages.some((language) => language.code === value);
const languageOf = (locale: string) => locale.toLowerCase().split(/[-_]/)[0] ?? '';

export function parseLanguageChoice(saved: unknown): LanguageChoice {
  const value = typeof saved === 'string' ? saved.trim() : '';
  return isLanguage(value) ? value : 'system';
}

// The phone's preferences come in order; the first the app speaks wins, and
// English stands in when it speaks none of them.
export function resolveLanguage(choice: LanguageChoice, deviceLocales: readonly string[]): Language {
  if (choice !== 'system') return choice;
  for (const locale of deviceLocales) {
    const language = languageOf(locale);
    if (isLanguage(language)) return language;
  }
  return 'en';
}

// Dates and times keep the phone's own region (a 24-hour clock in Britain)
// when that region speaks the language chosen.
export function resolveLocale(language: Language, deviceLocales: readonly string[]): string {
  return deviceLocales.find((locale) => languageOf(locale) === language)
    ?? languages.find((entry) => entry.code === language)!.locale;
}

// ---------------------------------------------------------------- Plurals

export type PluralCategory = 'one' | 'few' | 'many' | 'other';

// The forms each language's catalog gives a counted phrase, after CLDR's
// rules for whole numbers. Counts in the app never reach the millions where
// French and Spanish take a further form.
export const pluralForms: Record<Language, readonly PluralCategory[]> = {
  en: ['one', 'other'],
  es: ['one', 'other'],
  pt: ['one', 'other'],
  fr: ['one', 'other'],
  de: ['one', 'other'],
  ru: ['one', 'few', 'many'],
};

export function pluralCategory(language: Language, count: number): PluralCategory {
  const n = Math.abs(Math.trunc(count));
  switch (language) {
    case 'fr':
    case 'pt':
      return n <= 1 ? 'one' : 'other';
    case 'ru': {
      const tens = n % 100;
      if (n % 10 === 1 && tens !== 11) return 'one';
      if (n % 10 >= 2 && n % 10 <= 4 && (tens < 12 || tens > 14)) return 'few';
      return 'many';
    }
    default:
      return n === 1 ? 'one' : 'other';
  }
}

// ---------------------------------------------------------------- Catalogs

export type MessageKey = keyof typeof en;
// The plural phrases, keyed by their English plural form.
export type PluralKey = { [K in MessageKey]: (typeof en)[K] extends string ? never : K }[MessageKey];
export type PluralEntry = Partial<Record<PluralCategory, string>>;
export type Catalog = Partial<Record<MessageKey, string | PluralEntry>>;

export const catalogs: Record<Language, Catalog> = { en, es, pt, fr, de, ru };

// Marks English defined outside a component, so the catalog generator finds
// it and the type checker knows it is a key; `t` translates it where shown.
export const msg = <K extends MessageKey>(key: K): K => key;

export type Vars = Record<string, string | number>;

export function interpolate(template: string, vars: Vars = {}): string {
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match));
}

// A sentence cut around the `{parts}` it leaves for elements, such as a bold
// name, so a translation can move them; the text between stays as it is.
export function templateParts(text: string): (string | { part: string })[] {
  return text
    .split(/(\{\w+\})/)
    .filter((piece) => piece !== '')
    .map((piece) => {
      const part = piece.match(/^\{(\w+)\}$/)?.[1];
      return part ? { part } : piece;
    });
}

export type Translate = {
  (key: MessageKey, vars?: Vars): string;
  // A counted phrase: its English singular and plural, the count, and any
  // other placeholders. The plural is the key; `{count}` is filled in.
  plural(one: string, other: PluralKey, count: number, vars?: Vars): string;
  language: Language;
  // The region dates and times are set for, such as en-GB for a 24-hour clock.
  locale: string;
};

const defaultLocale = (language: Language) => languages.find((entry) => entry.code === language)!.locale;

export function translator(language: Language, locale = defaultLocale(language)): Translate {
  const catalog = catalogs[language];
  const t = ((key: MessageKey, vars?: Vars) => {
    const entry = catalog[key] ?? en[key];
    return interpolate(typeof entry === 'string' ? entry : key, vars);
  }) as Translate;
  t.plural = (one, other, count, vars) => {
    const entry = (catalog[other] ?? en[other]) as PluralEntry | string | undefined;
    const category = pluralCategory(language, count);
    const english = count === 1 ? one : other;
    const form = typeof entry === 'object'
      ? entry[category] ?? entry.other ?? english
      : language === 'en' ? english : entry ?? english;
    return interpolate(form, { ...vars, count });
  };
  t.language = language;
  t.locale = locale;
  return t;
}

// Where no language is in hand: tests, and copy kept in English on purpose.
export const english = translator('en');

// The language in effect, for code outside components: error messages, day
// labels, notification text. LanguageProvider sets it before anything below
// it renders; a notification shown while the app is closed sets it from the
// saved choice. Components read it through `useI18n`, which also re-renders
// them when it changes.
let current: Translate = english;

export function setCurrentLanguage(language: Language, locale = defaultLocale(language)): Translate {
  if (current.language !== language || current.locale !== locale) current = translator(language, locale);
  return current;
}

export const t = ((key: MessageKey, vars?: Vars) => current(key, vars)) as Translate;
t.plural = (one, other, count, vars) => current.plural(one, other, count, vars);
Object.defineProperty(t, 'language', { get: () => current.language });
Object.defineProperty(t, 'locale', { get: () => current.locale });
