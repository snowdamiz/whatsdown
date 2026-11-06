import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  catalogs,
  english,
  languages,
  parseLanguageChoice,
  pluralCategory,
  pluralForms,
  resolveLanguage,
  resolveLocale,
  setCurrentLanguage,
  t as shared,
  templateParts,
  translator,
  type Language,
} from './i18n.ts';
import { en } from './locales/en.ts';

test('a saved choice is a supported language or the phone’s', () => {
  assert.equal(parseLanguageChoice('ru'), 'ru');
  assert.equal(parseLanguageChoice(' de '), 'de');
  assert.equal(parseLanguageChoice('system'), 'system');
  assert.equal(parseLanguageChoice('ja'), 'system');
  assert.equal(parseLanguageChoice(null), 'system');
});

test('the phone’s language is the first preference the app speaks', () => {
  assert.equal(resolveLanguage('system', ['ru-RU', 'en-US']), 'ru');
  // Portuguese of any region reads the Brazilian translation.
  assert.equal(resolveLanguage('system', ['pt-PT']), 'pt');
  assert.equal(resolveLanguage('system', ['es-MX']), 'es');
  // An unsupported first choice falls through to the next one listed.
  assert.equal(resolveLanguage('system', ['ja-JP', 'de-AT']), 'de');
  assert.equal(resolveLanguage('system', ['ja-JP']), 'en');
  assert.equal(resolveLanguage('system', []), 'en');
  // A choice made in the app wins over the phone.
  assert.equal(resolveLanguage('fr', ['ru-RU']), 'fr');
});

test('dates follow the phone’s region when it speaks the chosen language', () => {
  assert.equal(resolveLocale('en', ['en-GB', 'ru-RU']), 'en-GB');
  assert.equal(resolveLocale('ru', ['en-GB', 'ru-RU']), 'ru-RU');
  assert.equal(resolveLocale('de', ['en-GB']), 'de-DE');
});

test('plural categories follow each language’s rules', () => {
  assert.deepEqual([0, 1, 2, 5].map((n) => pluralCategory('en', n)), ['other', 'one', 'other', 'other']);
  // French and Brazilian Portuguese count zero as singular.
  assert.deepEqual([0, 1, 2].map((n) => pluralCategory('fr', n)), ['one', 'one', 'other']);
  assert.deepEqual([0, 1, 2].map((n) => pluralCategory('pt', n)), ['one', 'one', 'other']);
  assert.deepEqual(
    [1, 2, 4, 5, 11, 12, 14, 21, 22, 25, 101, 111].map((n) => pluralCategory('ru', n)),
    ['one', 'few', 'few', 'many', 'many', 'many', 'many', 'one', 'few', 'many', 'one', 'many'],
  );
});

test('a translator fills placeholders and picks the plural form', () => {
  const t = english;
  assert.equal(t('Welcome back'), 'Welcome back');
  assert.equal(t.plural('{count} member', '{count} members', 1), '1 member');
  assert.equal(t.plural('{count} member', '{count} members', 3), '3 members');
  const ru = translator('ru');
  assert.equal(ru.plural('{count} member', '{count} members', 2), '2 участника');
  assert.equal(ru.plural('{count} member', '{count} members', 5), '5 участников');
});

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
const forms = (entry: unknown) => (typeof entry === 'string' ? [entry] : Object.values(entry as object) as string[]);

for (const { code } of languages.filter((language) => language.code !== 'en')) {
  test(`${code} translates every message, keeping its placeholders`, () => {
    const catalog = catalogs[code as Language];
    const missing = Object.keys(en).filter((key) => !(key in catalog));
    assert.deepEqual(missing, [], `untranslated: ${missing.join(' | ')}`);
    const extra = Object.keys(catalog).filter((key) => !(key in en));
    assert.deepEqual(extra, [], `not in the English catalog: ${extra.join(' | ')}`);
    for (const [key, source] of Object.entries(en)) {
      const entry = (catalog as Record<string, unknown>)[key];
      const expected = placeholders(forms(source)[forms(source).length - 1]!);
      if (typeof source === 'string') {
        assert.equal(typeof entry, 'string', key);
      } else {
        assert.deepEqual(Object.keys(entry as object).sort(), [...pluralForms[code as Language]].sort(), key);
      }
      for (const form of forms(entry)) {
        assert.ok(form.trim().length > 0, `empty: ${key}`);
        assert.deepEqual(placeholders(form).filter((name) => name !== 'count'), expected.filter((name) => name !== 'count'), key);
      }
    }
  });
}

test('the shared translator follows the language set last', () => {
  setCurrentLanguage('ru');
  assert.equal(shared('Welcome back'), 'С возвращением');
  assert.equal(shared.language, 'ru');
  setCurrentLanguage('en');
  assert.equal(shared('Welcome back'), 'Welcome back');
});

test('a sentence splits around the parts it leaves to be filled', () => {
  assert.deepEqual(templateParts('Open {place} and choose {action}.'), ['Open ', { part: 'place' }, ' and choose ', { part: 'action' }, '.']);
  assert.deepEqual(templateParts('{action}, then {place}'), [{ part: 'action' }, ', then ', { part: 'place' }]);
  assert.deepEqual(templateParts('Nothing to fill'), ['Nothing to fill']);
});

test('the shared translator carries the region dates are set for', () => {
  setCurrentLanguage('en', 'en-GB');
  assert.equal(shared.locale, 'en-GB');
  setCurrentLanguage('de');
  assert.equal(shared.locale, 'de-DE');
  setCurrentLanguage('en');
  assert.equal(shared.locale, 'en-US');
});
