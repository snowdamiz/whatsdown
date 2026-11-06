import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { collect, render } from './messages.mjs';

test('the catalog holds every literal the app translates, once, by first use', () => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-messages-'));
  try {
    const file = join(directory, 'Screen.tsx');
    writeFileSync(file, [
      'const title = msg("Chats");',
      'label={t("Delete account")} hint={t(\'It’s gone for good.\')}',
      'body={t(`Line one\\nline two`)}',
      't.plural("{count} member", "{count} members", count)',
      't("Delete account"); value.t("Not a message"); t(`Hi ${name}`);',
      '// A comment quoting t("Not a message") is not code.',
      '/* t("Nor is this") */',
    ].join('\n'));
    const entries = collect([file]);
    assert.deepEqual([...entries.keys()], ['Chats', 'Delete account', 'It’s gone for good.', 'Line one\nline two', '{count} members']);
    assert.deepEqual(entries.get('{count} members').value, { one: '{count} member', other: '{count} members' });
    assert.match(render(entries), /'It’s gone for good\.': 'It’s gone for good\.',/);
  } finally {
    rmSync(directory, { recursive: true });
  }
});

test('the English catalog matches the code', () => {
  const script = fileURLToPath(new URL('./messages.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, '--check'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('the CLI recognizes translated keys in real mixed-quote catalogs and still reports missing and unused keys', () => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'morse-catalog-report-')));
  try {
    const scripts = join(directory, 'scripts');
    const source = join(directory, 'src');
    mkdirSync(scripts);
    mkdirSync(source);
    copyFileSync(new URL('./messages.mjs', import.meta.url), join(scripts, 'messages.mjs'));
    cpSync(new URL('../src/locales', import.meta.url), join(source, 'locales'), { recursive: true });
    const languages = ['es', 'pt', 'fr', 'de', 'ru'];
    const escaped = 'A "quoted" catalog key\\suffix';
    const unused = 'An unused "quoted" catalog key';
    for (const language of languages) {
      const catalog = join(source, 'locales', `${language}.ts`);
      const original = readFileSync(catalog, 'utf8');
      assert.match(original, /\n};\s*$/);
      writeFileSync(catalog, original.replace(/\n};\s*$/, [
        `\n  ${JSON.stringify(escaped)}: 'Synthetic translation',`,
        `  ${JSON.stringify(unused)}: 'Unused synthetic translation',`,
        '};\n',
      ].join('\n')));
    }
    const used = ['Loading…', 'Morse is locked', 'Could not unlock. Your messages remain protected.', escaped,
      'One deliberately untranslated test message'];
    const screen = join(source, 'Screen.tsx');
    const report = () => {
      writeFileSync(screen, used.map(key => `t(${JSON.stringify(key)});`).join('\n'));
      const result = spawnSync(process.execPath, [join(scripts, 'messages.mjs')], { encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      return new Map(languages.map(language => {
        const line = result.stdout.split('\n').find(line => line.startsWith(`${language}: `));
        assert.ok(line, result.stdout);
        const counts = /^\w+: (\d+) to translate, (\d+) no longer used$/.exec(line);
        assert.ok(counts, line);
        assert.equal(Number(counts[1]), 1, line);
        return [language, Number(counts[2])];
      }));
    };
    const before = report();
    used.push(unused);
    const after = report();
    for (const language of languages) assert.equal(after.get(language), before.get(language) - 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
