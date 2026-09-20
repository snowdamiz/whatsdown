import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { AndroidConfig, compileModsAsync } = require('@expo/config-plugins');
const withDataProtection = require('../plugins/with-data-protection.cjs');
const { dataExtractionRules, fullBackupContent, writeBackupRules } = withDataProtection;
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function application(seed = {}) {
  const config = await compileModsAsync(withDataProtection({
    name: 'Morse', slug: 'morse', android: { package: 'com.snowdamiz.morse', ...seed },
  }), { projectRoot, introspect: true, platforms: ['android'], ignoreExistingNativeFiles: true });
  return AndroidConfig.Manifest.getMainApplicationOrThrow(config._internal.modResults.android.manifest).$;
}

test('no OS backup or device transfer can carry the message database off the device', async () => {
  const attributes = await application();
  assert.equal(attributes['android:allowBackup'], 'false');
  // Android 12+ ignores allowBackup for device-to-device transfer; only explicit rules stop it.
  assert.equal(attributes['android:dataExtractionRules'], '@xml/morse_data_extraction_rules');
  assert.equal(attributes['android:fullBackupContent'], '@xml/morse_full_backup_content');
  // A permissive value seeded by another plugin or a template must not survive.
  assert.equal((await application({ allowBackup: true }))['android:allowBackup'], 'false');

  for (const section of ['cloud-backup', 'device-transfer']) {
    const block = dataExtractionRules.match(new RegExp(`<${section}[^>]*>([\\s\\S]*?)</${section}>`))?.[1] ?? '';
    for (const domain of ['root', 'file', 'database', 'sharedpref', 'external']) {
      assert.match(block, new RegExp(`<exclude domain="${domain}" path="\\."\\s*/>`), `${section} must exclude ${domain}`);
    }
    assert.doesNotMatch(block, /<include/);
  }
  for (const domain of ['root', 'file', 'database', 'sharedpref', 'external']) {
    assert.match(fullBackupContent, new RegExp(`<exclude domain="${domain}" path="\\."\\s*/>`));
  }
  assert.doesNotMatch(fullBackupContent, /<include/);
});

test('the backup rules the manifest names are written as Android XML resources', () => {
  const root = mkdtempSync(join(tmpdir(), 'morse-backup-rules-'));
  try {
    writeBackupRules(root);
    const xml = name => readFileSync(join(root, 'app/src/main/res/xml', name), 'utf8');
    assert.equal(xml('morse_data_extraction_rules.xml'), dataExtractionRules);
    assert.equal(xml('morse_full_backup_content.xml'), fullBackupContent);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
