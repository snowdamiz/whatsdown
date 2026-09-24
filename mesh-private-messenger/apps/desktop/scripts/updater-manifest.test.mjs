import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { releases, updaterManifest } from './updater-manifest.mjs';

const config = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));

test('installed apps look for the manifest the release job publishes', () => {
  assert.deepEqual(config.plugins.updater.endpoints, [`${releases}/latest/download/latest.json`]);
});

test('the manifest points each platform at its signed bundle in the release', () => {
  const dir = mkdtempSync(join(tmpdir(), 'morse-manifest-'));
  try {
    for (const name of ['Morse_0.1.30_aarch64.app.tar.gz', 'Morse_0.1.30_x64.app.tar.gz', 'Morse_0.1.30_x64-setup.exe']) {
      writeFileSync(join(dir, `${name}.sig`), `sig-${name}\n`);
    }
    const base = `${releases}/download/desktop-v0.1.30`;
    assert.deepEqual(updaterManifest(dir, '0.1.30'), {
      version: '0.1.30',
      platforms: {
        'darwin-aarch64': { signature: 'sig-Morse_0.1.30_aarch64.app.tar.gz', url: `${base}/Morse_0.1.30_aarch64.app.tar.gz` },
        'darwin-x86_64': { signature: 'sig-Morse_0.1.30_x64.app.tar.gz', url: `${base}/Morse_0.1.30_x64.app.tar.gz` },
        'windows-x86_64': { signature: 'sig-Morse_0.1.30_x64-setup.exe', url: `${base}/Morse_0.1.30_x64-setup.exe` },
      },
    });

    // A platform without its signature would never update, so the release fails instead.
    rmSync(join(dir, 'Morse_0.1.30_x64-setup.exe.sig'));
    assert.throws(() => updaterManifest(dir, '0.1.30'), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
