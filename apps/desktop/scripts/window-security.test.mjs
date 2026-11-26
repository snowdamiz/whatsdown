import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const config = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));

test('every window is excluded from screenshots, recordings, and screen sharing', () => {
  assert.ok(config.app.windows.length > 0);
  for (const window of config.app.windows) {
    // NSWindowSharingNone on macOS, WDA_EXCLUDEFROMCAPTURE on Windows.
    assert.equal(window.contentProtected, true, `window ${window.label} must be content-protected`);
  }
});
