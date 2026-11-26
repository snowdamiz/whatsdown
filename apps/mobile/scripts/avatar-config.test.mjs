import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('adding photo selection preserves QR camera access without requesting microphone access', () => {
  const cwd = fileURLToPath(new URL('../', import.meta.url));
  const config = JSON.parse(execFileSync(process.execPath, ['node_modules/expo/bin/cli', 'config', '--type', 'introspect', '--json'], { cwd, encoding: 'utf8' }));
  const ios = config._internal.modResults.ios.infoPlist;
  assert.ok(ios.NSCameraUsageDescription, 'QR scanning still needs a camera purpose string');
  assert.ok(ios.NSPhotoLibraryUsageDescription);
  assert.equal(ios.NSMicrophoneUsageDescription, undefined);
  const permissions = config._internal.modResults.android.manifest.manifest['uses-permission'];
  assert.ok(permissions.some((permission) => permission.$['android:name'] === 'android.permission.CAMERA' && permission.$['tools:node'] !== 'remove'));
});
