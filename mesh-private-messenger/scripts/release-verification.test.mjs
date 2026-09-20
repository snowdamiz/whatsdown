import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('C8 publication requires successful verification of both exact commits, including OTA', () => {
  const valid = {
    GITHUB_SHA: 'a'.repeat(40), MESH_LANG_REVISION: 'b'.repeat(40),
    VERIFIED_MORSE_REVISION: 'a'.repeat(40), VERIFIED_MESH_REVISION: 'b'.repeat(40),
    VERIFICATION_RESULT: 'success',
  };
  const run = overrides => spawnSync(process.execPath, [new URL('./release-verification.mjs', import.meta.url).pathname], {
    env: { PATH: process.env.PATH, ...valid, ...overrides }, encoding: 'utf8',
  });
  assert.equal(run({}).status, 0);
  for (const status of ['', 'failure', 'cancelled', 'skipped', 'in_progress']) {
    assert.notEqual(run({ VERIFICATION_RESULT: status }).status, 0, status);
  }
  for (const key of ['GITHUB_SHA', 'MESH_LANG_REVISION', 'VERIFIED_MORSE_REVISION', 'VERIFIED_MESH_REVISION']) {
    for (const value of ['', 'main', 'c'.repeat(40)]) {
      assert.notEqual(run({ [key]: value }).status, 0, key);
    }
  }
});
