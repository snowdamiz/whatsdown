import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { compilerConfig } from './prepare-build.mjs';
import { spawnSync } from 'node:child_process';

test('C8 manual backend preparation rejects a compiler other than the repository pin', () => {
  const result = spawnSync(process.execPath, ['prepare-build.mjs'], {
    cwd: new URL('.', import.meta.url),
    env: { ...process.env, MESH_LANG_REVISION: 'f'.repeat(40) }, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /pinned Mesh revision/);
});

test('every container uses the resolved compiler commit and a new commit changes build arguments', () => {
  const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
  for (const revision of ['1'.repeat(40), '2'.repeat(40)]) {
    const config = compilerConfig(original, revision);
    assert.equal(config.containers.length, 6);
    for (const container of config.containers) assert.equal(container.image_vars.MESH_LANG_REVISION, revision);
    assert.deepEqual(config.durable_objects, original.durable_objects);
  }
  assert.equal(original.containers[0].image_vars, undefined);
  assert.throws(() => compilerConfig(original, 'main'), /commit SHA/);
  assert.throws(() => compilerConfig(original, ''), /commit SHA/);
});
