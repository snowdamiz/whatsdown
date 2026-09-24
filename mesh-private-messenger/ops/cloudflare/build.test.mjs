import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { compilerConfig, meshRevision } from './prepare-build.mjs';

test('C8 a release deploys the Mesh commit its verification used; other builds take the latest release', async () => {
  const latestRelease = async () => '1'.repeat(40);
  assert.equal(await meshRevision({ MESH_LANG_REVISION: '2'.repeat(40) }, latestRelease), '2'.repeat(40));
  assert.equal(await meshRevision({}, latestRelease), '1'.repeat(40));
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
