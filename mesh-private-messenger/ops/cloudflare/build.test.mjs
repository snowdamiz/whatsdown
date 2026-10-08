import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { canaryConfig, compilerConfig, meshRevision } from './prepare-build.mjs';

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

test('the canary log deploys as its own backend with its own origin, log account and witnesses, and keeps the network crons', () => {
  const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
  const canary = canaryConfig(original);
  assert.equal(canary.name, 'morse-backend-canary');
  assert.deepEqual(canary.vars, { MORSE_LOG_ID: 'morse-canary', MESSENGER_TRANSPARENCY_LOG_ORIGIN: 'morseapp.io/log/canary',
    MORSE_ISOLATED_WITNESSES: '1', MORSE_ISOLATED_EDGE: '1' });
  assert.deepEqual(canary.containers.map(x => x.class_name), ['Directory', 'ObjectStore', 'PushBroker']);
  assert.ok(canary.durable_objects.bindings.some(x => x.name === 'NETWORK'));
  assert.ok(!canary.durable_objects.bindings.some(x => x.name.startsWith('WITNESS_') || x.name === 'PRIVACY_EDGE'));
  assert.notEqual(canary.r2_buckets[0].bucket_name, original.r2_buckets[0].bucket_name);
  assert.deepEqual(canary.triggers, original.triggers);
});

test('the image build context holds every directory the Dockerfile copies', () => {
  const dockerfile = readFileSync(new URL('./Dockerfile', import.meta.url), 'utf8');
  const included = readFileSync(new URL('./Dockerfile.dockerignore', import.meta.url), 'utf8').split('\n').filter(line => line.startsWith('!'));
  const copied = [...dockerfile.matchAll(/^COPY (mesh-private-messenger\/\S+)/gm)].map(match => match[1]);
  assert.ok(copied.length > 0);
  for (const path of copied) assert.ok(included.includes(`!${path}/**`), `${path} is excluded from the build context`);
});
