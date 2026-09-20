import assert from 'node:assert/strict';
import test from 'node:test';
import { initializeWitness, attestWitnesses, witnessRequest, directoryRequest } from './witness.mjs';
import { isolatedConfig, witnessConfig } from './prepare-build.mjs';
import { readFileSync } from 'node:fs';

const token = 'a'.repeat(64);
test('C7 witness invocation cannot sign supplied data, read checkpoints, or bypass authentication', async () => {
  let calls = 0;
  const env = { WITNESS_INVOKE_TOKEN: token, WITNESS: { getByName: () => ({ attest: async () => { calls++; } }) } };
  const request = (path, headers = {}, body) => new Request(`https://witness.test${path}`, { method: 'POST', headers, body });
  for (const [req, status] of [
    [request('/attest'), 401],
    [request('/attest', { Authorization: `Bearer ${'é'.repeat(64)}` }), 401],
    [request('/attest', { Authorization: `Bearer ${'b'.repeat(64)}` }), 401],
    [request('/checkpoint', { Authorization: `Bearer ${token}` }), 404],
    [request('/attest?checkpoint=forged', { Authorization: `Bearer ${token}` }), 404],
    [request('/attest', { Authorization: `Bearer ${token}` }, 'forged'), 400],
    [request('/attest', { Authorization: `Bearer ${token}` }), 204],
  ]) assert.equal((await witnessRequest(req, env)).status, status);
  assert.equal(calls, 1);
  assert.equal((await witnessRequest(request('/attest'), { ...env, WITNESS_INVOKE_TOKEN: '' })).status, 503);
});

test('C7 isolated witness calls reject redirects and cannot fall back to local signing', async () => {
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', WITNESS_A_INVOKE_TOKEN: token, WITNESS_B_INVOKE_TOKEN: 'b'.repeat(64), MORSE_ISOLATED_WITNESSES: '1' };
  const urls = [];
  await attestWitnesses(env, async (url, init) => {
    urls.push(url.toString());
    assert.equal(init.redirect, 'manual');
    assert.equal(init.method, 'POST');
    return new Response(null, { status: 204 });
  });
  assert.deepEqual(urls.sort(), ['https://a.test/attest', 'https://b.test/attest']);
  await assert.rejects(attestWitnesses(env, async () => new Response(null, { status: 302 })), /attestation failed/);
  await assert.rejects(attestWitnesses({ ...env, WITNESS_B_URL: '' }), /HTTPS origin/);
  const safe = directoryRequest(new Request('http://directory.internal/v1/transparency/checkpoint'), { MORSE_DIRECTORY_URL: 'https://directory.test' });
  assert.equal(safe.url, 'https://directory.test/v1/transparency/checkpoint');
  assert.equal(safe.redirect, 'manual');
  assert.equal(directoryRequest(new Request('http://directory.internal/internal/v1/jobs/directory'), { MORSE_DIRECTORY_URL: 'https://directory.test' }), null);
});

test('C7 isolated configurations give each witness only its own store and remove backend witness bindings', () => {
  const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url)));
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test' };
  const delivery = isolatedConfig(original, env);
  // Directory, object store, and push broker; witnesses and the privacy edge deploy separately.
  assert.deepEqual(delivery.containers.map(x => x.class_name), ['Directory', 'ObjectStore', 'PushBroker']);
  assert.ok(delivery.durable_objects.bindings.every(x => !x.name.startsWith('WITNESS')));
  assert.deepEqual(delivery.migrations, original.migrations, 'existing checkpoint stores must not be deleted during cutover');
  assert.throws(() => isolatedConfig(original, { ...env, WITNESS_B_URL: env.WITNESS_A_URL }), /distinct/);
  for (const name of ['a', 'b']) {
    const config = witnessConfig(original, name, { MORSE_DIRECTORY_URL: 'https://directory.test' });
    assert.equal(config.name, `morse-witness-${name}`);
    assert.equal(config.containers.length, 1);
    assert.deepEqual(config.durable_objects.bindings.map(x => x.name), ['WITNESS', 'WITNESS_STATE']);
    assert.equal(config.r2_buckets, undefined);
  }
});

test('C5 a separated witness requires an explicit checkpoint transfer and never overwrites existing continuity', async () => {
  let state;
  const requests = [];
  const env = { WITNESS_STATE: { getByName: () => ({ fetch: async (url, init) => {
    requests.push(init?.method ?? 'GET');
    if (init?.method === 'PUT') { assert.equal(init.headers['If-Match'], 'none'); state = init.body; return new Response(null, { status: 204 }); }
    return new Response(state, { status: state ? 200 : 404 });
  } }) } };
  await assert.rejects(initializeWitness(env), /checkpoint transfer/);
  env.WITNESS_INITIAL_CHECKPOINT_HEX = '05'.repeat(188);
  await initializeWitness(env);
  assert.equal(state.byteLength, 188);
  delete env.WITNESS_INITIAL_CHECKPOINT_HEX;
  await initializeWitness(env);
  assert.equal(requests.filter(x => x === 'PUT').length, 1);
});
