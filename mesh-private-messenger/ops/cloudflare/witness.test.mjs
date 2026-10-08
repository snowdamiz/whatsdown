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
    // Deployed Workers hand a bodiless POST an empty stream, not null.
    [request('/attest', { Authorization: `Bearer ${token}` }, ''), 204],
  ]) assert.equal((await witnessRequest(req, env)).status, status);
  assert.equal(calls, 2);
  assert.equal((await witnessRequest(request('/attest'), { ...env, WITNESS_INVOKE_TOKEN: '' })).status, 503);
});

// An entry as the directory lists it; the defaults are what the legacy
// MESSENGER_WITNESS_{A,B}_PUBLIC_KEY_HEX seeding stores (no push_url).
const registryEntry = (witness_id, extra = {}) => ({ witness_id, public_key: '0'.repeat(64), operator: 'Morse', status: 'pinned',
  software: 'mesh', morse_run: true, c2sp_name: null, push_url: null, ...extra });
// The directory's internal push list (INTERFACES §7), as the jobs Worker reads it.
const directoryWith = (witnesses, seen = []) => ({ getByName: () => ({ fetch: async (url, init) => {
  seen.push([url, init.headers.Authorization]);
  return Response.json({ witnesses });
} }) });

test('C7 isolated witness calls reject redirects and cannot fall back to local signing', async () => {
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', WITNESS_A_INVOKE_TOKEN: token, WITNESS_B_INVOKE_TOKEN: 'b'.repeat(64), MORSE_ISOLATED_WITNESSES: '1',
    MESSENGER_DELIVERY_INTERNAL_TOKEN: 'd'.repeat(64), DIRECTORY: directoryWith([registryEntry('witness-a'), registryEntry('witness-b')]) };
  const urls = [];
  await attestWitnesses(env, async (url, init) => {
    urls.push(url.toString());
    assert.equal(init.redirect, 'manual');
    assert.equal(init.method, 'POST');
    return new Response(null, { status: 204 });
  });
  assert.deepEqual(urls.sort(), ['https://a.test/attest', 'https://b.test/attest']);
  await assert.rejects(attestWitnesses(env, async () => new Response(null, { status: 302 })), /attestation failed/);
  await assert.rejects(attestWitnesses({ ...env, WITNESS_B_URL: '' }, async () => new Response(null, { status: 204 })), /HTTPS origin/);
  const safe = directoryRequest(new Request('http://directory.internal/v1/transparency/checkpoint'), { MORSE_DIRECTORY_URL: 'https://directory.test' });
  assert.equal(safe.url, 'https://directory.test/v1/transparency/checkpoint');
  assert.equal(safe.redirect, 'manual');
  assert.equal(directoryRequest(new Request('http://directory.internal/internal/v1/jobs/directory'), { MORSE_DIRECTORY_URL: 'https://directory.test' }), null);
});

test('C7 isolated configurations give each witness only its own store and remove backend witness bindings', () => {
  const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url)));
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://push.test' };
  const delivery = isolatedConfig(original, env);
  // Directory and object store; witnesses, the privacy edge and the push broker deploy separately.
  assert.deepEqual(delivery.containers.map(x => x.class_name), ['Directory', 'ObjectStore']);
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

test('registry-driven witness jobs ask every configured Morse-run Mesh witness to sign; empty lists are normal', async () => {
  const seen = [];
  const calls = [];
  let down = null;
  const fetcher = async url => { calls.push(String(url)); return new Response(null, { status: String(url).includes(down) ? 503 : 204 }); };
  const env = { MORSE_ISOLATED_WITNESSES: '1', MESSENGER_DELIVERY_INTERNAL_TOKEN: 'd'.repeat(64),
    WITNESS_A_URL: 'https://a.test', WITNESS_A_INVOKE_TOKEN: token, WITNESS_B_URL: 'https://b.test', WITNESS_B_INVOKE_TOKEN: token };
  // Zero outside witnesses, and no witness at all.
  await attestWitnesses({ ...env, DIRECTORY: directoryWith([], seen) }, fetcher);
  assert.deepEqual(calls, []);
  assert.deepEqual(seen, [['http://service/internal/v1/transparency/push-witnesses', `Bearer ${'d'.repeat(64)}`]]);
  // The default registry: the legacy-seeded witness-a and witness-b, no push_url.
  await attestWitnesses({ ...env, DIRECTORY: directoryWith([registryEntry('witness-a'), registryEntry('witness-b')]) }, fetcher);
  assert.deepEqual(calls.sort(), ['https://a.test/attest', 'https://b.test/attest']);
  // A C2SP witness is pushed to elsewhere; a Morse witness with no /attest URL
  // runs in pull mode; a retired one is never asked.
  calls.length = 0;
  await attestWitnesses({ ...env, DIRECTORY: directoryWith([registryEntry('witness-b'),
    registryEntry('acme-1', { software: 'c2sp', morse_run: false, operator: 'Acme', c2sp_name: 'acme.example/w1', push_url: 'https://acme.example/w1/add-checkpoint' }),
    registryEntry('witness-c', { status: 'shadow' }), registryEntry('witness-a', { status: 'retired' })]) }, fetcher);
  assert.deepEqual(calls, ['https://b.test/attest']);
  // Combined development topology: the ID names the Durable Object binding.
  const attested = [];
  const bindings = { WITNESS_A: { getByName: () => ({ attest: async () => attested.push('a') }) } };
  await attestWitnesses({ ...bindings, DIRECTORY: directoryWith([registryEntry('witness-a'), registryEntry('witness-c')]) });
  assert.deepEqual(attested, ['a']);
  // One failing witness fails the job, after the others were asked; half a
  // configuration (a URL without its token) is an error, not pull mode.
  calls.length = 0;
  down = 'a.test';
  await assert.rejects(attestWitnesses({ ...env, DIRECTORY: directoryWith([registryEntry('witness-a'), registryEntry('witness-b')]) }, fetcher), /witness-a attestation failed/);
  assert.deepEqual(calls.sort(), ['https://a.test/attest', 'https://b.test/attest']);
  await assert.rejects(attestWitnesses({ ...env, WITNESS_B_INVOKE_TOKEN: undefined, DIRECTORY: directoryWith([registryEntry('witness-b')]) }, fetcher), /invocation token/);
});
