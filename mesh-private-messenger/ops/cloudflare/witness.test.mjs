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

test('C7 isolated witness calls reject redirects and cannot fall back to local signing', async () => {
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', WITNESS_A_INVOKE_TOKEN: token, WITNESS_B_INVOKE_TOKEN: 'b'.repeat(64), MORSE_ISOLATED_WITNESSES: '1' };
  let met = true;
  env.MESSENGER_DELIVERY_INTERNAL_TOKEN = token;
  env.DIRECTORY = { getByName: () => ({ fetch: async url => url.endsWith('/push-witnesses')
    ? Response.json({ witnesses: ['A', 'B'].map(name => ({ witness_id: `witness-${name.toLowerCase()}`, push_url: `${env[`WITNESS_${name}_URL`]}/attest` })) })
    : Response.json({ threshold_met: met }) }) };
  const urls = [];
  await attestWitnesses(env, async (url, init) => {
    urls.push(url.toString());
    assert.equal(init.redirect, 'manual');
    assert.equal(init.method, 'POST');
    return new Response(null, { status: 204 });
  });
  assert.deepEqual(urls.sort(), ['https://a.test/attest', 'https://b.test/attest']);
  met = false;
  await assert.rejects(attestWitnesses(env, async () => new Response(null, { status: 302 })), /threshold/);
  env.WITNESS_B_URL = 'http://b.test';
  await assert.rejects(attestWitnesses(env), /HTTPS witness endpoint/);
  const safe = directoryRequest(new Request('http://directory.internal/v1/transparency/checkpoint'), { MORSE_DIRECTORY_URL: 'https://directory.test' });
  assert.equal(safe.url, 'https://directory.test/v1/transparency/checkpoint');
  assert.equal(safe.redirect, 'manual');
  const rfc = directoryRequest(new Request('http://directory.internal/v2/transparency/legacy-bridge', {
    method: 'POST', body: 'query',
  }), { MORSE_DIRECTORY_URL: 'https://directory.test' });
  assert.equal(rfc?.url, 'https://directory.test/v2/transparency/legacy-bridge');
  assert.equal(rfc.method, 'POST');
  assert.equal(await rfc.text(), 'query');
  assert.equal(directoryRequest(new Request('http://directory.internal/internal/v1/jobs/directory'), { MORSE_DIRECTORY_URL: 'https://directory.test' }), null);
});

test('C7 isolated configurations give each witness only its own store and remove backend witness bindings', () => {
  const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url)));
  const env = { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://broker.test' };
  const delivery = isolatedConfig(original, env);
  // Directory, object store and report reader; witnesses, edge and broker deploy separately.
  assert.deepEqual(delivery.containers.map(x => x.class_name), ['Directory', 'ObjectStore', 'PublicReportReader']);
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


test('registry push fan-out supports arbitrary IDs, pull-only sets and an unavailable minority', async () => {
  let members = [{ witness_id: 'morse-west', push_url: 'https://west.test/attest' },
    { witness_id: 'morse-east', push_url: 'https://east.test/attest' }];
  let thresholdMet = true;
  const env = { MORSE_ISOLATED_WITNESSES: '1', MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    MESSENGER_WITNESS_PUSH_TOKENS: JSON.stringify({ 'morse-west': token, 'morse-east': 'b'.repeat(64) }),
    DIRECTORY: { getByName: () => ({ fetch: async (url, init) => {
      assert.equal(init.headers.Authorization, `Bearer ${token}`);
      if (url.endsWith('/push-witnesses')) return Response.json({ witnesses: members });
      assert.ok(url.endsWith('/witness-health'));
      return Response.json({ threshold_met: thresholdMet });
    } }) } };
  const reached = [];
  const fetcher = async (url, init) => {
    reached.push(url); assert.equal(init.redirect, 'manual');
    return new Response(null, { status: url.includes('west') ? 204 : 503 });
  };
  await attestWitnesses(env, fetcher);
  assert.deepEqual(reached.sort(), ['https://east.test/attest', 'https://west.test/attest']);
  thresholdMet = false;
  await assert.rejects(attestWitnesses(env, fetcher), /threshold/);
  members = []; thresholdMet = true; reached.length = 0;
  await attestWitnesses(env, fetcher);
  assert.deepEqual(reached, [], 'a pull-only registry must never call a built-in witness');
});

test('C2SP push jobs invoke the Mesh directory flow and honor the kill switch', async () => {
  const pushes = [];
  let ready = false;
  const env = { MORSE_C2SP_PUSH: 'on', MESSENGER_DELIVERY_INTERNAL_TOKEN: token, DIRECTORY: { getByName: () => ({ fetch: async (url, init) => {
    assert.equal(init.headers.Authorization, `Bearer ${token}`);
    if (url.endsWith('/push-witnesses')) return Response.json({ witnesses: [
      { witness_id: 'external', software: 'c2sp', push_url: 'https://external.test/add-checkpoint' },
    ] });
    if (url.endsWith('/c2sp-push')) {
      assert.equal(init.method, 'POST');
      assert.equal(init.body, 'external');
      pushes.push(url); ready = true;
      return new Response(null, { status: 204 });
    }
    assert.ok(url.endsWith('/witness-health'));
    return Response.json({ threshold_met: ready, log_version: 2 });
  } }) } };
  const report = await attestWitnesses(env, async () => { throw new Error('C2SP protocol belongs in Mesh'); });
  assert.deepEqual(pushes, ['http://service/internal/v2/transparency/c2sp-push']);
  assert.equal(report.push_failures, 0);
  env.MORSE_C2SP_PUSH = 'off';
  await attestWitnesses(env);
  assert.equal(pushes.length, 1, 'turning off C2SP pushes must not invoke its Mesh handler');
});
