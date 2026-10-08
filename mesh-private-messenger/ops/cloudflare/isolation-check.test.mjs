import assert from 'node:assert/strict';
import test from 'node:test';
import { isolationCheck, report } from './isolation-check.mjs';

const ids = ['backend', 'edge', 'push-broker', 'witness-a', 'witness-b'];
const envName = id => id.toUpperCase().replace('-', '_');
const pin = 'ab'.repeat(32);

// Five accounts as the cutover leaves them. Tokens look like real ones so a
// leak into the report would be caught.
function world() {
  const account = Object.fromEntries(ids.map((id, index) => [id, String(index + 1).repeat(32)]));
  const token = Object.fromEntries(ids.map(id => [id, `cf-${id}-${'Z'.repeat(40)}`]));
  const witness = name => ({
    scripts: { [`morse-witness-${name}`]: {
      secrets: ['MESSENGER_WITNESS_SIGNING_SEED_HEX', 'MESSENGER_WITNESS_PUBLIC_KEY_HEX', 'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX', 'WITNESS_INVOKE_TOKEN'],
      bindings: [{ type: 'durable_object_namespace', name: 'WITNESS' }, { type: 'durable_object_namespace', name: 'WITNESS_STATE' },
        { type: 'plain_text', name: 'MESSENGER_WITNESS_ID', text: `witness-${name}` }, { type: 'plain_text', name: 'MORSE_DIRECTORY_URL', text: 'https://api.morse.test' }],
    } },
    containers: [{ name: `morse-witness-${name}-isolatedwitness` }], buckets: [],
  });
  const resources = {
    [account.backend]: {
      scripts: { 'morse-backend': {
        secrets: ['MESSENGER_DATABASE_URL', 'OBJECT_DATABASE_URL', 'MESSENGER_DELIVERY_SEALING_SEED_HEX', 'MESSENGER_DELIVERY_INTERNAL_TOKEN',
          'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX', 'WITNESS_A_INVOKE_TOKEN', 'MORSE_FEE_PAYER_KEYPAIR'],
        bindings: [{ type: 'durable_object_namespace', name: 'DIRECTORY' }, { type: 'durable_object_namespace', name: 'JOBS' },
          { type: 'r2_bucket', name: 'OBJECTS' }, { type: 'plain_text', name: 'MORSE_INGRESS_CLIENT_CERT_SHA256', text: pin }],
      } },
      containers: [{ name: 'morse-backend-directory' }, { name: 'morse-backend-objectstore' }], buckets: ['morse-encrypted-objects'],
    },
    [account.edge]: {
      scripts: { 'morse-privacy-edge': {
        secrets: ['MESSENGER_DELIVERY_INTERNAL_TOKEN'],
        bindings: [{ type: 'durable_object_namespace', name: 'PRIVACY_EDGE' }, { type: 'mtls_certificate', name: 'DELIVERY_CLIENT_CERT', certificate_id: 'x' },
          { type: 'plain_text', name: 'MORSE_DELIVERY_URL', text: 'https://ingress.morse.test' }],
      } },
      containers: [{ name: 'morse-privacy-edge-isolatedprivacyedge' }], buckets: [],
    },
    [account['push-broker']]: {
      scripts: { 'morse-push-broker': {
        secrets: ['MESSENGER_PUSH_BROKER_SEED_HEX', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'PUSH_DATABASE_URL'],
        bindings: [{ type: 'durable_object_namespace', name: 'PUSH_BROKER' }, { type: 'durable_object_namespace', name: 'JOBS' }],
      } },
      containers: [{ name: 'morse-push-broker-isolatedpushbroker' }], buckets: [],
    },
    [account['witness-a']]: witness('a'),
    [account['witness-b']]: witness('b'),
  };
  const access = Object.fromEntries(ids.map(id => [token[id], [account[id]]]));
  const env = Object.fromEntries(ids.flatMap(id => [
    [`MORSE_ISOLATION_${envName(id)}_TOKEN`, token[id]], [`MORSE_ISOLATION_${envName(id)}_ACCOUNT_ID`, account[id]]]));
  const failing = new Set();
  const calls = [];
  const json = (status, result) => new Response(JSON.stringify({ success: status === 200, result,
    errors: status === 200 ? [] : [{ code: 10000, message: 'Authentication error' }] }), { status });
  async function fetcher(url, init) {
    const { pathname } = new URL(url);
    assert.equal(init.method ?? 'GET', 'GET', 'the checks are read-only');
    const bearer = init.headers.Authorization.slice('Bearer '.length);
    calls.push(pathname);
    if (failing.has(pathname)) return json(500, null);
    const path = pathname.replace('/client/v4', '');
    if (path === '/accounts') return json(200, (access[bearer] ?? []).map(id => ({ id })));
    const [, , id, ...rest] = path.split('/');
    if (!access[bearer]?.includes(id)) return json(403, null);
    const store = resources[id];
    const route = rest.join('/');
    if (route === 'workers/scripts') return json(200, Object.keys(store.scripts).map(name => ({ id: name })));
    if (route === 'containers/applications') return json(200, store.containers);
    if (route === 'r2/buckets') return json(200, { buckets: store.buckets.map(name => ({ name })) });
    const script = /^workers\/scripts\/([^/]+)\/(secrets|settings)$/.exec(route);
    if (script && store.scripts[script[1]]) {
      const { secrets, bindings } = store.scripts[script[1]];
      return json(200, script[2] === 'secrets' ? secrets.map(name => ({ name, type: 'secret_text' })) : { bindings });
    }
    return json(404, null);
  }
  return { account, token, resources, access, env, fetcher, failing, calls };
}

const failures = results => results.filter(x => !x.ok).map(x => `${x.deployment}: ${x.check}`);

test('M1 separately held accounts pass every reach and denial check, and the report never shows a token', async () => {
  const w = world();
  const results = await isolationCheck(w.env, w.fetcher);
  assert.deepEqual(failures(results), []);
  // Every deployment was denied every other deployment's Worker, containers and stores.
  for (const id of ids) for (const other of ids.filter(x => x !== id)) {
    assert.ok(results.some(x => x.deployment === id && x.check === `denied ${other}` && x.ok), `${id} denied ${other}`);
  }
  const text = report(results);
  for (const value of Object.values(w.token)) assert.ok(!text.includes(value) && !JSON.stringify(results).includes(value));
  assert.match(text, /^PASS/m);
});

test('M1 an edge in the backend account, or a token that reaches two accounts, fails', async () => {
  const shared = world();
  shared.env.MORSE_ISOLATION_EDGE_ACCOUNT_ID = shared.account.backend;
  shared.access[shared.token.edge] = [shared.account.backend];
  shared.resources[shared.account.backend].scripts['morse-privacy-edge'] = shared.resources[shared.account.edge].scripts['morse-privacy-edge'];
  const results = failures(await isolationCheck(shared.env, shared.fetcher));
  assert.ok(results.includes('edge: denied backend'), results.join('\n'));
  assert.ok(results.includes('backend: denied edge'));
  assert.ok(results.includes('backend: only its own Workers'));

  const wide = world();
  wide.access[wide.token.edge].push(wide.account.backend);
  const wideFailures = failures(await isolationCheck(wide.env, wide.fetcher));
  assert.ok(wideFailures.includes('edge: reaches only its own account'));
  assert.ok(wideFailures.includes('edge: denied backend'));
});

test('M1 secrets, bindings or containers held by the wrong deployment fail', async () => {
  const w = world();
  w.resources[w.account.backend].scripts['morse-backend'].secrets.push('MESSENGER_PUSH_BROKER_SEED_HEX');
  w.resources[w.account.backend].containers.push({ name: 'morse-backend-pushbroker' });
  w.resources[w.account.edge].scripts['morse-privacy-edge'].secrets.push('MESSENGER_DATABASE_URL');
  w.resources[w.account['push-broker']].scripts['morse-push-broker'].bindings.push({ type: 'r2_bucket', name: 'OBJECTS' });
  assert.deepEqual(failures(await isolationCheck(w.env, w.fetcher)), [
    'backend: secrets', 'backend: containers', 'edge: secrets', 'push-broker: bindings',
  ]);
});

test('M1 an unanswered denial probe or a dead token is a failure, not a pass', async () => {
  const w = world();
  w.failing.add(`/client/v4/accounts/${w.account.backend}/r2/buckets`);
  const results = failures(await isolationCheck(w.env, w.fetcher));
  assert.ok(results.includes('edge: denied backend'), 'a 500 proves nothing about denial');
  assert.ok(results.includes('backend: stores'));

  const dead = world();
  dead.access[dead.token['witness-b']] = [];
  const deadFailures = failures(await isolationCheck(dead.env, dead.fetcher));
  assert.ok(deadFailures.includes('witness-b: reaches only its own account'));
  assert.ok(deadFailures.includes('witness-b: own Worker'));
});

test('M1 the check reports M2 until the edge certificate and the backend pin are configured', async () => {
  const w = world();
  const backend = w.resources[w.account.backend].scripts['morse-backend'];
  backend.bindings = backend.bindings.filter(x => x.name !== 'MORSE_INGRESS_CLIENT_CERT_SHA256');
  const edge = w.resources[w.account.edge].scripts['morse-privacy-edge'];
  edge.bindings = edge.bindings.filter(x => x.type !== 'mtls_certificate');
  assert.deepEqual(failures(await isolationCheck(w.env, w.fetcher)), ['backend: M2 ingress pin', 'edge: M2 edge credential']);
  // The signed-request path satisfies M2 on its own: a pinned public key on the
  // backend, the signing key as the edge's secret.
  backend.bindings.push({ type: 'plain_text', name: 'MORSE_EDGE_INGRESS_PUBLIC_KEY', text: 'cd'.repeat(32) });
  edge.secrets.push('MORSE_EDGE_INGRESS_SIGNING_KEY');
  assert.deepEqual(failures(await isolationCheck(w.env, w.fetcher)), []);
  // The backend must never hold the edge's certificate or signing key itself.
  backend.bindings.push({ type: 'mtls_certificate', name: 'DELIVERY_CLIENT_CERT', certificate_id: 'x' });
  backend.secrets.push('MORSE_EDGE_INGRESS_SIGNING_KEY');
  assert.deepEqual(failures(await isolationCheck(w.env, w.fetcher)), ['backend: secrets', 'backend: bindings']);
});

test('M1 each credential holder runs the check with only their own token and the others\' account IDs', async () => {
  const w = world();
  const env = Object.fromEntries(Object.entries(w.env).filter(([name]) => !name.endsWith('_TOKEN') || name === 'MORSE_ISOLATION_EDGE_TOKEN'));
  const results = await isolationCheck(env, w.fetcher);
  assert.deepEqual([...new Set(results.map(x => x.deployment))], ['edge']);
  assert.deepEqual(failures(results), []);
  assert.ok(results.some(x => x.check === 'denied backend' && x.ok));
  assert.match(report(results), /checked: edge; not checked here: backend, push-broker, witness-a, witness-b/);
});

test('M1 missing credentials are named without printing any value', async () => {
  const w = world();
  const tokenless = Object.fromEntries(Object.entries(w.env).filter(([name]) => !name.endsWith('_TOKEN')));
  await assert.rejects(isolationCheck(tokenless, w.fetcher), /Set at least one MORSE_ISOLATION_<ID>_TOKEN/);
  w.env.MORSE_ISOLATION_EDGE_ACCOUNT_ID = 'not-an-account';
  await assert.rejects(isolationCheck(w.env, w.fetcher), error => {
    assert.match(error.message, /MORSE_ISOLATION_EDGE_ACCOUNT_ID/);
    for (const value of Object.values(w.token)) assert.ok(!error.message.includes(value));
    return true;
  });
  assert.equal(w.calls.length, 0);
});
