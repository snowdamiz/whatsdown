import assert from 'node:assert/strict';
import test from 'node:test';
import { publicRoute, publicHealth } from './routing.mjs';

test('public ingress routes each API and excludes private endpoints including encoded paths', () => {
  const route = (path, method = 'POST', headers) => publicRoute(new Request(`https://morse.example${path}`, { method, headers }));
  assert.equal(route('/v1/envelopes/batch'), 'PRIVACY_EDGE');
  assert.equal(route('/v1/mailbox/fetch'), 'DIRECTORY');
  assert.equal(route('/v1/mailbox/stream', 'GET', { Upgrade: 'websocket' }), 'STREAM');
  assert.equal(route('/v1/mailbox/stream', 'GET'), null);
  assert.equal(route('/v1/attachments/grant'), 'OBJECT_STORE');
  assert.equal(route(`/v1/objects/${'a'.repeat(64)}/parts/0`, 'PUT'), 'OBJECT_STORE');
  for (const path of ['/internal/v1/envelopes/sealed', '/internal/v1/push', '/%69nternal/v1/push', '/checkpoint']) {
    assert.equal(route(path), null);
  }
  assert.equal(route('/v1/envelopes/batch', 'GET'), null);
  // The unauthenticated single-device directory is retired at every layer.
  assert.equal(route('/v1/directory/register', 'PUT'), null);
  assert.equal(route('/v1/directory/resolve', 'POST'), null);
  assert.equal(route('/v1/directory/resolve', 'GET'), null);
  assert.equal(route('/v1/devices/register', 'PUT'), 'DIRECTORY');
  assert.equal(route('/v1/devices/resolve', 'POST'), 'DIRECTORY');
  assert.equal(route('/v1/accounts/delete', 'POST'), 'DIRECTORY');
  assert.equal(route('/v1/accounts/delete', 'GET'), null);
  assert.equal(route('/v1/devices/leave', 'POST'), 'DIRECTORY');
});

test('public health reports cached job failures without starting services or signers', async () => {
  let failures = 0;
  let observed = Date.now();
  const env = { JOBS: { getByName: kind => ({ status: async () => ({ pending: 0, due: 0, failures,
    ...(kind === 'witness' ? { witness: { threshold_met: true, threshold: 2, valid_signatures: 2,
      checkpoint_age_ms: 10, anchor_lag_ms: null, witnesses: [], observed_at: observed } } : {}) }) }) } };
  for (const binding of ['DIRECTORY', 'PRIVACY_EDGE', 'OBJECT_STORE', 'PUSH_BROKER', 'WITNESS_A', 'WITNESS_B']) {
    Object.defineProperty(env, binding, { get() { throw new Error('public probe activated ' + binding); } });
  }
  const healthy = await publicHealth(env);
  assert.equal(healthy.status, 200);
  assert.equal((await healthy.json()).witness.threshold_met, true);
  failures = 1;
  assert.equal((await publicHealth(env)).status, 503);
  failures = 0; observed -= 300_001;
  const stale = await publicHealth(env);
  assert.equal(stale.status, 503);
  assert.equal((await stale.json()).witness.threshold_met, false);
});

test('RFC endpoints route separately while cutover controls stay private', () => {
  const route = (path, method) => publicRoute(new Request(`https://morse.example${path}`, { method }));
  for (const path of ['/v1/transparency/checkpoint.note', '/v2/transparency/checkpoint.note',
    '/v2/transparency/checkpoint', '/v2/transparency/witnesses']) {
    assert.equal(route(path, 'GET'), 'DIRECTORY');
  }
  for (const path of ['/v2/transparency/consistency', '/v2/transparency/inclusion']) {
    assert.equal(route(path, 'GET'), 'DIRECTORY');
    assert.equal(route(path, 'POST'), 'DIRECTORY');
  }
  for (const version of [1, 2]) {
    assert.equal(route(`/v${version}/transparency/checkpoint`, 'POST'), 'DIRECTORY');
    assert.equal(route(`/v${version}/transparency/checkpoint`, 'PUT'), null);
    assert.equal(route(`/v${version}/transparency/leaf`, 'POST'), 'DIRECTORY');
    assert.equal(route(`/v${version}/transparency/leaf`, 'GET'), null);
  }
  for (const path of ['/v2/devices/resolve', '/v2/transparency/legacy-bridge', '/v2/transparency/witnesses']) {
    assert.equal(route(path, 'POST'), 'DIRECTORY');
  }
  for (const path of ['/v2/transparency/cutover', '/v2/devices/register', '/internal/v2/transparency/cutover',
    '/internal/v2/transparency/c2sp-push']) {
    assert.equal(route(path, 'POST'), null);
  }
});

test('anchor health ages the independent cached job without invoking a signer',async()=> {
  const now=Date.now();
  let anchor={mode:'devnet',observedAt:now,issues:[],pending:2,fee:{level:'healthy',balanceLamports:'500000000'},
    alert:{configured:true,pending:false},lastPost:{version:2,sequence:'12',treeSize:'7',checkpointHash:'ab'.repeat(32),slot:'100',ringIndex:4}};
  const queried=[];
  const env={MORSE_ANCHOR_MODE:'devnet',JOBS:{getByName:kind=>({status:async()=> {
    queried.push(kind);return {failures:0,...(kind==='anchor'?{anchor}:{}),...(kind==='witness'?{witness:{
      observed_at:now,threshold_met:true,checkpoint_age_ms:0,witnesses:[]}}:{})};
  }})}};
  let response=await publicHealth(env),body=await response.json();
  assert.equal(response.status,200);assert.ok(queried.includes('anchor'));
  assert.equal(body.anchor.last_post.sequence,'12');assert.equal(body.anchor.pending_transactions,2);
  anchor={...anchor,observedAt:now-120_001};response=await publicHealth(env);body=await response.json();
  assert.equal(response.status,503);assert.equal(body.services.anchor,false);
  anchor={...anchor,observedAt:now,issues:['clock_skew']};assert.equal((await publicHealth(env)).status,503);
  anchor=undefined;assert.equal((await publicHealth(env)).status,503);
  queried.length=0;env.MORSE_ANCHOR_MODE='off';response=await publicHealth(env);
  assert.equal(response.status,200);assert.equal((await response.json()).anchor.mode,'off');
  assert.ok(!queried.includes('anchor'),'disabled writers do not need an initialized job');
});

test('anchor receipt discovery accepts only bounded canonical GET coordinates and keeps writes private', () => {
  const route = (path, method = 'GET') => publicRoute(new Request(`https://morse.example${path}`, { method }));
  for (const version of [1, 2]) {
    for (const sequence of ['1', '9007199254740993', '18446744073709551615']) {
      assert.equal(route(`/v${version}/transparency/anchor/${sequence}`), 'DIRECTORY');
      assert.equal(route(`/v${version}/transparency/anchor/${sequence}`, 'POST'), null);
    }
    for (const sequence of ['0', '01', '-1', '%31', '1/', '18446744073709551616', '1'.repeat(128)]) {
      assert.equal(route(`/v${version}/transparency/anchor/${sequence}`), null);
    }
  }
  assert.equal(route('/v3/transparency/anchor/1'), null);
  assert.equal(route('/internal/v1/transparency/anchors', 'POST'), null);
  assert.equal(route('/internal/v1/transparency/anchors'), null);
  assert.equal(route('/internal/v1/transparency/anchor-candidate/1'), null);
  assert.equal(route('/internal/v1/transparency/anchor-cosigns', 'POST'), null);
});


test('priority signup routes through the privacy boundary and rejects alternate verbs and queries', () => {
  const request = (path = '/v1/credits/signup', method = 'POST') => new Request('https://morse.example' + path, { method });
  assert.equal(publicRoute(request()), 'PRIVACY_EDGE');
  assert.equal(publicRoute(request(), { MORSE_ISOLATED_EDGE: '1' }), 'DIRECTORY');
  assert.equal(publicRoute(request('/v1/credits/signup?trace=1')), null);
  assert.equal(publicRoute(request('/v1/credits/signup', 'GET')), null);
  assert.equal(publicRoute(request('/v1/credits/%73ignup')), null);
});

test('paid attachment routes are explicit and bounded while the free namespace stays unchanged', () => {
  const id = 'b'.repeat(64);
  const route = (path, method = 'POST', env = {}) => publicRoute(new Request('https://morse.example' + path, { method }), env);
  assert.equal(route('/v1/attachments/paid-grant'), null);
  assert.equal(route('/v1/attachments/paid-grant', 'POST', { MORSE_PAID_LARGE_ATTACHMENTS: 'on' }), 'OBJECT_STORE');
  assert.equal(route('/v1/attachments/paid-grant?trace=1', 'POST', { MORSE_PAID_LARGE_ATTACHMENTS: 'on' }), null);
  for (const method of ['GET', 'PUT']) {
    assert.equal(route(`/v2/objects/${id}/parts/8192`, method), 'OBJECT_STORE');
    for (const index of ['8193', '08192', '-1', '%31']) assert.equal(route(`/v2/objects/${id}/parts/${index}`, method), null);
    assert.equal(route(`/v2/objects/${id}/parts/0?trace=1`, method), null);
  }
  for (const path of ['/v2/attachments/complete', '/v2/attachments/delete']) {
    assert.equal(route(path), 'OBJECT_STORE');
    assert.equal(route(path, 'GET'), null);
    assert.equal(route(path + '?trace=1'), null);
  }
  assert.equal(route(`/v1/objects/${id}/parts/0`, 'PUT'), 'OBJECT_STORE');
  for (const env of [{}, { MORSE_ISOLATED_EDGE: '1' }]) {
    assert.equal(route('/v1/credits/signup-policy', 'POST', env), env.MORSE_ISOLATED_EDGE ? 'DIRECTORY' : 'PRIVACY_EDGE');
    assert.equal(route('/v1/credits/signup-policy?trace=1', 'POST', env), null);
    assert.equal(route('/v1/credits/signup-policy', 'GET', env), null);
  }
});

test('credit reconciliation exposes only canonical raw POST through the privacy boundary', () => {
  for (const env of [{}, { MORSE_ISOLATED_EDGE: '1' }]) {
    const route = (path, method = 'POST') => publicRoute(new Request('https://morse.example' + path, { method }), env);
    assert.equal(route('/v1/credits/reconcile'), env.MORSE_ISOLATED_EDGE ? 'DIRECTORY' : 'PRIVACY_EDGE');
    for (const method of ['GET', 'PUT', 'DELETE']) assert.equal(route('/v1/credits/reconcile', method), null);
    for (const path of ['/v1/credits/reconcile?trace=1', '/v1/credits/%72econcile', '/v1/credits/reconcile/']) assert.equal(route(path), null);
  }
});
