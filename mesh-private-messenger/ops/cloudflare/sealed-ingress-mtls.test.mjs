import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { publicRoute } from './routing.mjs';
import { isolatedConfig, edgeConfig } from './prepare-build.mjs';
import { sealedDeliveryRequest, sealedIngressRequest } from './edge.mjs';

const fingerprint = 'ab'.repeat(32);
const origin = 'https://backend.example';
const policy = { MORSE_ISOLATED_EDGE: '1', MORSE_SEALED_INGRESS_MTLS: 'required',
  MORSE_SEALED_INGRESS_ORIGIN: origin, MORSE_EDGE_CLIENT_CERT_SHA256: fingerprint };
const verified = { certPresented: '1', certVerified: 'SUCCESS', certRevoked: '0', certFingerprintSHA256: fingerprint };
const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const isolation = { WITNESS_A_URL: 'https://a.example', WITNESS_B_URL: 'https://b.example', MORSE_PUSH_BROKER_URL: 'https://broker.example' };

function request(tls, path = '/v1/ingress/sealed', at = origin, headers = {}) {
  const value = new Request(at + path, { method: 'POST', body: 'opaque', headers });
  if (tls !== undefined) Object.defineProperty(value, 'cf', { value: { tlsClientAuth: tls } });
  return value;
}

test('required sealed ingress refuses missing, unverified, revoked or different client certificates', () => {
  for (const tls of [undefined, {}, { ...verified, certPresented: '0' }, { ...verified, certPresented: true },
    { ...verified, certVerified: 'NONE' }, { ...verified, certVerified: 'FAILED:self signed certificate' },
    { ...verified, certVerified: true }, { ...verified, certRevoked: '1' }, { ...verified, certRevoked: undefined },
    { ...verified, certFingerprintSHA256: 'cd'.repeat(32) }, { ...verified, certFingerprintSHA256: undefined }]) {
    assert.equal(publicRoute(request(tls), policy), null, JSON.stringify(tls));
  }
  assert.equal(publicRoute(request(verified), policy), 'SEALED_INGRESS');
});

test('certificate headers, alternate hosts and malformed opt-in configuration cannot bypass the gate', () => {
  assert.equal(publicRoute(request(undefined, undefined, undefined, {
    'X-CERT-VERIFY': 'SUCCESS', 'X-CERT-FINGER': fingerprint, 'Client-Cert': ':forged:',
    'CF-Cert-Verified': 'SUCCESS', 'CF-Cert-Fingerprint-Sha256': fingerprint,
  }), policy), null);
  for (const path of ['/v1/ingress/sealed?x=1', '/v1/ingress/sealed#x=1', '/v1/ingress/sealed/', '/v1/ingress/%73ealed']) {
    assert.equal(publicRoute(request(verified, path), policy), null);
  }
  assert.equal(publicRoute(request(verified, undefined, 'https://alternate.example'), policy), null);
  for (const invalid of [{ MORSE_SEALED_INGRESS_MTLS: 'off' }, { MORSE_SEALED_INGRESS_MTLS: '' },
    { MORSE_EDGE_CLIENT_CERT_SHA256: undefined }, { MORSE_EDGE_CLIENT_CERT_SHA256: 'not-a-fingerprint' },
    { MORSE_SEALED_INGRESS_ORIGIN: undefined }, { MORSE_SEALED_INGRESS_ORIGIN: 'https://backend.example/path' }]) {
    assert.equal(publicRoute(request(verified), { ...policy, ...invalid }), null);
  }
  assert.equal(sealedIngressRequest(request(undefined), policy), null, 'mapper itself must enforce the policy');
  assert.equal(sealedIngressRequest(request(verified), policy)?.url, origin + '/internal/v1/envelopes/sealed');
  for (const env of [policy, { ...policy, MORSE_ISOLATED_EDGE: undefined }]) {
    assert.equal(publicRoute(request(verified, '/v1/envelopes/batch'), env), null, 'combined Worker cannot bypass enabled policy');
  }
});

test('backend config makes the optional certificate policy explicit and rejects incomplete policy', () => {
  const config = isolatedConfig(original, { ...isolation, ...policy });
  for (const name of ['MORSE_SEALED_INGRESS_MTLS', 'MORSE_SEALED_INGRESS_ORIGIN', 'MORSE_EDGE_CLIENT_CERT_SHA256']) {
    assert.equal(config.vars[name], policy[name]);
  }
  for (const invalid of [{ MORSE_SEALED_INGRESS_MTLS: 'off' }, { MORSE_EDGE_CLIENT_CERT_SHA256: '' },
    { MORSE_SEALED_INGRESS_ORIGIN: undefined }, { MORSE_SEALED_INGRESS_ORIGIN: '' },
    { MORSE_SEALED_INGRESS_ORIGIN: 'http://backend.example' }]) {
    assert.throws(() => isolatedConfig(original, { ...isolation, ...policy, ...invalid }), /sealed ingress mTLS/);
  }
  assert.equal(isolatedConfig(original, isolation).vars.MORSE_SEALED_INGRESS_MTLS, undefined);
  assert.throws(() => isolatedConfig(original, { ...isolation, MORSE_EDGE_CLIENT_CERT_SHA256: fingerprint }), /sealed ingress mTLS/);
});

test('direct Worker-to-Worker mTLS activation is rejected before producing an unusable edge build', () => {
  assert.throws(() => edgeConfig(original, { MORSE_DELIVERY_URL: origin,
    MORSE_SEALED_INGRESS_MTLS: 'required', MORSE_EDGE_MTLS_CERTIFICATE_ID: '1'.repeat(32) }), /Worker-to-Worker mTLS.*unsupported/);
  assert.throws(() => edgeConfig(original, { MORSE_DELIVERY_URL: origin,
    MORSE_EDGE_MTLS_CERTIFICATE_ID: '1'.repeat(32) }), /Worker-to-Worker mTLS.*unsupported/);
  const outgoing = new Request('http://delivery.internal/internal/v1/envelopes/sealed', { method: 'POST', body: 'opaque' });
  assert.throws(() => sealedDeliveryRequest(outgoing, { MORSE_DELIVERY_URL: origin,
    MORSE_SEALED_INGRESS_MTLS: 'required' }), /Worker-to-Worker mTLS.*unsupported/, 'runtime must not silently use global fetch');
  assert.throws(() => edgeConfig({ ...original, mtls_certificates: [{ binding: 'SEALED_INGRESS_MTLS', certificate_id: '1'.repeat(32) }] },
    { MORSE_DELIVERY_URL: origin }), /Worker-to-Worker mTLS.*unsupported/);
});

test('edge CLI preflight refuses the unsupported topology without replacing build output', () => {
  const output = new URL('./wrangler.build.json', import.meta.url);
  const before = existsSync(output) ? readFileSync(output) : null;
  const result = spawnSync(process.execPath, ['prepare-build.mjs', '--edge'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)), timeout: 5000, encoding: 'utf8',
    env: { ...process.env, MORSE_DELIVERY_URL: origin, MORSE_SEALED_INGRESS_MTLS: 'required', MESH_LANG_REVISION: 'invalid-revision' },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Worker-to-Worker mTLS.*unsupported/);
  assert.doesNotMatch(result.stderr, /must be a full commit SHA/);
  assert.deepEqual(existsSync(output) ? readFileSync(output) : null, before);
});

test('production Worker enforces certificate policy before Directory and retains independent bearer authentication', { timeout: 30000 }, async () => {
  // Only the fixture sets cf metadata. These are NOT real Cloudflare TLS exchanges.
  const contents = `
    import worker, {PrivacyEdge} from './worker.mjs';
    const policy = ${JSON.stringify(policy)}, verified = ${JSON.stringify(verified)};
    export default { async fetch(request) {
      const scenario = new URL(request.url).searchParams.get('case');
      const tls = scenario === 'absent' || scenario === 'spoof' ? undefined :
        scenario === 'wrong' ? {...verified,certFingerprintSHA256:'cd'.repeat(32)} :
        scenario === 'unverified' ? {...verified,certVerified:'NONE'} :
        scenario === 'revoked' ? {...verified,certRevoked:'1'} : verified;
      const headers = {Authorization: scenario === 'wrong-bearer' ? 'Bearer wrong' : 'Bearer owned-fixture-token',
        'CF-Connecting-IP':'198.51.100.1',Cookie:'drop','X-CERT-VERIFY':'SUCCESS','X-CERT-FINGER':verified.certFingerprintSHA256};
      const incoming = new Request('${origin}/v1/ingress/sealed', {method:'POST',body:'owned-opaque-record',headers,
        ...(tls ? {cf:{tlsClientAuth:tls}} : {})});
      let calls=0, captured;
      const env={...policy,DIRECTORY:{getByName(){return {async fetch(value){
        calls++;captured={path:new URL(value.url).pathname,headers:[...value.headers.keys()].sort(),body:await value.text()};
        return new Response(null,{status:value.headers.get('Authorization')==='Bearer owned-fixture-token'?204:401});
      }};}}};
      if(scenario==='combined-internal') {
        const result=await PrivacyEdge.outboundByHost['delivery.internal'](
          new Request('http://delivery.internal/internal/v1/envelopes/sealed',{method:'POST',body:'opaque'}),env);
        return Response.json({status:result.status,calls});
      }
      const result=await worker.fetch(incoming,env);
      return Response.json({status:result.status,calls,captured});
    }};`;
  const bundle = await build({ stdin: { resolveDir: fileURLToPath(new URL('.', import.meta.url)), sourcefile: 'sealed-mtls-proof.mjs', contents },
    bundle: true, write: false, platform: 'browser', format: 'esm', conditions: ['workerd', 'browser'], external: ['cloudflare:workers', 'node:*'],
    alias: Object.fromEntries(builtinModules.filter(name => !name.startsWith('node:')).map(name => [name, `node:${name}`])) });
  const options = convertV4MiniflareOptions({ name: 'sealed-mtls-proof', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [{ type: 'ESModule', path: 'entry.mjs', contents: bundle.outputFiles[0].text }] });
  const mf = new Miniflare(options);
  try {
    for (const mode of ['absent', 'spoof', 'wrong', 'unverified', 'revoked', 'combined-internal']) {
      const result = await (await mf.dispatchFetch('http://test/?case=' + mode)).json();
      assert.equal(result.status, 404, mode);
      assert.equal(result.calls, 0, mode + ' must not reach Directory');
    }
    for (const [mode, status] of [['verified', 204], ['wrong-bearer', 401]]) {
      const result = await (await mf.dispatchFetch('http://test/?case=' + mode)).json();
      assert.equal(result.status, status, mode);
      assert.equal(result.calls, 1);
      assert.deepEqual(result.captured, { path: '/internal/v1/envelopes/sealed', headers: ['authorization', 'content-type'], body: 'owned-opaque-record' });
    }
  } finally { await mf.dispose(); }
});
