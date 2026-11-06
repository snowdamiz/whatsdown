import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { isolatedConfig, pushBrokerConfig } from './prepare-build.mjs';
import { directoryPushUrl, pushBrokerContainerEnv, pushBrokerIngressRequest } from './push-broker.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publicHealth } from './routing.mjs';

const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const origins = { WITNESS_A_URL: 'https://a.example', WITNESS_B_URL: 'https://b.example', MORSE_PUSH_BROKER_URL: 'https://broker.example' };
const token = 'owned-broker-only-credential-32-bytes';

async function bundle(contents) {
  const result = await build({ stdin: { resolveDir: fileURLToPath(new URL('.', import.meta.url)), sourcefile: 'push-isolation-proof.mjs', contents },
    bundle: true, write: false, platform: 'browser', format: 'esm', conditions: ['workerd', 'browser'], external: ['cloudflare:workers', 'node:*'],
    alias: Object.fromEntries(builtinModules.filter(name => !name.startsWith('node:')).map(name => [name, `node:${name}`])) });
  return result.outputFiles[0].text;
}

test('isolated backend removes the broker container and binding, while combined dev retains them', () => {
  const config = isolatedConfig(original, origins);
  assert.equal(config.vars.MORSE_ISOLATED_PUSH_BROKER, '1');
  assert.equal(config.vars.MORSE_PUSH_BROKER_URL, origins.MORSE_PUSH_BROKER_URL);
  assert(!config.containers.some(row => row.class_name === 'PushBroker'));
  assert(!config.durable_objects.bindings.some(row => row.name === 'PUSH_BROKER'));
  assert(original.containers.some(row => row.class_name === 'PushBroker'));
  assert(original.durable_objects.bindings.some(row => row.name === 'PUSH_BROKER'));
  const broker = pushBrokerConfig(original, origins);
  assert.equal(broker.main, 'isolated-push-broker.mjs');
  assert.deepEqual(broker.containers.map(row => row.class_name), ['IsolatedPushBroker']);
  assert.deepEqual(broker.durable_objects.bindings.map(row => row.name), ['PUSH_BROKER', 'JOBS']);
  assert.equal(broker.r2_buckets, undefined);
  assert.deepEqual(broker.triggers, { crons: ['* * * * *'] }, 'private recovery can bootstrap an existing queue without a public trigger');
  assert.deepEqual(broker.vars, { MORSE_PUSH_BROKER_URL: origins.MORSE_PUSH_BROKER_URL });
});

test('isolated backend requires pinned HTTPS broker origin and rejects broker-only credentials', () => {
  for (const url of [undefined, 'http://broker.example', 'https://user:password@broker.example', 'https://broker.example/path']) {
    assert.throws(() => isolatedConfig(original, { ...origins, MORSE_PUSH_BROKER_URL: url }), /HTTPS origin/);
  }
  for (const key of ['MESSENGER_PUSH_BROKER_SEED_HEX', 'PUSH_DATABASE_URL', 'MESSENGER_EXPO_ACCESS_TOKEN']) {
    assert.throws(() => isolatedConfig(original, { ...origins, [key]: 'must-not-reach-backend' }), /broker-only/);
    assert.throws(() => isolatedConfig({ ...original, vars: { [key]: 'must-not-reach-backend' } }, origins), /broker-only/);
  }
  assert.throws(() => directoryPushUrl({ MORSE_ISOLATED_PUSH_BROKER: '0' }), /Invalid isolated broker/);
  assert.throws(() => directoryPushUrl({ ...origins, MORSE_ISOLATED_PUSH_BROKER: '1', MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token,
    MESSENGER_PUSH_BROKER_SEED_HEX: 'must-not-reach-backend' }), /broker-only/);
});

test('production backend routes a bounded opaque wake across HTTPS without a local broker capability', { timeout: 30000 }, async () => {
  const script = await bundle(`
    import {Directory} from './worker.mjs';
    export default {async fetch(request) {
      const env={MORSE_ISOLATED_PUSH_BROKER:'1',MORSE_PUSH_BROKER_URL:'https://broker.example',MESSENGER_PUSH_BROKER_INTERNAL_TOKEN:${JSON.stringify(token)}};
      Object.defineProperty(env,'PUSH_BROKER',{get(){throw Error('forbidden local broker binding');}});
      const incoming=new Request('http://push.internal/internal/v1/push',{method:'POST',body:new Uint8Array([1,2,3]),
        headers:{Authorization:'Bearer '+${JSON.stringify(token)},Cookie:'drop','CF-Connecting-IP':'198.51.100.1'}});
      try {const response=await Directory.outboundByHost['push.internal'](incoming,env);return Response.json({status:response.status});}
      catch(error){return Response.json({error:error.message});}
    }};`);
  const calls = [];
  const options = convertV4MiniflareOptions({ name: 'push-backend-proof', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [{ type: 'ESModule', path: 'entry.mjs', contents: script }], outboundService: async request => {
      calls.push({ url: request.url, method: request.method, headers: [...request.headers.keys()].sort(), bytes: [...new Uint8Array(await request.arrayBuffer())] });
      return new Response(null, { status: 204 });
    } });
  const mf = new Miniflare(options);
  try {
    assert.deepEqual(await (await mf.dispatchFetch('http://test/')).json(), { status: 204 });
    // workerd adds transport headers; no application-supplied tracking header survives.
    assert.deepEqual(calls.map(row => ({ ...row, headers: row.headers.filter(name => !['cf-worker', 'content-length', 'host'].includes(name)) })),
      [{ url: 'https://broker.example/v1/ingress/push', method: 'POST', headers: ['authorization', 'content-type'], bytes: [1, 2, 3] }]);
  } finally { await mf.dispose(); }
});

test('broker container allowlist excludes every core, issuer, object and account-link capability', () => {
  const env = pushBrokerContainerEnv({ MESSENGER_PUSH_BROKER_SEED_HEX: 'a'.repeat(64), MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token,
    PUSH_DATABASE_URL: 'postgres://owned-queue', MESSENGER_DATABASE_URL: 'must-drop', MESSENGER_DELIVERY_SEALING_SEED_HEX: 'must-drop',
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: 'must-drop', MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN: 'must-drop', MESSENGER_OBJECT_INTERNAL_TOKEN: 'must-drop' });
  assert.deepEqual(Object.keys(env).sort(), ['MESSENGER_EXPO_ACCESS_TOKEN', 'MESSENGER_JOBS_URL', 'MESSENGER_PUSH_BROKER_DATABASE_URL', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN', 'MESSENGER_PUSH_BROKER_SEED_HEX']);
  assert(!Object.values(env).includes('must-drop'));
});

test('broker authentication precedes reading a request body', async () => {
  const request = { url: 'https://broker.example/v1/ingress/push', method: 'POST', headers: new Headers({ Authorization: 'Bearer wrong' }),
    get body() { throw Error('unauthenticated body read'); } };
  assert.equal((await pushBrokerIngressRequest(request, { ...origins, MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token })).status, 401);
});

test('isolated backend health never claims a remote broker was observed or activates its legacy job', async () => {
  const names = [], now = Date.now();
  const env = { MORSE_ISOLATED_PUSH_BROKER: '1', JOBS: { getByName(name) {
    names.push(name); assert.notEqual(name, 'push');
    return { async status() { return { failures: 0, ...(name === 'witness' ? { witness: { observed_at: now, threshold_met: true, checkpoint_age_ms: 0, witnesses: [] } } : {}) }; } };
  } } };
  const response = await publicHealth(env), value = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(value.push_broker, { mode: 'external', health: 'not-observed' });
  assert.equal(value.services.push, undefined);
  assert.deepEqual(names, ['directory', 'objects', 'witness']);
});

test('backend cutover retires old push alarms without deleting pending records or calling a removed binding', { timeout: 30000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-retired-push-'));
  const script = await bundle(`
    import {JobScheduler} from './jobs.mjs';
    export class ProbeScheduler extends JobScheduler {
      async defer(){await this.ctx.storage.setAlarm(Date.now()+600000);}
      async alarmTime(){return await this.ctx.storage.getAlarm();}
    }
    export default {async fetch(request,env){
      const job=env.JOBS.getByName('push'),path=new URL(request.url).pathname;
      if(path==='/register'){try{await job.register('push','47');await job.defer();return new Response(null,{status:204});}catch{return new Response(null,{status:403});}}
      if(path==='/tick')await job.run();
      return Response.json({...(await job.status()),alarm:await job.alarmTime()});
    }};`);
  const options = flag => {
    const result = convertV4MiniflareOptions({ name: 'retired-backend-push', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
      modules: [{ type: 'ESModule', path: 'entry.mjs', contents: script }], bindings: flag ? { MORSE_ISOLATED_PUSH_BROKER: '1' } : {},
      durableObjects: { JOBS: { className: 'ProbeScheduler', useSQLite: true, unsafeUniqueKey: 'retired-backend-push-jobs' } } });
    result.resourcePersistencePath = directory; return result;
  };
  let mf = new Miniflare(options(false));
  try {
    assert.equal((await mf.dispatchFetch('http://test/register')).status, 204);
    const old = await (await mf.dispatchFetch('http://test/status')).json();
    assert.equal(old.pending, 1); assert(old.alarm > Date.now());
    await mf.dispose(); mf = new Miniflare(options(true));
    const retired = await (await mf.dispatchFetch('http://test/tick')).json();
    assert.equal(retired.pending, 1, 'retain cutover records; queue/data migration is not automatic');
    assert.equal(retired.failures, 0, 'a removed broker binding was never invoked');
    assert.equal(retired.alarm, null, 'the retired backend alarm does not rearm forever');
    assert.equal((await mf.dispatchFetch('http://test/register')).status, 403);
  } finally { await mf.dispose(); await rm(directory, { recursive: true, force: true }); }
});

test('production isolated broker admits only exact authenticated bounded push and owns durable push-only scheduling', { timeout: 30000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-isolated-push-'));
  const script = await bundle(`
    import worker,{IsolatedPushBroker} from './isolated-push-broker.mjs';
    export {PushJobScheduler} from './isolated-push-broker.mjs';
    import {DurableObject} from 'cloudflare:workers';
    export class FixtureBroker extends DurableObject {
      async calls(){return await this.ctx.storage.get('calls')??[];}
      async mode(value){await this.ctx.storage.put('mode',value);}
      async fetch(request){
        if(request.headers.get('Authorization')!=='Bearer '+this.env.MESSENGER_PUSH_BROKER_INTERNAL_TOKEN)return new Response(null,{status:401});
        const calls=await this.calls();calls.push({path:new URL(request.url).pathname,headers:[...request.headers.keys()].sort(),body:[...new Uint8Array(await request.arrayBuffer())]});await this.ctx.storage.put('calls',calls);
        const jobs=new URL(request.url).pathname==='/internal/v1/jobs/push';
        return jobs?new Response('0',{status:await this.ctx.storage.get('mode')==='fail'?503:200}):new Response(null,{status:204});
      }
    }
    export default {async fetch(request,env){
      const url=new URL(request.url),job=env.JOBS.getByName('push'),broker=env.PUSH_BROKER.getByName('primary');
      if(url.pathname==='/proof/calls')return Response.json(await broker.calls());
      if(url.pathname==='/proof/status')return Response.json(await job.status());
      if(url.pathname==='/proof/tick'){await job.run();return new Response(null,{status:204});}
      if(url.pathname==='/proof/cron'){await worker.scheduled({},env);return new Response(null,{status:204});}
      if(url.pathname==='/proof/mode'){await broker.mode(await request.text());return new Response(null,{status:204});}
      if(url.pathname==='/proof/wakeup')return IsolatedPushBroker.outboundByHost['jobs.internal'](new Request('http://jobs.internal/push',{method:'POST',body:await request.text()}),env);
      if(url.pathname==='/proof/forbidden'){try{await job.register('directory','42');return new Response(null,{status:500});}catch{return new Response(null,{status:403});}}
      if(url.pathname==='/proof/forbidden-anchor'){try{await job.runAnchors();return new Response(null,{status:500});}catch{return new Response(null,{status:403});}}
      const restricted={...env};for(const name of ['DIRECTORY','OBJECT_STORE','WITNESS_A','PRIVACY_EDGE'])Object.defineProperty(restricted,name,{get(){throw Error('forbidden '+name);}});
      return worker.fetch(request,restricted);
    }};`);
  const options = convertV4MiniflareOptions({ name: 'isolated-broker-proof', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [{ type: 'ESModule', path: 'entry.mjs', contents: script }], bindings: { MORSE_PUSH_BROKER_URL: origins.MORSE_PUSH_BROKER_URL, MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token },
    durableObjects: { PUSH_BROKER: { className: 'FixtureBroker', useSQLite: true, unsafeUniqueKey: 'owned-broker' },
      JOBS: { className: 'PushJobScheduler', useSQLite: true, unsafeUniqueKey: 'owned-push-jobs' } } });
  options.resourcePersistencePath = directory;
  let mf = new Miniflare(options);
  let backend;
  const send = (path, { method = 'POST', body = new Uint8Array([1, 2, 3]), authorization = `Bearer ${token}`, host = 'https://broker.example' } = {}) =>
    mf.dispatchFetch(host + path, { method, headers: { Authorization: authorization, Cookie: 'drop', 'CF-Connecting-IP': '198.51.100.1' }, ...(method !== 'GET' ? { body } : {}) });
  const calls = async () => (await mf.dispatchFetch('https://broker.example/proof/calls')).json();
  const stats = async () => (await mf.dispatchFetch('https://broker.example/proof/status')).json();
  try {
    assert.equal((await send('/health', { method: 'GET' })).status, 200);
    assert.deepEqual(await calls(), [], 'cached health never invokes the container');
    for (const [path, args, status] of [
      ['/v1/ingress/push', { authorization: 'Bearer wrong' }, 401], ['/v1/ingress/push', { authorization: 'bearer ' + token }, 401],
      ['/v1/ingress/push?x=1', {}, 404], ['/v1/ingress/push/', {}, 404], ['/v1/ingress/%70ush', {}, 404],
      ['/v1/ingress/push', { method: 'GET' }, 404], ['/v1/ingress/push', { host: 'https://alternate.example' }, 404],
      ['/internal/v1/jobs/push', {}, 404], ['/internal/v1/push', {}, 404], ['/v1/devices/resolve', {}, 404],
      ['/v1/ingress/push', { body: new Uint8Array(622) }, 422], ['/v1/ingress/push', { body: new Uint8Array() }, 422],
    ]) assert.equal((await send(path, args)).status, status, path);
    assert.deepEqual(await calls(), [], 'invalid requests must not invoke any broker/core capability');
    assert.equal((await send('/v1/ingress/push', { body: new Uint8Array(621).fill(7) })).status, 204);
    assert.deepEqual((await calls()).map(row => ({ ...row, headers: row.headers.filter(name => name !== 'content-length') })),
      [{ path: '/internal/v1/push', headers: ['authorization', 'content-type'], body: Array(621).fill(7) }]);
    const backendScript = await bundle(`
      import {Directory} from './worker.mjs';
      export default {async fetch(request){
        const env={MORSE_ISOLATED_PUSH_BROKER:'1',MORSE_PUSH_BROKER_URL:'https://broker.example',MESSENGER_PUSH_BROKER_INTERNAL_TOKEN:${JSON.stringify(token)}};
        Object.defineProperty(env,'PUSH_BROKER',{get(){throw Error('forbidden local broker binding');}});
        const value=new Request('http://push.internal'+new URL(request.url).pathname,{method:'POST',body:request.body,headers:request.headers});
        return Directory.outboundByHost['push.internal'](value,env);
      }};`);
    let upstream = 'service'; const destinations = [];
    backend = new Miniflare(convertV4MiniflareOptions({ name: 'isolated-backend-hop', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
      modules: [{ type: 'ESModule', path: 'entry.mjs', contents: backendScript }], outboundService: async request => {
        destinations.push(request.url);
        if (upstream === 'redirect') return new Response(null, { status: 302, headers: { Location: 'https://not-allowed.example/' } });
        const response = await mf.dispatchFetch(request.url, { method: request.method, headers: request.headers, body: await request.arrayBuffer() });
        return new Response(response.body, { status: response.status, headers: response.headers });
      } }));
    const hop = (body, authorization = `Bearer ${token}`, path = '/internal/v1/push') => backend.dispatchFetch('http://backend-test' + path,
      { method: 'POST', body, headers: { Authorization: authorization, Cookie: 'must-drop', 'CF-Connecting-IP': '198.51.100.1' } });
    assert.equal((await hop(new Uint8Array([8, 9]))).status, 204, 'both production routing layers admit the exact opaque wake');
    const beforeDenied = destinations.length;
    assert.equal((await hop(new Uint8Array([8]), 'Bearer wrong')).status, 401);
    assert.equal((await hop(new Uint8Array(622))).status, 422);
    assert.equal((await hop(new Uint8Array([8]), `Bearer ${token}`, '/internal/v1/jobs/push')).status, 404);
    assert.equal(destinations.length, beforeDenied, 'denied backend requests never reach the broker');
    upstream = 'redirect';
    assert.equal((await hop(new Uint8Array([8]))).status, 502);
    assert(destinations.every(url => url === 'https://broker.example/v1/ingress/push'), 'redirects cannot leak the broker credential');
    assert.deepEqual((await calls())[1].body, [8, 9]);
    assert(!(await calls())[1].headers.some(name => ['cookie', 'cf-connecting-ip', 'cf-worker', 'host'].includes(name)), 'broker container receives no transport/client metadata');
    assert.equal((await send('/proof/forbidden')).status, 403);
    assert.equal((await send('/proof/forbidden-anchor')).status, 403, 'the shared scheduler helper must not add an anchor capability');
    await send('/proof/mode', { body: 'fail' });
    assert.equal((await send('/proof/wakeup', { body: '42' })).status, 204);
    await send('/proof/tick');
    assert.equal((await stats()).pending, 1);
    await mf.dispose(); mf = new Miniflare(options);
    assert.equal((await stats()).pending, 1, 'pending work survives an isolated broker restart');
    await send('/proof/mode', { body: 'ready' }); await send('/proof/tick');
    assert.equal((await stats()).pending, 0);
    const actual = await calls();
    assert(actual.slice(2).every(row => row.path === '/internal/v1/jobs/push' && row.headers.includes('authorization')));
    assert.equal((await send('/proof/cron')).status, 204);
    assert.equal((await stats()).pending, 1, 'independent cron recovers existing quiet queue work');
    await send('/proof/tick'); assert.equal((await stats()).pending, 0);
  } finally { if (backend) await backend.dispose(); await mf.dispose(); await rm(directory, { recursive: true, force: true }); }
});
