import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { builtinModules } from 'node:module';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

// Transport orchestration fixture only: real Mesh-authenticated report values,
// synthetic retrieval times. Native account authentication is tested separately.
const report = JSON.parse(await readFile(new URL('../public-chain/fixtures/legacy-closed-report.json', import.meta.url)));
const week = report.burns[0], pin = week.program;
const config = { schema_version: 1, scope: 'configured-rpc', epochs: [week.epoch], minimum_context_slot: '0', max_age_seconds: '900',
  pins: { program: pin, governance: pin, program_slot: '1', usdc: week.usdc_mint, treasury: pin, factory: pin },
  endpoints: ['https://one.example', 'https://two.example', 'https://three.example'] };
const raw = JSON.stringify(config), sha = value => createHash('sha256').update(value).digest('hex');

test('production Worker schedules only explicit mode, exposes read-only bytes, and persistent DO retains failure history', { timeout: 30000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-public-worker-'));
  const contents = `
    import worker from './worker.mjs';
    export * from './worker.mjs';
    import {DurableObject} from 'cloudflare:workers';
    import {PublicSnapshotPublisher} from './public-snapshot-worker.mjs';
    export class TestPublisher extends PublicSnapshotPublisher { async proofTick() { await this.alarm(); } }
    export class FixtureReader extends DurableObject {
      async mode(mode) { await this.ctx.storage.put('mode', mode); }
      async calls() { return await this.ctx.storage.get('calls') ?? 0; }
      async fetch(request) {
        if(request.url!=='http://public-report.internal/internal/v1/public-report'||request.method!=='POST'||request.headers.get('Authorization')!=='Bearer '+this.env.MORSE_PUBLIC_REPORT_INTERNAL_TOKEN) return new Response(null,{status:401});
        await this.ctx.storage.put('calls', await this.calls()+1);
        const mode=await this.ctx.storage.get('mode');
        if(mode==='outage')return new Response(null,{status:503});
        if(mode==='oversize')return new Response('x'.repeat(8388609));
        if(mode==='redirect')return new Response(null,{status:302,headers:{Location:'http://not-allowed/'}});
        const report=JSON.parse(this.env.FIXTURE_REPORT),now=String(Math.floor(Date.now()/1000));
        report.scope='configured-rpc';report.generated_at_unix=now;report.burns[0].source_time_unix=now;
        return Response.json({schema_version:1,nonce:await request.text(),policy_sha256:this.env.MORSE_PUBLIC_REPORT_POLICY_SHA256,
          generator_sha256:mode==='wrong-build'?'c'.repeat(64):this.env.MORSE_PUBLIC_REPORT_GENERATOR_SHA256,started_at_unix:now,completed_at_unix:now,report});
      }
    }
    export default {async fetch(request, env) {
      const url=new URL(request.url), p=env.PUBLIC_SNAPSHOTS.getByName('primary'), reader=env.PUBLIC_REPORT_READER.getByName('primary');
      if(url.pathname==='/proof/cron') {
        const calls=[];await worker.scheduled({}, {...env,MORSE_PUBLIC_REPORT_MODE:url.searchParams.get('mode'),JOBS:{getByName(){throw Error('unrelated signer');}},PUBLIC_SNAPSHOTS:{getByName(){return {async schedule(){calls.push('schedule');}};}}});return Response.json(calls);
      }
      if(url.pathname==='/proof/cron-failure') {
        const calls=[],which=url.searchParams.get('which');let error=null;
        try {await worker.scheduled({}, {...env,MORSE_PUBLIC_REPORT_MODE:'on',MORSE_ANCHOR_MODE:'on',
          PUBLIC_SNAPSHOTS:{getByName(){return {async schedule(){calls.push('snapshot');if(which==='snapshot')throw Error('snapshot failed');}};}},
          JOBS:{getByName(){return {async register(){await new Promise(resolve=>setTimeout(resolve,10));calls.push('anchor');if(which==='anchor')throw Error('anchor failed');}};}}
        });}catch(cause){error=cause.message;}
        return Response.json({calls,error});
      }
      if(url.pathname==='/proof/tick'){await p.proofTick();return new Response(null,{status:204});}
      if(url.pathname==='/proof/mode'){await reader.mode(await request.text());return new Response(null,{status:204});}
      if(url.pathname==='/proof/calls')return Response.json(await reader.calls());
      return worker.fetch(request,env);
    }};`;
  const bundle = await build({ stdin: { resolveDir: fileURLToPath(new URL('.', import.meta.url)), sourcefile: 'public-snapshot-proof.mjs', contents }, bundle: true, write: false,
    platform: 'browser', format: 'esm', conditions: ['workerd','browser'], external: ['cloudflare:workers','node:*'],
    alias: Object.fromEntries(builtinModules.filter(n => !n.startsWith('node:')).map(n => [n, `node:${n}`])) });
  const options = convertV4MiniflareOptions({ name: 'public-snapshot-proof', compatibilityDate: '2026-09-18', compatibilityFlags: ['nodejs_compat'],
    modules: [{ type: 'ESModule', path: 'entry.mjs', contents: bundle.outputFiles[0].text }],
    bindings: { MORSE_PUBLIC_REPORT_MODE: 'on', MORSE_PUBLIC_REPORT_CONFIG: raw, MORSE_PUBLIC_REPORT_POLICY_SHA256: sha(raw), MORSE_PUBLIC_REPORT_GENERATOR_SHA256: 'b'.repeat(64),
      MORSE_PUBLIC_REPORT_INTERNAL_TOKEN: 'owned-transport-only-authentication-token', FIXTURE_REPORT: JSON.stringify(report) },
    durableObjects: { PUBLIC_SNAPSHOTS: { className: 'TestPublisher', useSQLite: true, unsafeUniqueKey: 'public-test-publisher' },
      PUBLIC_REPORT_READER: { className: 'FixtureReader', useSQLite: true, unsafeUniqueKey: 'public-test-reader' } } });
  options.resourcePersistencePath = directory;
  let mf = new Miniflare(options);
  const get = path => mf.dispatchFetch(`http://test${path}`), post = (path, body = '') => mf.dispatchFetch(`http://test${path}`, { method: 'POST', body });
  try {
    for (const mode of ['off','invalid','']) assert.deepEqual(await (await get(`/proof/cron?mode=${mode}`)).json(), []);
    assert.deepEqual(await (await get('/proof/cron?mode=on')).json(), ['schedule']);
    for(const which of ['snapshot','anchor']) {
      const failed=await (await get('/proof/cron-failure?which='+which)).json();
      assert.deepEqual(failed.calls.sort(),['anchor','snapshot'],'one failed scheduler must not prevent the other recovery attempt');
      assert.equal(failed.error,which+' failed','cron failure remains observable after both tasks settle');
    }
    assert.equal((await (await get('/public/network-data.json')).json()).status, 'bootstrap');
    assert.equal(await (await get('/proof/calls')).json(), 0, 'public GET never wakes native reader');
    assert.equal((await post('/public/network-data.json')).status, 404);
    assert.equal((await get('/public/network-data.json?pins=caller')).status, 404);
    await post('/proof/tick'); let value = await (await get('/public/network-data.json')).json(); assert.equal(value.status, 'available');
    const first = value.last_good.report_sha256;
    const script = await get('/public/network-data.js'); assert.match(script.headers.get('Content-Type'), /javascript/);
    assert.equal(script.headers.get('Cache-Control'), 'no-store'); assert((await script.text()).startsWith('globalThis.MORSE_NETWORK_REPORT='));
    await mf.dispose(); mf = new Miniflare(options);
    value = await (await get('/public/network-data.json')).json(); assert.equal(value.last_good.report_sha256, first);
    for (const [mode, expected] of [['outage','unavailable'],['wrong-build','identity-mismatch'],['redirect','unavailable'],['oversize','unavailable']]) {
      await post('/proof/mode', mode); await post('/proof/tick'); value = await (await get('/public/network-data.json')).json();
      assert.equal(value.status, expected); assert.equal(value.current, null); assert.equal(value.last_good.report_sha256, first);
    }
    const wrangler = JSON.parse(await readFile(new URL('./wrangler.jsonc', import.meta.url)));
    assert(wrangler.durable_objects.bindings.some(row => row.name === 'PUBLIC_SNAPSHOTS'));
    assert(wrangler.containers.some(row => row.class_name === 'PublicReportReader'));
    assert.equal(wrangler.vars?.MORSE_PUBLIC_REPORT_MODE, undefined, 'not activated by config change');
    assert.deepEqual(wrangler.triggers.crons, ['* * * * *']);
  } finally { await mf.dispose(); await rm(directory, { recursive: true, force: true }); }
});
