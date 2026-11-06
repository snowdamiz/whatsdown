import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('anchor alarms are independent of witness polling, survive restart and stop when disabled',async()=> {
  const path=await mkdtemp(join(tmpdir(),'morse-anchor-scheduler-'));
  const options=convertV4MiniflareOptions({name:'morse-anchor-scheduler-proof',compatibilityDate:'2026-09-18',
    bindings:{MORSE_ANCHOR_MODE:'devnet',MESSENGER_DELIVERY_INTERNAL_TOKEN:'test-token'},
    modules:[
      {type:'ESModule',path:'entry.mjs',contents:`import {DurableObject} from 'cloudflare:workers';
        export {JobScheduler} from './jobs.mjs';
        export class Probe extends DurableObject {
          async stats(){return await this.ctx.storage.get('stats')??{anchor:0,witness:0,jobs:0};}
          async mode(value){await this.ctx.storage.put('mode',value);}
          async fetch(request){
            const path=new URL(request.url).pathname,stats=await this.stats(),mode=await this.ctx.storage.get('mode');
            if(path==='/anchor'){stats.anchor++;await this.ctx.storage.put('stats',stats);return Response.json({mode:'devnet',issues:[],fee:{level:'critical',balanceLamports:'10000'}});}
            if(path==='/witness'){stats.witness++;await this.ctx.storage.put('stats',stats);return new Response(null,{status:503});}
            stats.jobs++;await this.ctx.storage.put('stats',stats);return new Response('0',{status:mode==='directory-failure'?503:200});
          }
        }
        export default {async fetch(r,e){const job=e.JOBS.getByName('anchor'),witness=e.JOBS.getByName('witness'),probe=e.DIRECTORY.getByName('primary');
          switch(new URL(r.url).pathname){
            case '/register':await job.register('anchor',await r.text()||'0');break;
            case '/witness-register':await witness.register('witness',await r.text()||'0');break;
            case '/witness-run':await witness.run();break;
            case '/witness-stats':return Response.json(await witness.status());
            case '/run':await job.run();break;
            case '/fail-directory':await probe.mode('directory-failure');break;
            case '/healthy-directory':await probe.mode('healthy');break;
            case '/stats':return Response.json({...await job.status(),calls:await probe.stats()});
          }return new Response(null,{status:204});}};`},
      {type:'ESModule',path:'jobs.mjs',contents:await readFile(new URL('./jobs.mjs',import.meta.url),'utf8')},
      {type:'ESModule',path:'storage.mjs',contents:await readFile(new URL('./storage.mjs',import.meta.url),'utf8')},
      {type:'ESModule',path:'witness.mjs',contents:`export async function attestWitnesses(env){const r=await env.DIRECTORY.getByName('primary').fetch('http://probe/witness');if(!r.ok)throw new Error('witness unavailable');}`},
      {type:'ESModule',path:'anchor-job.mjs',contents:`export async function runAnchorJob(ctx,env){return (await env.DIRECTORY.getByName('primary').fetch('http://probe/anchor')).json();}`},
      {type:'ESModule',path:'anchor-alerts.mjs',contents:await readFile(new URL('./anchor-alerts.mjs',import.meta.url),'utf8')},
    ],durableObjects:{JOBS:{className:'JobScheduler',useSQLite:true,unsafeUniqueKey:'anchor-job-scheduler'},
      DIRECTORY:{className:'Probe',useSQLite:true,unsafeUniqueKey:'anchor-job-probe'}}});
  options.resourcePersistencePath=path;
  let mf=new Miniflare(options);
  const post=(path,body)=>mf.dispatchFetch(`http://test${path}`,{method:'POST',body});
  const stats=async()=> (await mf.dispatchFetch('http://test/stats')).json();
  try {
    await post('/register');await post('/run');let first=await stats();
    assert.equal(first.calls.anchor,1);assert.equal(first.calls.witness,0);assert.equal(first.calls.jobs,0);
    assert.equal(first.anchor.fee.level,'critical');assert.equal(first.anchor.alert.pending,true);
    assert.equal(first.pending,0);
    assert.ok(first.due>Date.now() && first.due<=Date.now()+15_000);
    await mf.dispose();mf=new Miniflare(options);
    assert.equal((await stats()).anchor.fee.level,'critical');
    await post('/witness-register','1');await post('/witness-register','2');await post('/witness-run');
    const witness=await (await mf.dispatchFetch('http://test/witness-stats')).json();
    assert.equal(witness.witness.healthy,false);assert.equal(witness.pending,0);assert.ok(witness.due>Date.now());
    assert.equal((await stats()).calls.anchor,1,'witness jobs never invoke anchor work');
    await post('/fail-directory');await post('/witness-register');await post('/witness-run');
    await post('/register');await post('/run');
    const second=await stats();assert.equal(second.calls.anchor,2,'failed directory jobs cannot prevent anchor reconciliation');
    assert.equal(second.calls.witness,1);assert.equal(second.pending,0);
    assert.ok(second.due<=Date.now()+15_000);
    const failed=await (await mf.dispatchFetch('http://test/witness-stats')).json();assert.equal(failed.pending,1);
    await mf.dispose();options.workers[0].config.env.MORSE_ANCHOR_MODE.value='off';mf=new Miniflare(options);
    await post('/register');await post('/run');
    const off=await stats();assert.equal(off.calls.anchor,2,'the anchor kill switch prevents another run');
    assert.equal(off.pending,0);assert.equal(off.due,0,'disabled anchor alarms stop');
  } finally {await mf.dispose();await rm(path,{recursive:true,force:true});}
});
