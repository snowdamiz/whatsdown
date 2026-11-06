import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RelayJournal } from './journal.mjs';
import { createRelayService } from './service.mjs';

if (!process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH) throw new Error('Run scripts/prove-relay-writer.sh for Mesh plans');
const plan=JSON.parse((await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH,'utf8')).trim().split('\n')[0]);
const wire=()=>Buffer.from(plan.proof_hex,'hex');
async function fixture(t,overrides={}) {
  const root=await mkdtemp(join(tmpdir(),'relay-service-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const options={path:join(root,'relay.sqlite'),identity:'test:service',pins:plan,policy:{perJobLamports:'100000000',windowLamports:'200000000',maxJobs:1}};
  const journal=new RelayJournal(options);t.after(()=>journal.close());let now=1,reads=0,ticks=0;
  const service=createRelayService({journal,now:()=>now++,maxQueued:2,
    verifier:{admit:async bytes=>{reads++;assert.deepEqual(bytes,wire());return structuredClone(plan);},...overrides},
    scheduler:{tick:async()=>{ticks++;return {state:'idle'};}}});
  t.after(()=>service.close());return {service,journal,options,get reads(){return reads;},get ticks(){return ticks;}};
}

test('admission queues raw copied evidence and acknowledges only a durable Mesh-admitted job',async t=>{
  const f=await fixture(t),bytes=wire(),pending=f.service.submit(bytes);bytes.fill(0);
  assert.equal(f.journal.jobs().length,0);assert.equal(f.reads,0);
  await f.service.cycle();const accepted=await pending;
  assert.deepEqual(accepted,{schema_version:1,status:'queued',proof_hash:plan.proof_hash,finder:plan.finder,duplicate:false});
  const reopened=new RelayJournal(f.options);assert.equal(reopened.job(plan.proof_hash).finder,plan.finder);reopened.close();
  const retry=f.service.submit(wire());await f.service.cycle();assert.equal((await retry).duplicate,true);
  assert.equal(f.journal.jobs().length,1);assert.equal(f.ticks,2);
});

test('bounded admission and cancellation cannot reserve money or feed caller reports to the writer',async t=>{
  const f=await fixture(t),controller=new AbortController();
  const first=f.service.submit(wire(),{signal:controller.signal});const second=f.service.submit(wire());
  await assert.rejects(f.service.submit(wire()),/busy/);await assert.rejects(f.service.submit(plan),/evidence/);
  await assert.rejects(f.service.submit(Buffer.alloc(8193)),/evidence/);
  const cancelled=assert.rejects(first,/cancelled/);controller.abort();await cancelled;
  await f.service.cycle();await second;assert.equal(f.reads,1);assert.equal(f.journal.pending(),null);
});

test('scheduler failures do not prevent bounded admissions and verifier failures do not enter SQLite',async t=>{
  const f=await fixture(t,{admit:async()=>{throw new Error('private provider URL');}});
  const rejected=assert.rejects(f.service.submit(wire()),/admission unavailable/);await f.service.cycle();await rejected;
  assert.equal(f.journal.jobs().length,0);assert.equal(f.journal.pending(),null);
  const svc=createRelayService({journal:f.journal,verifier:{admit:async()=>structuredClone(plan)},scheduler:{tick:async()=>{throw new Error('wallet detail');}},now:()=>50});
  const pending=svc.submit(wire());const result=await svc.cycle();assert.equal(result.scheduler.state,'unavailable');await pending;await svc.close();
});

test('cycle serialization and shutdown cancel outstanding native admission without accepting it',async t=>{
  let release,started;const entered=new Promise(resolve=>{started=resolve;});
  const f=await fixture(t,{admit:async(_bytes,_floor,{signal})=>{started();await new Promise(resolve=>{release=resolve;signal.addEventListener('abort',resolve,{once:true});});return structuredClone(plan);}});
  const failure=assert.rejects(f.service.submit(wire()),/cancelled|closed/);
  const one=f.service.cycle();await entered;assert.equal((await f.service.cycle()).scheduler.state,'busy');
  const queued=assert.rejects(f.service.submit(wire()),/closed/);await f.service.close();await one;await failure;await queued;
  release();assert.equal(f.journal.jobs().length,0);assert.equal(f.ticks,1);
});

test('a Mesh-authenticated existing receipt returns its actual winner without creating a spend job',async t=>{
  const receipt={schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.program,context_slot:plan.context_slot};
  const f=await fixture(t,{admit:async()=>({schema_version:1,status:'settled',receipt})});
  const pending=f.service.submit(wire());await f.service.cycle();assert.deepEqual(await pending,{schema_version:1,status:'settled',proof_hash:plan.proof_hash,finder:plan.program});
  assert.equal(f.journal.jobs().length,0);
});
