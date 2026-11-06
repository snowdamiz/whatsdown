import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressDecoder } from '@solana/kit';
import { RelayJournal } from './journal.mjs';
import { prepareRelayTransactions, relayStepEffect, relayStepMessage } from './transactions.mjs';
import { createRelayScheduler } from './scheduler.mjs';

if(!process.env.MORSE_RELAY_PLAN_REVISIONS_PATH)throw new Error('Run scripts/prove-relay-writer.sh for fresh Mesh plans');
const cases=(await readFile(process.env.MORSE_RELAY_PLAN_REVISIONS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
async function fixture(t,entry){
  const directory=await mkdtemp(join(tmpdir(),'morse-relay-scheduler-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const original=entry.original,options={path:join(directory,'relay.sqlite'),identity:'local:scheduler',pins:original,
    policy:{perJobLamports:'1000000000',windowLamports:'1000000000',maxJobs:8}};
  let journal=new RelayJournal(options);t.after(()=>journal.close());let clock=1000,slot=BigInt(entry.later.context_slot),receipt=null;
  journal.accept(original,clock++);
  let stage={status:'missing',received_bytes:0,sealed:false,verified:[]},lookup=null,destinations={finder:{status:'missing'},locked:{status:'missing'}};
  let fresh=entry.later;const sent=[],executed=new Set(),quotes=[];let scheduler;
  function context(floor){assert.ok(BigInt(floor)<=slot);return slot.toString();}
  const verifier={
    async admit(wire,floor){assert.equal(Buffer.from(wire).toString('hex'),original.proof_hex);context(floor);return receipt?{schema_version:1,status:'settled',receipt:{...receipt,context_slot:slot.toString()}}:{...structuredClone(fresh),context_slot:slot.toString()};},
    async receipt(plan,floor){return {schema_version:1,status:receipt?'settled':'missing',address:plan.receipt,proof_hash:plan.proof_hash,context_slot:context(floor),receipt:receipt?{...receipt,context_slot:slot.toString()}:null};},
    async stage(plan,floor){return {...structuredClone(stage),context_slot:context(floor)};},
    async destinations(plan,floor){return {...structuredClone(destinations),context_slot:context(floor)};},
    async lookup(plan,floor){
      const result={schema_version:1,address:plan.lookup.address,authority:plan.submitter,creationSlot:plan.lookup.recent_slot,contextSlot:context(floor),
        lastExtendedSlot:lookup?.lastExtendedSlot??'0',deactivationSlot:lookup?.deactivationSlot??'18446744073709551615',addresses:lookup?.addresses??[],remainingBlocks:0};
      if(!lookup)result.status='missing';
      else if(result.deactivationSlot!=='18446744073709551615'){
        result.status=slot>BigInt(result.deactivationSlot)+512n?'closable':'cooling';result.remainingBlocks=result.status==='closable'?0:513;
      }else result.status=result.addresses.length<plan.lookup.addresses.length?'extending':BigInt(result.lastExtendedSlot)===slot?'warm':'ready';
      return result;
    },
  };
  const rpc={
    async quote(step,view){quotes.push(step.id);const hash=Buffer.alloc(32);hash.writeBigUInt64LE(slot);
      const life={blockhash:getAddressDecoder().decode(hash),lastValidBlockHeight:9007199254740993n},info=relayStepMessage(step,life,view);
      assert.ok(BigInt(info.minContextSlot)>=slot);return {...life,lastValidBlockHeight:life.lastValidBlockHeight.toString(),maxDebitLamports:'10000000',messageHash:info.messageHash,minContextSlot:info.minContextSlot};},
    async broadcast(packet){
      sent.push(packet);if(executed.has(packet.signature))return {accepted:2};executed.add(packet.signature);
      const plan=journal.job(original.proof_hash).plan,prepared=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex});
      const step=[...prepared.preparation,...prepared.lookup,prepared.settlement,...prepared.cleanup].find(value=>value.id===packet.stepId);
      const effect=relayStepEffect(step,plan);
      switch(effect.kind){
        case 'initialize':stage.status='uploading';break;
        case 'append':stage.received_bytes=effect.receivedBytes;stage.status=stage.received_bytes===plan.proof_hex.length/2?'uploaded':'uploading';break;
        case 'seal':stage.sealed=true;stage.status='sealed';break;
        case 'verify':stage.verified.push(...effect.signatures.filter(value=>!stage.verified.some(old=>old.ordinal===value.ordinal)));break;
        case 'setup':destinations[effect.destination].status='ready';break;
        case 'create-table':lookup={addresses:[],lastExtendedSlot:'0',deactivationSlot:'18446744073709551615'};break;
        case 'extend-table':lookup.addresses=plan.lookup.addresses.slice(0,effect.addressCount);lookup.lastExtendedSlot=slot.toString();break;
        case 'settle':receipt={schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder};break;
        case 'close-stage':stage={status:'missing',received_bytes:0,sealed:false,verified:[]};break;
        case 'deactivate-table':lookup.deactivationSlot=slot.toString();break;
        case 'close-table':lookup=null;break;
      }
      return {accepted:2};
    },
    async observe(){return {state:'finalized',success:true,debitLamports:'5000',slot:slot.toString()};},
  };
  function start(){scheduler=createRelayScheduler({journal,verifier,rpc,signer,now:()=>clock++,owner:`worker-${clock}`});}
  start();
  return {get journal(){return journal;},get receipt(){return receipt;},verifier,rpc,sent,quotes,original,
    get lookup(){return lookup;},get stage(){return stage;},get destinations(){return destinations;},
    now:()=>clock++,async tick(){clock+=1001;return scheduler.tick();},advanceSlots(n=1n){slot+=n;},
    restart(){journal.close();journal=new RelayJournal(options);clock+=30001;start();},
    changePlan(value){fresh=value;},competingReceipt(){receipt={schema_version:1,proof_hash:original.proof_hash,mint:original.mint,finder:original.program};},
    expireLease(){clock+=30001;assert.ok(journal.claim('replacement',clock++));},
  };
}

test('the durable scheduler drives every Mesh plan through preparation, payout, cooldown and cleanup across restarts',async t=>{
  for(const entry of cases){
    const f=await fixture(t,entry);let completed=false,restarts=0;
    for(let turn=0;turn<140;turn++){
      const result=await f.tick();
      if(result.state==='waiting'){f.advanceSlots(result.reason==='cooldown'?513n:1n);}
      if(f.journal.pending()&&restarts<2){f.restart();restarts++;}
      if(result.state==='complete'){completed=true;break;}
    }
    assert.equal(completed,true,entry.original.proof_hash);assert.equal(restarts,2);
    assert.equal(f.journal.job(f.original.proof_hash).state,'complete');
    assert.equal(f.receipt.finder,f.original.finder);assert.equal(f.journal.pending(),null);
    assert.equal(f.stage.status,'missing');assert.equal(f.lookup,null);
    assert.equal(f.journal.budget(100000000).reservedLamports,'0');
    assert.equal(f.sent.filter(value=>value.stepId==='settle').length,1);
    assert.equal(new Set(f.sent.map(value=>value.signature)).size,f.sent.length);
  }
});

test('an already paid unspent job completes without signing or closing another job table',async t=>{
  const f=await fixture(t,cases[15]);f.competingReceipt();
  assert.equal((await f.tick()).state,'complete');assert.equal(f.sent.length,0);assert.equal(f.quotes.length,0);
  assert.equal(f.journal.job(f.original.proof_hash).finder,f.original.finder);
  assert.equal(f.journal.job(f.original.proof_hash).receipt.finder,f.original.program);
});

test('a competing receipt stops preparation rebroadcast while preserving pending accounting and rent cleanup',async t=>{
  const f=await fixture(t,cases[0]);assert.equal((await f.tick()).state,'broadcast');f.competingReceipt();
  assert.equal((await f.tick()).state,'finalized');
  for(let i=0;i<10&&f.journal.job(f.original.proof_hash).state!=='complete';i++)await f.tick();
  assert.deepEqual(f.sent.map(value=>value.stepId),['initialize','close-stage']);
  assert.equal(f.journal.job(f.original.proof_hash).state,'complete');
  assert.equal(f.journal.budget(100000000).reservedLamports,'0');
});

test('fresh custody changes remove withdrawn witness work, and externally closed finder accounts are recreated',async t=>{
  const f=await fixture(t,cases[0]);let changed=false,closed=false;
  for(let i=0;i<80&&f.journal.job(f.original.proof_hash).state!=='complete';i++){
    if(!changed&&f.stage.sealed&&!f.journal.pending()){f.changePlan(cases[0].withdrawn);changed=true;}
    if(!closed&&f.destinations.finder.status==='ready'&&!f.journal.pending()){f.destinations.finder.status='missing';closed=true;f.advanceSlots();}
    await f.tick();
  }
  assert.ok(changed&&closed);assert.equal(f.journal.job(f.original.proof_hash).state,'complete');
  assert.equal(f.sent.filter(value=>value.stepId==='setup/0').length,2);
  assert.ok(f.journal.job(f.original.proof_hash).plan.stage.witnesses.length===0);
  assert.deepEqual(f.journal.originalPlan(f.original.proof_hash),f.original);
});

test('a failed native read or lease loss during admission cannot authorize spending',async t=>{
  for(const lost of [false,true]){
    const f=await fixture(t,cases[0]);const admit=f.verifier.admit;
    f.verifier.admit=async(...args)=>{if(lost){f.expireLease();return admit(...args);}throw new Error('unavailable');};
    await assert.rejects(f.tick(),lost?/lease/i:/unavailable/);
    assert.equal(f.journal.pending(),null);assert.equal(f.sent.length,0);assert.equal(f.quotes.length,0);
  }
});

test('durable scheduling moves past a failed job after restart instead of starving another proof',async t=>{
  const f=await fixture(t,cases[0]),other=cases[6].original;
  f.journal.accept(other,1002);
  const read=f.verifier.receipt;
  f.verifier.receipt=async(plan,minimum)=>plan.proof_hash===other.proof_hash?
    {status:'settled',context_slot:minimum,receipt:{schema_version:1,proof_hash:other.proof_hash,mint:other.mint,finder:other.finder,context_slot:minimum}}:read(plan,minimum);
  f.verifier.admit=async()=>{throw new Error('unavailable');};
  await assert.rejects(f.tick(),/unavailable/);f.restart();
  const next=await f.tick();assert.equal(next.state,'complete');assert.equal(next.proofHash,other.proof_hash);
  assert.equal(f.journal.job(f.original.proof_hash).state,'queued');assert.equal(f.sent.length,0);
});

test('one scheduler tick owns its asynchronous work and a second worker cannot spend under its lease',async t=>{
  const f=await fixture(t,cases[0]);let enter,release;
  const entered=new Promise(resolve=>{enter=resolve;}),gate=new Promise(resolve=>{release=resolve;});
  const admit=f.verifier.admit;
  f.verifier.admit=async(...args)=>{enter();await gate;return admit(...args);};
  const first=f.tick();await entered;
  assert.equal((await f.tick()).state,'busy');
  const other=createRelayScheduler({journal:f.journal,verifier:f.verifier,rpc:f.rpc,signer,now:f.now,owner:'other'});
  assert.equal((await other.tick()).state,'lease-busy');
  release();assert.equal((await first).state,'broadcast');
  assert.equal(f.sent.length,1);assert.equal(f.quotes.length,1);
});
