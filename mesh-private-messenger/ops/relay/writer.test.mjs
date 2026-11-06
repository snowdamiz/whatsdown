import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { RelayJournal } from './journal.mjs';
import { prepareRelayTransactions, relayStepMessage } from './transactions.mjs';
import { submitRelayStep, recoverRelayPending } from './writer.mjs';

const path=process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH;
if(!path)throw new Error('Run scripts/prove-relay-writer.sh for fresh plans');
const plan=JSON.parse((await readFile(path,'utf8')).trim().split('\n')[0]);
const pins={...plan,proofHex:plan.proof_hex},prepared=prepareRelayTransactions(plan,pins);
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const life={blockhash:plan.program,lastValidBlockHeight:9007199254740993n};
async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),'morse-relay-writer-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const options={path:join(root,'relay.sqlite'),identity:'local:test:writer',pins,
    policy:{perJobLamports:'1000000',windowLamports:'1000000',maxJobs:5}};
  const journal=new RelayJournal(options);t.after(()=>journal.close());
  let time=1000;const now=()=>time++;
  journal.accept(plan,now());const lease=journal.claim('worker',now());
  const calls=[],rpc={
    async quote(step){calls.push('quote');const info=relayStepMessage(step,life);return {blockhash:life.blockhash,lastValidBlockHeight:life.lastValidBlockHeight.toString(),maxDebitLamports:'100000',messageHash:info.messageHash,minContextSlot:info.minContextSlot};},
    async broadcast(packet){calls.push('broadcast');assert.equal(journal.pending().phase,'signed');assert.equal(journal.pending().signed.wire,packet.wire);return {accepted:2};},
    async observe(step,packet,readEffect){calls.push('observe');assert.equal(step.id,packet.stepId);assert.equal(packet.wire,journal.pending().signed.wire);return {state:'pending'};},
  };
  return {journal,options,lease,now,rpc,signer,proofHash:plan.proof_hash,stepId:'initialize',calls,advance:ms=>{time+=ms;}};
}

test('writer reserves before signing and persists/authenticates before broadcast; retries need no wallet',async t=>{
  const f=await fixture(t);
  const signed=await submitRelayStep(f);
  assert.equal(signed.state,'broadcast');assert.deepEqual(f.calls,['quote','broadcast']);
  const packet=f.journal.pending().signed;
  const restored=new RelayJournal(f.options);t.after(()=>restored.close());
  f.advance(30001);const lease=restored.claim('restart',f.now());
  const retry=await recoverRelayPending({...f,journal:restored,lease,signer:undefined});
  assert.equal(retry.state,'broadcast');assert.equal(f.journal.pending().signed.wire,packet.wire);
  assert.deepEqual(f.calls,['quote','broadcast','observe','broadcast']);
  const throttled=await recoverRelayPending({...f,journal:restored,lease});
  assert.equal(throttled.state,'pending');assert.equal(f.calls.at(-1),'observe');
});

test('unacknowledged sends keep the exact reservation; finalized success and failure charge once',async t=>{
  for(const success of [true,false]){
    const f=await fixture(t);f.rpc.broadcast=async()=>{throw new Error('upstream secret');};
    assert.deepEqual(await submitRelayStep(f),{state:'unacknowledged'});
    assert.equal(f.journal.pending().phase,'signed');
    const id=f.journal.pending().id;
    f.rpc.observe=async()=>({state:'finalized',success,debitLamports:'5000',slot:plan.context_slot});
    assert.equal((await recoverRelayPending(f)).state,success?'finalized':'failed');
    assert.equal(f.journal.pending(),null);assert.equal(f.journal.transaction(id).debitLamports,'5000');
    assert.deepEqual(await recoverRelayPending(f),{state:'idle'});
    assert.equal(f.journal.budget(f.now()).chargedLamports,'5000');
  }
});

test('unsigned crash reservations are abandoned, and stale workers cannot reserve or broadcast',async t=>{
  const f=await fixture(t),quote=await f.rpc.quote(prepared.preparation[0]);
  f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.now());
  assert.deepEqual(await recoverRelayPending(f),{state:'unsigned-abandoned'});
  assert.equal(f.journal.budget(f.now()).reservedLamports,'0');
  f.rpc.quote=async()=>{f.advance(30001);assert.ok(f.journal.claim('replacement',f.now()));return quote;};
  await assert.rejects(submitRelayStep(f),/lease/i);
  assert.equal(f.journal.pending(),null);
  assert.equal(f.calls.includes('broadcast'),false);
});

test('expiry requires the adapter effect check and a barrier is never rebroadcast',async t=>{
  for(const state of ['expiry-barrier','expired','effect']){
    const f=await fixture(t);await submitRelayStep(f);f.calls.length=0;
    let effectRead=false;
    f.readEffect=async(job,step,request)=>{
      effectRead=true;assert.equal(job.proofHash,plan.proof_hash);assert.equal(step.id,'initialize');
      assert.equal(request.minContextSlot,plan.context_slot);return {state:state==='effect'?'present':'absent',slot:plan.context_slot};
    };
    f.rpc.observe=async(step,packet,readEffect)=>{
      if(state!=='expiry-barrier')await readEffect({minContextSlot:plan.context_slot});
      return {state,blockHeight:(life.lastValidBlockHeight+1n).toString(),slot:plan.context_slot};
    };
    assert.equal((await recoverRelayPending(f)).state,state);
    assert.equal(f.calls.includes('broadcast'),false);
    assert.equal(effectRead,state!=='expiry-barrier');
    assert.equal(f.journal.budget(f.now()).reservedLamports,state==='expiry-barrier'?'100000':'0');
    assert.equal(f.journal.budget(f.now()).chargedLamports,state==='effect'?'100000':'0');
  }
});

test('receipt suppression and lease loss during reconciliation cannot send or release a packet',async t=>{
  const f=await fixture(t);await submitRelayStep(f);f.calls.length=0;f.advance(2000);
  f.journal.recordReceipt(f.lease,plan.proof_hash,{schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder},f.now());
  assert.equal((await recoverRelayPending(f)).state,'pending');
  assert.equal(f.calls.includes('broadcast'),false);
  f.rpc.observe=async()=>{f.advance(30001);f.journal.claim('replacement',f.now());return {state:'finalized',success:true,debitLamports:'5000',slot:plan.context_slot};};
  await assert.rejects(recoverRelayPending(f),/lease/i);
  assert.equal(f.journal.pending().phase,'signed');
});

test('failed or superseded signing never broadcasts and remains recoverable as an unsigned reservation',async t=>{
  for(const superseded of [false,true]){
    const f=await fixture(t);
    const delayed={address:signer.address,async signTransactions(transactions){
      if(!superseded)throw new Error('wallet secret diagnostic');
      f.advance(30001);f.journal.claim('replacement',f.now());
      return signer.signTransactions(transactions);
    }};
    await assert.rejects(submitRelayStep({...f,signer:delayed}),error=>
      (superseded?/lease/i:/unsigned reservation/i).test(error.message)&&!error.message.includes('secret'));
    assert.equal(f.journal.pending().phase,'reserved');
    assert.equal(f.calls.includes('broadcast'),false);
    if(!superseded){assert.equal((await recoverRelayPending(f)).state,'unsigned-abandoned');}
  }
});

test('restart recovery automatically reads authenticated Mesh effects at the expiry barrier',async t=>{
  for(const present of [false,true]){
    const f=await fixture(t);await submitRelayStep(f);
    const floor=(BigInt(plan.context_slot)+100n).toString();
    let reads=0;
    f.verifier={async stage(value,minimum){
      reads++;assert.equal(value.proof_hex,plan.proof_hex);assert.equal(minimum,floor);
      return {status:present?'uploading':'missing',context_slot:floor};
    }};
    f.rpc.observe=async(step,packet,readEffect)=>{
      assert.equal(typeof readEffect,'function');
      const effect=await readEffect({minContextSlot:floor});
      assert.equal(effect.state,present?'present':'absent');
      return {state:present?'effect':'expired',slot:effect.slot,blockHeight:(life.lastValidBlockHeight+1n).toString()};
    };
    assert.equal((await recoverRelayPending(f)).state,present?'effect':'expired');
    assert.equal(reads,1);assert.equal(f.journal.pending(),null);
    assert.equal(f.journal.budget(f.now()).chargedLamports,present?'100000':'0');
  }
});

test('a failed transaction cannot be journaled and charged again under the same signature',async t=>{
  const f=await fixture(t);await submitRelayStep(f);
  f.rpc.observe=async()=>({state:'finalized',success:false,debitLamports:'5000',slot:plan.context_slot});
  assert.equal((await recoverRelayPending(f)).state,'failed');
  await assert.rejects(submitRelayStep(f),/signature.*already/i);
  assert.equal(f.journal.pending().phase,'reserved');
  assert.equal((await recoverRelayPending(f)).state,'unsigned-abandoned');
  assert.equal(f.journal.budget(f.now()).chargedLamports,'5000');
  assert.equal(f.calls.filter(value=>value==='broadcast').length,1);
});
