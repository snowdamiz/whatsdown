import assert from 'node:assert/strict';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { RewardsJournal } from './journal.mjs';
import { prepareRewardsTransaction,rewardsMessage } from './transactions.mjs';
import { runRewardsCycle } from './writer.mjs';

const signers=await Promise.all([11,12,21,22,23,24,25,26].map(n=>createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(n))));
const [payer,funder,...keys]=signers;
const pins={program:keys[0].address,judge:keys[1].address,log:keys[2].address,mint:keys[3].address,payer:payer.address};
const data=Buffer.alloc(9);data[0]=1;data.writeBigUInt64LE(99n,1);
const plan={...pins,schema_version:1,status:'ready',epoch:'99',context_slot:'10',action:'open',intent_hash:'ab'.repeat(32),
  signer_keys:[payer.address],rent_allocations:[{address:keys[5].address,space:8416}],instructions:[{schemaVersion:1,programId:pins.program,
    accountCount:4,accountKeys:[payer.address,keys[4].address,keys[5].address,'11111111111111111111111111111111'],
    signerKeys:[payer.address],writableKeys:[payer.address,keys[5].address],dataBase64:data.toString('base64'),dataBytes:9}]};
const life={blockhash:pins.program,lastValidBlockHeight:100n};

test('opening a funding epoch uses only its required signer and a lost send acknowledgement recovers without resigning',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'rewards-writer-'));let journal;
  try{
    const options={path:join(dir,'journal.sqlite'),pins,request:{action:'fund'},policy:{maxLamports:'5000000',maxTransactions:10}};
    journal=new RewardsJournal(options);let now=100,plans=0,quotes=0,effects=0,sends=[];
    const ctx={journal,lease:journal.claim('one',now),now:()=>++now,pins,request:options.request,signers:[payer,funder],
      planner:{plan:async()=>{plans++;return plan;},effect:async(request,previous,floor)=>{effects++;assert.equal(floor,'20');assert.deepEqual(previous,plan);return {state:'present',slot:'20'};}},
      rpc:{quote:async step=>{quotes++;return {...life,lastValidBlockHeight:'100',maxDebitLamports:'1000000',
        messageHash:rewardsMessage(step,life).messageHash,minContextSlot:'10',contextSlot:'11'};},
        broadcast:async signed=>{assert.deepEqual(journal.pending().signed,signed);sends.push(signed);throw new Error('lost acknowledgement');},
        observe:async()=>({state:'pending'})}};
    assert.equal((await runRewardsCycle(ctx)).state,'unacknowledged');
    const signed=journal.pending().signed;journal.close();journal=new RewardsJournal(options);now+=31000;
    ctx.journal=journal;ctx.lease=journal.claim('two',now);ctx.signers=[];
    assert.equal((await runRewardsCycle(ctx)).state,'unacknowledged');
    assert.deepEqual(sends,[signed,signed]);assert.equal(plans,1);assert.equal(quotes,1);
    ctx.rpc.observe=async(step,packet,readEffect)=>{assert.deepEqual(packet,signed);await readEffect({minContextSlot:'20'});return {state:'effect',slot:'20',blockHeight:'101'};};
    assert.equal((await runRewardsCycle(ctx)).state,'effect');assert.equal(effects,1);
    assert.equal(journal.progress().spentLamports,'1000000');assert.equal(journal.pending(),null);
    ctx.planner.plan=async(request,floor)=>{assert.equal(floor,'20');return {...plan,status:'complete',action:'complete',context_slot:'20',instructions:[]};};
    assert.equal((await runRewardsCycle(ctx)).state,'complete');assert.equal(quotes,1);
  }finally{journal?.close();await rm(dir,{recursive:true,force:true});}
});

test('a superseded lease cannot broadcast the result of an in-flight quote',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'rewards-writer-'));
  const options={path:join(dir,'journal.sqlite'),pins,request:{action:'settle'},policy:{maxLamports:'5000000',maxTransactions:10}};
  const a=new RewardsJournal(options),b=new RewardsJournal(options);let now=100,sends=0;
  try{
    const ctx={journal:a,lease:a.claim('one',now),now:()=>++now,pins,request:options.request,signers:[payer],planner:{plan:async()=>plan},
      rpc:{quote:async step=>{now+=30001;b.claim('two',now);return {...life,lastValidBlockHeight:'100',maxDebitLamports:'1000000',
        messageHash:rewardsMessage(step,life).messageHash,minContextSlot:'10',contextSlot:'11'};},broadcast:async()=>{sends++;}}};
    await assert.rejects(runRewardsCycle(ctx),/lease/i);assert.equal(sends,0);assert.equal(a.pending(),null);
  }finally{a.close();b.close();await rm(dir,{recursive:true,force:true});}
});
