import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { RewardsJournal } from './journal.mjs';
import { prepareRewardsTransaction, rewardsMessage, signRewardsTransaction } from './transactions.mjs';

const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const keys=(await Promise.all([21,22,23,24,25,26].map(n=>createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(n))))).map(s=>s.address);
const pins={program:keys[0],judge:keys[1],log:keys[2],mint:keys[3],payer:signer.address};
const data=Buffer.alloc(9);data[0]=1;data.writeBigUInt64LE(99n,1);
const plan={...pins,schema_version:1,status:'ready',epoch:'99',context_slot:'10',action:'open',intent_hash:'ab'.repeat(32),
  signer_keys:[signer.address],rent_allocations:[{address:keys[5],space:8416}],instructions:[{schemaVersion:1,programId:pins.program,
    accountCount:4,accountKeys:[signer.address,keys[4],keys[5],'11111111111111111111111111111111'],signerKeys:[signer.address],
    writableKeys:[signer.address,keys[5]],dataBase64:data.toString('base64'),dataBytes:9}]};
const step=prepareRewardsTransaction(plan,pins),life={blockhash:'11111111111111111111111111111111',lastValidBlockHeight:100n};
const quote={blockhash:life.blockhash,lastValidBlockHeight:'100',maxDebitLamports:'1000',messageHash:rewardsMessage(step,life).messageHash,minContextSlot:'10',contextSlot:'11'};
const options=path=>({path,pins,request:{action:'settle',epoch:'99'},policy:{maxLamports:'2000',maxTransactions:4}});

test('journal fences competing processes and persists the exact signed packet before any broadcast',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'morse-rewards-'));
  let a,b;
  try{
    a=new RewardsJournal(options(join(dir,'journal.sqlite')));b=new RewardsJournal(options(join(dir,'journal.sqlite')));
    const old=a.claim('one',100);assert.throws(()=>b.claim('two',101),/lease/i);
    a.reserve(old,plan,quote,102);
    assert.throws(()=>a.authorizeBroadcast(old,103),/signed/i);
    const signed=await signRewardsTransaction(step,[signer],life);
    await a.recordSigned(old,signed,()=>104);const packet=a.authorizeBroadcast(old,105);
    assert.deepEqual(packet,signed);
    a.close();a=undefined;
    const lease=b.claim('two',30101);
    assert.deepEqual(b.pending().signed,signed);
    assert.throws(()=>b.authorizeBroadcast(old,30102),/lease/i);
    assert.deepEqual(b.authorizeBroadcast(lease,30103),signed);
    assert.throws(()=>b.reserve(lease,plan,quote,30104),/pending/i);
    assert.throws(()=>b.finish(lease,{state:'finalized',slot:'9',debitLamports:'1000',success:true},30104),/context/i);
    b.finish(lease,{state:'finalized',slot:'12',debitLamports:'900',success:true},30105);
    assert.equal(b.pending(),null);assert.equal(b.progress().spentLamports,'900');assert.equal(b.progress().contextSlot,'12');
    assert.throws(()=>b.reserve(lease,plan,quote,30106),/context/i);
    assert.throws(()=>new RewardsJournal({...options(join(dir,'journal.sqlite')),request:{action:'fund'}}),/scope/i);
  }finally{a?.close();b?.close();await rm(dir,{recursive:true,force:true});}
});

test('unsigned abandonment is safe, signature substitution fails, and unresolved reservations consume the cap',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'morse-rewards-'));const j=new RewardsJournal(options(join(dir,'journal.sqlite')));
  try{
    const lease=j.claim('one',100);
    j.reserve(lease,plan,quote,101);j.abandonUnsigned(lease,102);assert.equal(j.progress().spentLamports,'0');
    const retry={...plan,context_slot:'11'},retryStep=prepareRewardsTransaction(retry,pins);
    j.reserve(lease,retry,{...quote,minContextSlot:'11',messageHash:rewardsMessage(retryStep,life).messageHash},103);
    const signed=await signRewardsTransaction(retryStep,[signer],life);
    await assert.rejects(j.recordSigned(lease,{...signed,signature:pins.program},()=>104),/reservation/i);
    await j.recordSigned(lease,signed,()=>105);
    assert.throws(()=>j.abandonUnsigned(lease,106),/unsigned/i);
    assert.throws(()=>j.finish(lease,{state:'expired',slot:'12',blockHeight:'100'},106),/expiry/i);
    j.finish(lease,{state:'effect',slot:'12',blockHeight:'101'},107);
    assert.equal(j.progress().spentLamports,'1000','unknown actual fees reserve the full cap');
    const next={...plan,context_slot:'12'},s=prepareRewardsTransaction(next,pins);
    const later={blockhash:keys[0],lastValidBlockHeight:200n};
    const q={...quote,blockhash:later.blockhash,lastValidBlockHeight:'200',minContextSlot:'12',contextSlot:'12',messageHash:rewardsMessage(s,later).messageHash};
    j.reserve(lease,next,q,108);const sig=await signRewardsTransaction(s,[signer],later);await j.recordSigned(lease,sig,()=>109);
    j.finish(lease,{state:'finalized',slot:'13',debitLamports:'1001',success:true},110);
    assert.equal(j.progress().halted,true,'overspending observed from chain halts instead of disappearing');
    assert.throws(()=>j.reserve(lease,next,q,111),/halted/i);
  }finally{j.close();await rm(dir,{recursive:true,force:true});}
});

test('signed persistence evaluates the lease clock after asynchronous cryptographic verification',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'morse-rewards-'));const j=new RewardsJournal(options(join(dir,'journal.sqlite')));
  try{
    const lease=j.claim('one',100);j.reserve(lease,plan,quote,101);
    const signed=await signRewardsTransaction(step,[signer],life);let calls=0;
    await assert.rejects(j.recordSigned(lease,signed,()=>{calls++;return 30100;}),/lease/i);
    assert.equal(calls,1);assert.equal(j.pending().phase,'reserved');assert.equal(j.pending().signed,null);
  }finally{j.close();await rm(dir,{recursive:true,force:true});}
});

test('expired signed packets retain their budget charge without finalized debit metadata, including v1',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'morse-rewards-'));
  const j=new RewardsJournal({...options(join(dir,'journal.sqlite')),policy:{maxLamports:'1000',maxTransactions:4}});
  try{
    const lease=j.claim('one',100);j.reserve(lease,plan,quote,101);
    await j.recordSigned(lease,await signRewardsTransaction(step,[signer],life),()=>102);
    j.finish(lease,{state:'expired',slot:'12',blockHeight:'101'},103);
    assert.equal(j.progress().spentLamports,'1000','absence is not evidence that signed work spent nothing');
    const next={...plan,context_slot:'12'},s=prepareRewardsTransaction(next,pins);
    const later={blockhash:keys[0],lastValidBlockHeight:200n};
    const q={...quote,blockhash:later.blockhash,lastValidBlockHeight:'200',minContextSlot:'12',contextSlot:'12',messageHash:rewardsMessage(s,later).messageHash};
    assert.throws(()=>j.reserve(lease,next,q,104),/budget/i);
  }finally{j.close();await rm(dir,{recursive:true,force:true});}
});

test('a previously ignored count in an old explicit scope cannot become a schedule',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'morse-rewards-'));
  const path=join(dir,'journal.sqlite'),bound={...pins,version:2},policy={maxLamports:'2000',maxTransactions:4};
  const request={schema_version:2,action:'settle',epoch:'99',epoch_count:'2'};
  let journal=new RewardsJournal({path,pins:bound,request:{schema_version:2,action:'settle',epoch:'99'},policy});
  journal.close();journal=undefined;
  const {DatabaseSync}=await import('node:sqlite'),db=new DatabaseSync(path);
  try{
    // The old journal accepted unknown request fields and stored version 1.
    db.prepare('UPDATE rewards_scope SET scope=?,spent=?,attempts=?,context_slot=? WHERE singleton=1')
      .run(JSON.stringify({version:1,pins:bound,request,policy}),'1000',1,'12');
  }finally{db.close();}
  try{assert.throws(()=>new RewardsJournal({path,pins:bound,request,policy}),/scope changed/);}
  finally{await rm(dir,{recursive:true,force:true});}
});
