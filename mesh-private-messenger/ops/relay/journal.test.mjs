import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { prepareRelayTransactions, relayStepMessage, signRelayStep } from './transactions.mjs';
import { RelayJournal } from './journal.mjs';

if(!process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH)throw new Error('Run scripts/prove-relay-writer.sh for fresh plans');
const plans=(await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
const plan=plans[0],signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const pins={program:plan.program,log:plan.log,mint:plan.mint,submitter:signer.address,proofHex:plan.proof_hex};
const prepared=prepareRelayTransactions(plan,pins);
const life={blockhash:'11111111111111111111111111111111',lastValidBlockHeight:9007199254740993n};
const quote={maxDebitLamports:'60',blockhash:life.blockhash,lastValidBlockHeight:life.lastValidBlockHeight.toString()};
const policy={perJobLamports:'100',windowLamports:'150',maxJobs:8};
const receipt={schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder};
async function setup(t){
  const directory=await mkdtemp(join(tmpdir(),'morse-relay-journal-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const options={path:join(directory,'relay.sqlite'),identity:'local:test:operator',pins,policy};
  return options;
}

test('signed relay transactions survive restart byte-for-byte and stale leases cannot spend or mutate them',async t=>{
  const options=await setup(t);let journal=new RelayJournal(options);
  const accepted=journal.accept(plan,1000);assert.equal(accepted.duplicate,false);
  const lease=journal.claim('worker-a',1001);
  const reservation=journal.reserve(lease,plan.proof_hash,prepared.preparation[0].id,quote,1002);
  assert.equal(journal.budget(1002).reservedLamports,'60');
  const signed=await signRelayStep(prepared.preparation[0],signer,life);
  await journal.recordSigned(lease,reservation.id,signed,1003);
  journal.close();journal=new RelayJournal(options);t.after(()=>journal.close());
  assert.equal(journal.claim('worker-b',1004),null);
  const next=journal.claim('worker-b',31002);assert.ok(next.generation>lease.generation);
  assert.throws(()=>journal.authorizeBroadcast(lease,reservation.id,31003),/lease/i);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'seal',quote,31003),/lease/i);
  assert.equal(journal.authorizeBroadcast(next,reservation.id,31004).wire,signed.wire);
  assert.equal(journal.authorizeBroadcast(next,reservation.id,31005),null,'backoff persists');
  assert.equal(journal.authorizeBroadcast(next,reservation.id,33005).wire,signed.wire);
  assert.equal(journal.transaction(reservation.id).signed.lastValidBlockHeight,'9007199254740993');
  assert.throws(()=>journal.expire(next,reservation.id,{blockHeight:'9007199254740993',slot:'5'},33006),/expired/i);
  journal.expire(next,reservation.id,{blockHeight:'9007199254740994',slot:'6'},33007);
  assert.equal(journal.budget(33007).reservedLamports,'0');
  const retry=journal.reserve(next,plan.proof_hash,prepared.preparation[0].id,quote,33008);
  assert.notEqual(retry.id,reservation.id);
  journal.abandonUnsigned(next,retry.id,33009);
  assert.equal(journal.budget(33009).reservedLamports,'0');
  assert.throws(()=>journal.renew(next,33000),/clock/i);
});

test('budget reservations are atomic, use exact unsigned units and cannot be bypassed by changing a job or restarting',async t=>{
  const options=await setup(t),journal=new RelayJournal(options);t.after(()=>journal.close());
  journal.accept(plan,1000);const lease=journal.claim('worker',1001);
  const reserved=journal.reserve(lease,plan.proof_hash,prepared.preparation[0].id,quote,1002);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'seal',quote,1003),/pending/i);
  const signed=await signRelayStep(prepared.preparation[0],signer,life);
  await journal.recordSigned(lease,reserved.id,signed,1004);
  journal.finalize(lease,reserved.id,{success:true,debitLamports:'45',slot:'9007199254740995'},1005);
  assert.equal(journal.budget(1005).chargedLamports,'45');
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'seal',quote,1006),/job budget/i);
  assert.equal(journal.budget(1006).reservedLamports,'0');
  const smaller=journal.reserve(lease,plan.proof_hash,'seal',{...quote,maxDebitLamports:'50'},1007);
  journal.abandonUnsigned(lease,smaller.id,1008);
  assert.equal(journal.accept(plan,1009).duplicate,true);
  assert.throws(()=>new RelayJournal({...options,identity:'different-wallet'}),/identity/i);
  assert.throws(()=>new RelayJournal({...options,policy:{...policy,perJobLamports:'999'}}),/policy/i);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'seal',{...quote,maxDebitLamports:'18446744073709551616'},1010),/lamport/i);
});

test('the journal rejects substituted signed bytes and retains reservations across missing responses',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());
  journal.accept(plan,1000);const lease=journal.claim('worker',1001);
  const reservation=journal.reserve(lease,plan.proof_hash,'initialize',quote,1002);
  const unrelated=await signRelayStep(prepared.preparation[1],signer,life);
  await assert.rejects(journal.recordSigned(lease,reservation.id,unrelated,1003),/transaction|step/i);
  const signed=await signRelayStep(prepared.preparation[0],signer,life);
  const damaged=Buffer.from(signed.wire,'base64');damaged[3]^=1;
  await assert.rejects(journal.recordSigned(lease,reservation.id,{...signed,wire:damaged.toString('base64')},1004),/transaction|signature/i);
  await journal.recordSigned(lease,reservation.id,signed,1005);
  assert.throws(()=>journal.abandonUnsigned(lease,reservation.id,1006),/signed/i);
  assert.throws(()=>journal.observeEffect(lease,reservation.id,{slot:'100',blockHeight:life.lastValidBlockHeight.toString()},1007),/expired/i);
  assert.equal(journal.budget(1007).reservedLamports,'60');
  journal.observeEffect(lease,reservation.id,{slot:'100',blockHeight:(life.lastValidBlockHeight+1n).toString()},1007);
  assert.equal(journal.budget(1007).chargedLamports,'60','an observed effect with unknown cost consumes its full reservation');
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',{...quote,maxDebitLamports:'1'},1008),/completed/i);
});

test('a competing receipt stops new preparation, preserves the requested finder, and requires cleanup before completion',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());
  journal.accept(plan,1000);const lease=journal.claim('worker',1001);
  const winner={...receipt,finder:plan.program};journal.recordReceipt(lease,plan.proof_hash,winner,1002);
  assert.equal(journal.job(plan.proof_hash).finder,plan.finder);
  assert.equal(journal.job(plan.proof_hash).receipt.finder,plan.program);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',quote,1003),/settled/i);
  assert.throws(()=>journal.complete(lease,plan.proof_hash,1004),/cleanup/i);
  journal.observeCleanup(lease,plan.proof_hash,'close-stage',{slot:'100'},1005);
  journal.complete(lease,plan.proof_hash,1006);
  assert.equal(journal.job(plan.proof_hash).state,'complete');
});

test('separate connections serialize claims and reservations, and an expired worker cannot commit a late signature',async t=>{
  const options=await setup(t),first=new RelayJournal(options),second=new RelayJournal(options);
  t.after(()=>first.close());t.after(()=>second.close());
  first.accept(plan,1000);const lease=first.claim('first',1001);
  assert.equal(second.claim('second',1002),null);
  const reservation=first.reserve(lease,plan.proof_hash,'initialize',quote,1003);
  const signed=await signRelayStep(prepared.preparation[0],signer,life);
  const next=second.claim('second',31002);
  await assert.rejects(first.recordSigned(lease,reservation.id,signed,31003),/lease/i);
  assert.throws(()=>second.reserve(next,plan.proof_hash,'seal',quote,31004),/pending/i);
  second.abandonUnsigned(next,reservation.id,31005);
  await assert.rejects(first.recordSigned(next,reservation.id,signed,31006),/reserved/i);
  assert.equal(second.pending(),null);
});

test('failed fees and rolling spending survive restart; old unresolved reservations never age out',async t=>{
  const options=await setup(t);options.policy={...policy,perJobLamports:'150',windowLamports:'100'};
  let journal=new RelayJournal(options);journal.accept(plan,1000);
  const lease=journal.claim('worker',1001),reservation=journal.reserve(lease,plan.proof_hash,'initialize',quote,1002);
  await journal.recordSigned(lease,reservation.id,await signRelayStep(prepared.preparation[0],signer,life),1003);
  journal.finalize(lease,reservation.id,{success:false,debitLamports:'45',slot:'100'},1004);
  assert.equal(journal.transaction(reservation.id).phase,'failed');
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',quote,1005),/window budget/i);
  const retry=journal.reserve(lease,plan.proof_hash,'initialize',{...quote,maxDebitLamports:'50'},1006);
  journal.close();journal=new RelayJournal(options);t.after(()=>journal.close());
  const next=journal.claim('restart',86_401_004);
  assert.deepEqual(journal.budget(86_401_004),{chargedLamports:'0',reservedLamports:'50',halted:false});
  journal.abandonUnsigned(next,retry.id,86_401_005);
  assert.throws(()=>journal.reserve(next,plan.proof_hash,'initialize',{...quote,maxDebitLamports:'106'},86_401_006),/job budget/i);
  assert.equal(journal.budget(86_401_006).reservedLamports,'0');
});

test('a quote overrun is charged durably and halts new spending without hiding a real debit',async t=>{
  const options=await setup(t);let journal=new RelayJournal(options);journal.accept(plan,1000);
  const lease=journal.claim('worker',1001),reservation=journal.reserve(lease,plan.proof_hash,'initialize',quote,1002);
  await journal.recordSigned(lease,reservation.id,await signRelayStep(prepared.preparation[0],signer,life),1003);
  const final={success:false,debitLamports:'101',slot:'100'};
  journal.finalize(lease,reservation.id,final,1004);
  journal.finalize(lease,reservation.id,final,1005);
  assert.throws(()=>journal.finalize(lease,reservation.id,{...final,debitLamports:'0'},1006),/pending/i);
  journal.close();journal=new RelayJournal(options);t.after(()=>journal.close());
  assert.deepEqual(journal.budget(1007),{chargedLamports:'101',reservedLamports:'0',halted:true});
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',{...quote,maxDebitLamports:'1'},1008),/halted/i);
});

test('a receipt suppresses pending preparation broadcasts but cannot discard their lifetime or reservation',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());journal.accept(plan,1000);
  const lease=journal.claim('worker',1001),reservation=journal.reserve(lease,plan.proof_hash,'initialize',quote,1002);
  await journal.recordSigned(lease,reservation.id,await signRelayStep(prepared.preparation[0],signer,life),1003);
  journal.recordReceipt(lease,plan.proof_hash,receipt,1004);
  assert.equal(journal.authorizeBroadcast(lease,reservation.id,1005),null);
  assert.throws(()=>journal.observeCleanup(lease,plan.proof_hash,'close-stage',{slot:'101'},1006),/pending/i);
  assert.equal(journal.budget(1006).reservedLamports,'60');
  journal.expire(lease,reservation.id,{blockHeight:(life.lastValidBlockHeight+1n).toString(),slot:'102'},1007);
  journal.observeCleanup(lease,plan.proof_hash,'close-stage',{slot:'103'},1008);
  journal.complete(lease,plan.proof_hash,1009);
});

test('worker mutations require a lease even when a caller passes null',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());journal.accept(plan,1000);
  const lease=journal.claim('worker',1001);
  assert.throws(()=>journal.reserve(null,plan.proof_hash,'initialize',quote,1002),/lease/i);
  const reservation=journal.reserve(lease,plan.proof_hash,'initialize',quote,1003);
  const signed=await signRelayStep(prepared.preparation[0],signer,life);
  await assert.rejects(journal.recordSigned(null,reservation.id,signed,1004),/lease/i);
  assert.throws(()=>journal.abandonUnsigned(null,reservation.id,1005),/lease/i);
  await journal.recordSigned(lease,reservation.id,signed,1006);
  assert.throws(()=>journal.authorizeBroadcast(null,reservation.id,1007),/lease/i);
  assert.throws(()=>journal.finalize(null,reservation.id,{success:true,debitLamports:'50',slot:'100'},1008),/lease/i);
  assert.throws(()=>journal.recordReceipt(null,plan.proof_hash,receipt,1009),/lease/i);
  assert.throws(()=>journal.renew(null,1010),/lease/i);
  assert.equal(journal.budget(1011).reservedLamports,'60');
});

test('duplicate admission never replaces the first finder or stored plan',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());journal.accept(plan,1000);
  // The journal consumes trusted admission reports. Exercise replacement of
  // that report independently of the Mesh FRK/hash/ATA derivation tests.
  const candidate={...structuredClone(plan),finder:plan.program};
  const duplicate=journal.accept(candidate,1001);
  assert.equal(duplicate.duplicate,true);assert.equal(duplicate.finder,plan.finder);
  assert.deepEqual(journal.job(plan.proof_hash).plan,plan);
});

test('receipt read contexts may advance while the on-chain winner remains immutable',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());journal.accept(plan,1000);
  const lease=journal.claim('worker',1001);
  const first={...receipt,context_slot:plan.context_slot};
  journal.recordReceipt(lease,plan.proof_hash,first,1002);
  const later={...first,context_slot:(BigInt(plan.context_slot)+1n).toString()};
  journal.recordReceipt(lease,plan.proof_hash,later,1003);
  assert.equal(journal.job(plan.proof_hash).receipt.context_slot,later.context_slot);
  assert.throws(()=>journal.recordReceipt(lease,plan.proof_hash,first,1004),/context/i);
  assert.throws(()=>journal.recordReceipt(lease,plan.proof_hash,{...later,finder:plan.program},1005),/changed/i);
});

test('closure reservations require cooldown evidence and bind its context across journal restart',async t=>{
  const ownPins=value=>({program:value.program,log:value.log,mint:value.mint,submitter:signer.address,proofHex:value.proof_hex});
  const maximum=plans.find(value=>prepareRelayTransactions(value,ownPins(value)).needsLookup);
  const options={...await setup(t),pins:ownPins(maximum)};let journal=new RelayJournal(options);
  journal.accept(maximum,1000);let lease=journal.claim('worker',1001);
  const step=prepareRelayTransactions(maximum,ownPins(maximum)).cleanup.find(value=>value.kind==='close-table');
  assert.throws(()=>journal.reserve(lease,maximum.proof_hash,step.id,quote,1002),/lookup/i);
  assert.equal(journal.pending(),null);
  assert.equal(journal.budget(1002).reservedLamports,'0');
  const view={schema_version:1,status:'closable',remainingBlocks:0,authority:signer.address,
    address:maximum.lookup.address,addresses:maximum.lookup.addresses,creationSlot:maximum.lookup.recent_slot,
    lastExtendedSlot:maximum.lookup.recent_slot,deactivationSlot:(BigInt(maximum.lookup.recent_slot)+1n).toString(),
    contextSlot:(BigInt(maximum.lookup.recent_slot)+515n).toString()};
  const reservation=journal.reserve(lease,maximum.proof_hash,step.id,quote,1003,view);
  const signed=await signRelayStep(step,signer,life,view);
  await assert.rejects(journal.recordSigned(lease,reservation.id,{...signed,minContextSlot:maximum.context_slot},1004),/lifetime/i);
  await journal.recordSigned(lease,reservation.id,signed,1004);
  journal.close();journal=new RelayJournal(options);t.after(()=>journal.close());
  lease=journal.claim('restart',31002);
  assert.equal(journal.authorizeBroadcast(lease,reservation.id,31003).minContextSlot,view.contextSlot);
});

test('RPC spending quotes cannot be substituted across prepared messages or observation floors',async t=>{
  const journal=new RelayJournal(await setup(t));t.after(()=>journal.close());
  journal.accept(plan,1000);const lease=journal.claim('worker',1001);
  const info=relayStepMessage(prepared.preparation[0],life);
  const other=relayStepMessage(prepared.preparation[1],life);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',{...quote,messageHash:other.messageHash},1002),/quote/i);
  assert.throws(()=>journal.reserve(lease,plan.proof_hash,'initialize',{...quote,messageHash:info.messageHash,minContextSlot:'0'},1002),/quote/i);
  assert.equal(journal.pending(),null);
  const reservation=journal.reserve(lease,plan.proof_hash,'initialize',{...quote,messageHash:info.messageHash,minContextSlot:info.minContextSlot},1003);
  assert.equal(reservation.phase,'reserved');
});
