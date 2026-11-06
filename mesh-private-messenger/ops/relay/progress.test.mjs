import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RelayJournal } from './journal.mjs';

if(!process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH)throw new Error('Run scripts/prove-relay-writer.sh for fresh plans');
const plans=(await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
const first=plans[15],second=plans[16],floor='9007199254740993';
async function setup(t){
  const path=await mkdtemp(join(tmpdir(),'morse-relay-progress-'));t.after(()=>rm(path,{recursive:true,force:true}));
  const options={path:join(path,'relay.sqlite'),identity:'local:progress',pins:first,
    policy:{perJobLamports:'100000000',windowLamports:'200000000',maxJobs:8}};
  const journal=new RelayJournal(options);t.after(()=>journal.close());
  journal.accept(first,1000);journal.accept(second,1001);
  const lease=journal.claim('worker',1002);
  return {journal,lease,options};
}

test('authenticated phase progress and its unsigned context floor survive restart without charging an unspent effect',async t=>{
  const {journal,lease,options}=await setup(t);
  assert.deepEqual(journal.progress(first.proof_hash),{minContextSlot:first.context_slot,done:[]});
  journal.observeStep(lease,first.proof_hash,'initialize',{slot:floor},1003);
  journal.observeStep(lease,first.proof_hash,'append/0',{slot:floor},1004);
  assert.deepEqual(journal.progress(first.proof_hash),{minContextSlot:floor,done:['initialize','append/0']});
  assert.equal(journal.budget(1004).chargedLamports,'0');
  const restored=new RelayJournal(options);t.after(()=>restored.close());
  assert.deepEqual(restored.progress(first.proof_hash),journal.progress(first.proof_hash));
  assert.throws(()=>journal.observeStep(lease,first.proof_hash,'seal',{slot:'9007199254740992'},1005),/context/i);
  assert.throws(()=>journal.observeStep(lease,first.proof_hash,'unknown',{slot:floor},1006),/step/i);
  const exposed=journal.progress(first.proof_hash);exposed.done.push('seal');
  assert.equal(journal.progress(first.proof_hash).done.includes('seal'),false);
});

test('a pending reservation prevents phase shortcuts and receipt context cannot be bypassed',async t=>{
  const {journal,lease}=await setup(t);
  const quote={blockhash:first.program,lastValidBlockHeight:'100',maxDebitLamports:'5000'};
  journal.reserve(lease,first.proof_hash,'initialize',quote,1003);
  assert.throws(()=>journal.observeStep(lease,first.proof_hash,'initialize',{slot:floor},1004),/pending/i);
  assert.throws(()=>journal.observeStep(lease,second.proof_hash,'initialize',{slot:floor},1005),/pending/i);
  journal.abandonUnsigned(lease,journal.pending().id,1006);
  journal.recordReceipt(lease,first.proof_hash,{schema_version:1,proof_hash:first.proof_hash,mint:first.mint,finder:first.finder,context_slot:floor},1007);
  assert.equal(journal.progress(first.proof_hash).minContextSlot,floor);
  assert.throws(()=>journal.observeStep(lease,first.proof_hash,'seal',{slot:floor},1008),/settled/i);
  journal.observeStep(lease,first.proof_hash,'close-stage',{slot:floor},1009);
});

test('table and Stage ownership is atomic and durable until all rent cleanup is complete',async t=>{
  const {journal,lease,options}=await setup(t);
  assert.equal(first.lookup.address,second.lookup.address,'fixture jobs intentionally share the table PDA');
  assert.equal(journal.claimResources(lease,first.proof_hash,1003),true);
  assert.equal(journal.claimResources(lease,first.proof_hash,1004),true);
  assert.equal(journal.claimResources(lease,second.proof_hash,1005),false);
  assert.throws(()=>journal.reserve(lease,second.proof_hash,'initialize',
    {blockhash:second.program,lastValidBlockHeight:'100',maxDebitLamports:'5000'},1005),/ownership/i);
  const restored=new RelayJournal(options);t.after(()=>restored.close());
  assert.equal(restored.claimResources(lease,second.proof_hash,1006),false);
  journal.recordReceipt(lease,first.proof_hash,{schema_version:1,proof_hash:first.proof_hash,mint:first.mint,finder:first.finder,context_slot:floor},1007);
  for(const [i,id] of ['close-stage','deactivate-table','close-table'].entries())journal.observeStep(lease,first.proof_hash,id,{slot:floor},1008+i);
  assert.equal(journal.claimResources(lease,second.proof_hash,1011),false,'cleanup observations alone do not release ownership');
  journal.complete(lease,first.proof_hash,1012);
  assert.equal(journal.claimResources(lease,second.proof_hash,1013),true);
  assert.throws(()=>journal.claimResources(lease,first.proof_hash,1014),/completed/i);
});
