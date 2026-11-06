import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RelayJournal } from './journal.mjs';
import { prepareRelayTransactions } from './transactions.mjs';

if(!process.env.MORSE_RELAY_PLAN_REVISIONS_PATH)throw new Error('Run scripts/prove-relay-writer.sh for Mesh revision plans');
const cases=(await readFile(process.env.MORSE_RELAY_PLAN_REVISIONS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
async function setup(t,entry=cases[0]){
  const directory=await mkdtemp(join(tmpdir(),'morse-relay-revisions-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const options={path:join(directory,'relay.sqlite'),identity:'local:revisions',pins:entry.original,
    policy:{perJobLamports:'1000000000',windowLamports:'1000000000',maxJobs:8}};
  const journal=new RelayJournal(options);t.after(()=>journal.close());
  journal.accept(entry.original,1000);const lease=journal.claim('worker',1001);
  return {journal,lease,options,...entry};
}
function table(plan,status='extending',floor=plan.context_slot){
  return {schema_version:1,status,address:plan.lookup.address,authority:plan.submitter,
    creationSlot:plan.lookup.recent_slot,contextSlot:floor,lastExtendedSlot:status==='missing'?'0':plan.lookup.recent_slot,
    deactivationSlot:status==='cooling'?plan.lookup.recent_slot:'18446744073709551615',remainingBlocks:status==='cooling'?513:0,
    addresses:status==='missing'?[]:plan.lookup.addresses.slice(0,10)};
}

test('fresh Mesh plans replace unsigned work while preserving the original evidence, finder and spending history',async t=>{
  assert.equal(cases.length,19);
  for(const entry of cases){
    const {journal,lease,options,original,later}=await setup(t,entry);
    assert.equal(journal.revisePlan(lease,original.proof_hash,later,1002).state,'updated');
    assert.deepEqual(journal.job(original.proof_hash).plan,later);
    assert.deepEqual(journal.originalPlan(original.proof_hash),original);
    const restored=new RelayJournal(options);t.after(()=>restored.close());
    assert.deepEqual(restored.job(original.proof_hash).plan,later);
    assert.deepEqual(restored.originalPlan(original.proof_hash),original);
    assert.equal(journal.budget(1002).chargedLamports,'0');
    assert.throws(()=>journal.revisePlan(lease,original.proof_hash,original,1003),/context/i);
    assert.throws(()=>journal.revisePlan(lease,original.proof_hash,{...later,finder:later.program},1004),/identity/i);
  }
});

test('custody revisions retain unchanged upload work and invalidate only changed verification recipes',async t=>{
  for(const entry of cases.filter(value=>value.withdrawn)){
    const {journal,lease,original,withdrawn}=await setup(t,entry);
    journal.observeStep(lease,original.proof_hash,'initialize',{slot:original.context_slot},1002);
    const prepared=prepareRelayTransactions(original,{...original,proofHex:original.proof_hex});
    for(const [index,step] of prepared.preparation.filter(value=>value.kind==='verify').entries()){
      journal.observeStep(lease,original.proof_hash,step.id,{slot:original.context_slot},1003+index);
    }
    assert.equal(journal.revisePlan(lease,original.proof_hash,withdrawn,1010).state,'updated');
    const next=prepareRelayTransactions(withdrawn,{...withdrawn,proofHex:withdrawn.proof_hex});
    const done=journal.progress(original.proof_hash).done;
    assert.ok(done.includes('initialize'));
    assert.ok(done.every(id=>next.preparation.some(step=>step.id===id)));
    assert.equal(done.includes('verify/1'),false,'withdrawn witness verification is no longer scheduled');
  }
});

test('owned active lookup tables survive context refresh; cooling tables retire before replacement',async t=>{
  for(const entry of cases.slice(15)){
    const {journal,lease,options,original,later}=await setup(t,entry);
    assert.equal(journal.claimResources(lease,original.proof_hash,1002),true);
    journal.observeStep(lease,original.proof_hash,'create-table',{slot:original.context_slot},1003);
    const active=table(original,'extending',later.context_slot);
    assert.equal(journal.revisePlan(lease,original.proof_hash,later,1004,active).state,'updated');
    const current=journal.job(original.proof_hash).plan;
    assert.deepEqual(current.lookup,original.lookup);
    assert.equal(current.context_slot,later.context_slot);
    assert.ok(journal.progress(original.proof_hash).done.includes('create-table'));
    assert.ok(current.rent_allocations.filter(value=>value.step.includes('table')).every(value=>value.address===original.lookup.address));
    assert.equal(journal.revisePlan(lease,original.proof_hash,later,1005,table(original,'cooling',later.context_slot)).state,'retire-table');
    assert.deepEqual(journal.job(original.proof_hash).plan,current);
    assert.equal(journal.revisePlan(lease,original.proof_hash,later,1006,table(original,'missing',later.context_slot)).state,'updated');
    assert.equal(journal.job(original.proof_hash).plan.lookup.address,later.lookup.address);
    assert.equal(journal.progress(original.proof_hash).done.includes('create-table'),false);
    assert.deepEqual(journal.resources(original.proof_hash).sort(),[original.stage.address,later.lookup.address].sort());
    const restored=new RelayJournal(options);t.after(()=>restored.close());
    assert.deepEqual(restored.resources(original.proof_hash),journal.resources(original.proof_hash));
  }
});

test('revisions cannot bypass pending packets, settled receipts, ownership conflicts, or lookup identity/context',async t=>{
  const {journal,lease,original,later}=await setup(t,cases[15]);
  journal.claimResources(lease,original.proof_hash,1002);
  for(const view of [undefined,table(original,'missing','0'),{...table(original,'missing',later.context_slot),address:original.program},
    {...table(original,'extending',later.context_slot),addresses:[original.program]}]){
    assert.throws(()=>journal.revisePlan(lease,original.proof_hash,later,1003,view),/lookup|context/i);
  }
  journal.reserve(lease,original.proof_hash,'initialize',{blockhash:original.program,lastValidBlockHeight:'100',maxDebitLamports:'5000'},1004);
  assert.throws(()=>journal.revisePlan(lease,original.proof_hash,later,1005,table(original,'missing',later.context_slot)),/pending/i);
  assert.throws(()=>journal.observeContext(lease,original.proof_hash,later.context_slot,1006),/pending/i);
  journal.abandonUnsigned(lease,journal.pending().id,1007);
  journal.revisePlan(lease,original.proof_hash,later,1008,table(original,'missing',later.context_slot));
  journal.accept(cases[16].original,1009);
  assert.equal(journal.revisePlan(lease,cases[16].original.proof_hash,cases[16].later,1010).state,'resource-busy');
  assert.deepEqual(journal.job(cases[16].original.proof_hash).plan,cases[16].original);
  journal.recordReceipt(lease,original.proof_hash,{schema_version:1,proof_hash:original.proof_hash,mint:original.mint,finder:original.finder},1011);
  assert.throws(()=>journal.revisePlan(lease,original.proof_hash,later,1012,table(later,'missing')),/settled/i);
});

test('new authenticated read contexts bind future packets without changing the accepted plan or instructions',async t=>{
  const {journal,lease,original}=await setup(t);
  const slot='9007199254740993';
  journal.observeContext(lease,original.proof_hash,slot,1002);
  assert.equal(journal.job(original.proof_hash).plan.context_slot,slot);
  assert.deepEqual(journal.originalPlan(original.proof_hash),original);
  assert.deepEqual(journal.job(original.proof_hash).plan.settlement,original.settlement);
  assert.equal(journal.progress(original.proof_hash).minContextSlot,slot);
  assert.throws(()=>journal.observeContext(lease,original.proof_hash,'1',1003),/context/i);
  assert.throws(()=>journal.observeContext(lease,original.proof_hash,slot,31002),/lease/i);
});
