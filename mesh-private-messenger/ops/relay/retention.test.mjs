import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { RelayJournal, RELAY_TRANSACTION_LIMIT } from './journal.mjs';
import { prepareRelayTransactions, signRelayStep } from './transactions.mjs';
import { createRelayService } from './service.mjs';

if(!process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH)throw new Error('Run scripts/prove-relay-writer.sh for Mesh plans');
const plans=(await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
const plan=plans[0],signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const life={blockhash:'11111111111111111111111111111111',lastValidBlockHeight:9007199254740993n};
const quote={...life,lastValidBlockHeight:String(life.lastValidBlockHeight),maxDebitLamports:'60'};
const floor=String(BigInt(plan.context_slot)+100n),week=7*86400000;
const step=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex}).preparation[0];
async function fixture(t){
  const directory=await mkdtemp(join(tmpdir(),'relay-retention-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const options={path:join(directory,'relay.sqlite'),identity:'local:retention',pins:plan,policy:{perJobLamports:'100',windowLamports:'200',maxJobs:1}};
  let journal=new RelayJournal(options),now=1000,lease=journal.claim('worker',now++);journal.accept(plan,now++);t.after(()=>journal.close());
  const sql=fn=>{const db=new DatabaseSync(options.path);try{return fn(db);}finally{db.close();}};
  return {options,sql,get journal(){return journal;},get lease(){return lease;},get now(){return now;},time:()=>now++,
    advance(ms){now+=ms;lease=journal.claim(`worker-${now}`,now++);assert.ok(lease);},
    restart(){journal.close();journal=new RelayJournal(options);},
    async failed(){const tx=journal.reserve(lease,plan.proof_hash,'initialize',quote,now++);await journal.recordSigned(lease,tx.id,await signRelayStep(step,signer,life),now++);journal.finalize(lease,tx.id,{success:false,debitLamports:'45',slot:floor},now++);return tx;},
    complete(){journal.recordReceipt(lease,plan.proof_hash,{schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder,context_slot:floor},now++);journal.observeCleanup(lease,plan.proof_hash,'close-stage',{slot:floor},now++);journal.complete(lease,plan.proof_hash,now++);},
    count(){return sql(db=>db.prepare('SELECT count(*) AS n FROM relay_transactions').get().n);},
  };
}

test('old signed history compacts without resetting job charges, context, signed ownership or blockhash lifetime',async t=>{
  const f=await fixture(t),tx=await f.failed();f.advance(week-100);f.journal.maintain(f.lease,f.time());assert.equal(f.count(),1);
  f.advance(60001);const result=f.journal.maintain(f.lease,f.time());assert.equal(result.transactions,1);assert.equal(f.count(),0);
  f.restart();assert.equal(f.journal.progress(plan.proof_hash).minContextSlot,floor);
  assert.equal(f.journal.retention().lastValidBlockHeight,String(life.lastValidBlockHeight));
  assert.deepEqual(f.journal.budget(f.now),{chargedLamports:'0',reservedLamports:'0',halted:false});
  assert.throws(()=>f.journal.transaction(tx.id),/Unknown/);
  f.journal.observeContext(f.lease,plan.proof_hash,floor,f.time());
  assert.throws(()=>f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time()),/retained.*lifetime/);
  const fresh={...quote,blockhash:plan.program,lastValidBlockHeight:String(life.lastValidBlockHeight+1n)};
  assert.throws(()=>f.journal.reserve(f.lease,plan.proof_hash,'initialize',fresh,f.time()),/job budget/);
  const next=f.journal.reserve(f.lease,plan.proof_hash,'initialize',{...fresh,maxDebitLamports:'55'},f.time());
  assert.ok(next.id>tx.id,'compaction must not reuse transaction identities');
  await assert.rejects(f.journal.recordSigned(f.lease,next.id,await signRelayStep(step,signer,life),f.time()),/lifetime|signature|transaction/);
  f.journal.abandonUnsigned(f.lease,next.id,f.time());
  f.journal.recordReceipt(f.lease,plan.proof_hash,{schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder,context_slot:floor},f.time());
  assert.equal(f.journal.completeUnspent(f.lease,plan.proof_hash,f.time()),false,'signed history survives packet compaction');
});

test('recent charges and every unresolved packet survive retention, including an expired worker',async t=>{
  const f=await fixture(t);await f.failed();assert.equal(f.journal.maintain(f.lease,f.time()).transactions,0);
  assert.equal(f.journal.budget(f.now).chargedLamports,'45');
  const tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',{...quote,maxDebitLamports:'50'},f.time());
  const old=f.lease;f.advance(week+1);assert.throws(()=>f.journal.maintain(old,f.time()),/lease/);
  assert.equal(f.journal.maintain(f.lease,f.time()).state,'pending');assert.equal(f.journal.pending().id,tx.id);
  assert.equal(f.journal.budget(f.now).reservedLamports,'50');assert.equal(f.count(),2);
});

test('receipt-backed completed jobs free capacity only after retention and preserve a global admission context floor',async t=>{
  const f=await fixture(t);await f.failed();f.complete();f.advance(week+1);
  const result=f.journal.maintain(f.lease,f.time());assert.equal(result.jobs,1);assert.equal(f.count(),0);assert.equal(f.journal.jobs().length,0);
  f.restart();assert.equal(f.journal.retention().minContextSlot,floor);assert.throws(()=>f.journal.accept(plan,f.time()),/retained.*context/);
  let observedFloor;
  const service=createRelayService({journal:f.journal,now:f.time,verifier:{admit:async(_wire,minimum)=>{observedFloor=minimum;return {schema_version:1,status:'settled',receipt:{proof_hash:plan.proof_hash,finder:plan.finder}};}},scheduler:{tick:async()=>({state:'idle'})}});
  const retry=service.submit(Buffer.from(plan.proof_hex,'hex'));await service.cycle();assert.equal((await retry).status,'settled');assert.equal(observedFloor,floor);assert.equal(f.journal.jobs().length,0);await service.close();
  const next={...plans[6],context_slot:floor};f.journal.accept(next,f.time());assert.equal(f.journal.jobs().length,1);
});

test('unsigned crash records are bounded without losing recent fees or releasing a pending reservation',async t=>{
  const f=await fixture(t);
  for(let i=0;i<70;i++){const tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time());f.journal.abandonUnsigned(f.lease,tx.id,f.time());}
  const result=f.journal.maintain(f.lease,f.time());assert.equal(result.transactions,38);assert.equal(f.count(),32);
  assert.equal(f.journal.retention().lastValidBlockHeight,'0');assert.equal(f.journal.budget(f.now).chargedLamports,'0');
});

test('storage capacity fails closed before another reservation and cleanup compaction is bounded per pass',async t=>{
  const f=await fixture(t);const tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time());f.journal.abandonUnsigned(f.lease,tx.id,f.time());
  f.sql(db=>db.prepare(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
    INSERT INTO relay_transactions (proof,step,phase,max_debit,blockhash,last_valid_height,message_hash,min_context_slot)
    SELECT proof,step,phase,max_debit,blockhash,last_valid_height,message_hash,min_context_slot FROM n,relay_transactions WHERE id=?`).run(RELAY_TRANSACTION_LIMIT-1,tx.id));
  assert.equal(f.count(),RELAY_TRANSACTION_LIMIT);
  assert.throws(()=>f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time()),/transaction capacity/);
  assert.equal(f.journal.maintain(f.lease,f.time()).transactions,256);assert.equal(f.count(),RELAY_TRANSACTION_LIMIT-256);
});

test('v1 migration retains exact packets and rejects an active legacy worker before changing the schema version',async t=>{
  const f=await fixture(t);const tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time());
  const signed=await signRelayStep(step,signer,life);await f.journal.recordSigned(f.lease,tx.id,signed,f.time());
  f.sql(db=>db.prepare('UPDATE relay_scope SET version=1, lease_until=?').run(Date.now()+60000));
  assert.throws(()=>new RelayJournal(f.options),/legacy.*worker/);assert.equal(f.sql(db=>db.prepare('SELECT version FROM relay_scope').get().version),1);
  f.sql(db=>db.prepare('UPDATE relay_scope SET lease_until=0').run());f.restart();
  assert.equal(f.sql(db=>db.prepare('SELECT version FROM relay_scope').get().version),2);assert.deepEqual(f.journal.pending().signed,signed);
  assert.equal(f.journal.budget(f.now).reservedLamports,'60');
});


test('a corrupt history row rolls back the whole maintenance batch without losing earlier unsigned rows',async t=>{
  const f=await fixture(t);
  for(let i=0;i<40;i++){const tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time());f.journal.abandonUnsigned(f.lease,tx.id,f.time());}
  const tx=await f.failed();f.sql(db=>db.prepare('UPDATE relay_transactions SET observation=? WHERE id=?').run('{"slot":"bad"}',tx.id));
  f.advance(week+1);assert.throws(()=>f.journal.maintain(f.lease,f.time()),/coordinate/);
  assert.equal(f.count(),41);assert.equal(f.journal.retention().minContextSlot,'0');
  assert.equal(f.sql(db=>db.prepare('SELECT count(*) AS n FROM relay_compacted').get().n),0);
});

test('legacy completion without a receipt context is retained until a fresh authenticated receipt supplies it',async t=>{
  const f=await fixture(t),receipt={schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,finder:plan.finder};
  f.journal.recordReceipt(f.lease,plan.proof_hash,receipt,f.time());assert.equal(f.journal.completeUnspent(f.lease,plan.proof_hash,f.time()),true);
  f.advance(week+1);assert.equal(f.journal.maintain(f.lease,f.time()).jobs,0);assert.equal(f.journal.jobs().length,1);
  f.journal.recordReceipt(f.lease,plan.proof_hash,{...receipt,context_slot:floor},f.time());
  f.advance(60001);assert.equal(f.journal.maintain(f.lease,f.time()).jobs,1);assert.equal(f.journal.retention().minContextSlot,floor);
});

test('a real quote overrun remains halted after its completed job and transaction history are pruned',async t=>{
  const f=await fixture(t),tx=f.journal.reserve(f.lease,plan.proof_hash,'initialize',quote,f.time());
  await f.journal.recordSigned(f.lease,tx.id,await signRelayStep(step,signer,life),f.time());
  f.journal.finalize(f.lease,tx.id,{success:false,debitLamports:'90',slot:floor},f.time());f.complete();
  f.advance(week+1);assert.equal(f.journal.maintain(f.lease,f.time()).jobs,1);f.restart();
  assert.equal(f.journal.budget(f.now).halted,true);assert.equal(f.journal.budget(f.now).chargedLamports,'0');
  const next={...plans[6],context_slot:floor};f.journal.accept(next,f.time());
  assert.throws(()=>f.journal.reserve(f.lease,next.proof_hash,'initialize',quote,f.time()),/halted/);
});
