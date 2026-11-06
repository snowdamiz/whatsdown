import { DatabaseSync } from 'node:sqlite';
import { closeSync, chmodSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname } from 'node:path';
import { prepareRewardsTransaction, rewardsMessage, rewardsSignedStep, rewardsCoordinate } from './transactions.mjs';

const LEASE_MS=30000;
const fail=message=>{throw new Error(message);};
const json=JSON.stringify;
const amount=rewardsCoordinate;
function time(value){if(!Number.isSafeInteger(value)||value<0||value>Number.MAX_SAFE_INTEGER-LEASE_MS)fail('Invalid rewards clock');}
function label(value){if(typeof value!=='string'||!value.length||value.length>256)fail('Invalid rewards lease identity');}

// One explicit operator request per durable journal. SQLite FULL transactions
// persist reservations and signed bytes before the broadcast capability exists.
// A lease is checked again after every asynchronous signer/RPC operation.
export class RewardsJournal {
  #db;#pins;#policy;
  constructor({path,pins,request,policy}){
    if(typeof path!=='string'||!path.length||path===':memory:')fail('Rewards journal requires a durable path');
    if(amount(policy?.maxLamports)===0n||!Number.isSafeInteger(policy.maxTransactions)||policy.maxTransactions<1||policy.maxTransactions>4096)fail('Invalid rewards budget');
    this.#pins=structuredClone(pins);this.#policy=structuredClone(policy);
    const scope=json({version:1,pins,request,policy});if(scope.length>16384)fail('Rewards journal scope too large');
    mkdirSync(dirname(path),{recursive:true,mode:0o700});
    try{closeSync(openSync(path,'wx',0o600));}catch(error){if(error.code!=='EEXIST')throw error;}
    if(!lstatSync(path).isFile())fail('Rewards journal must be a regular file');chmodSync(path,0o600);
    this.#db=new DatabaseSync(path);
    try{
      this.#db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
      this.#atomic(()=>{
        this.#db.exec(`CREATE TABLE IF NOT EXISTS rewards_scope(singleton INTEGER PRIMARY KEY CHECK(singleton=1),scope TEXT NOT NULL,
          clock INTEGER NOT NULL DEFAULT 0,owner TEXT,generation INTEGER NOT NULL DEFAULT 0,lease_until INTEGER NOT NULL DEFAULT 0,
          context_slot TEXT NOT NULL DEFAULT '0',spent TEXT NOT NULL DEFAULT '0',attempts INTEGER NOT NULL DEFAULT 0,halted INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS rewards_transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,phase TEXT NOT NULL,
          plan TEXT NOT NULL,quote TEXT NOT NULL,signed TEXT,observation TEXT,broadcast_at INTEGER NOT NULL DEFAULT 0);
          CREATE UNIQUE INDEX IF NOT EXISTS rewards_one_pending ON rewards_transactions((1)) WHERE phase IN ('reserved','signed');
          CREATE UNIQUE INDEX IF NOT EXISTS rewards_unique_signature ON rewards_transactions(json_extract(signed,'$.signature')) WHERE signed IS NOT NULL;`);
        this.#run('INSERT OR IGNORE INTO rewards_scope(singleton,scope) VALUES(1,?)',scope);
        if(this.#scope().scope!==scope)fail('Rewards journal scope changed');
      });
    }catch(error){this.#db.close();throw error;}
  }
  #run(sql,...args){return this.#db.prepare(sql).run(...args);}
  #get(sql,...args){return this.#db.prepare(sql).get(...args);}
  #scope(){return this.#get('SELECT * FROM rewards_scope WHERE singleton=1');}
  #atomic(fn){this.#db.exec('BEGIN IMMEDIATE');try{const result=fn();this.#db.exec('COMMIT');return result;}catch(error){this.#db.exec('ROLLBACK');throw error;}}
  #write(lease,now,fn){
    time(now);return this.#atomic(()=>{
      const scope=this.#scope();if(now<scope.clock)fail('Rewards clock moved backwards');
      if(lease&&(lease.owner!==scope.owner||lease.generation!==scope.generation||now>=scope.lease_until))fail('Rewards lease expired or superseded');
      this.#run('UPDATE rewards_scope SET clock=? WHERE singleton=1',now);return fn(scope);
    });
  }
  close(){this.#db.close();}
  claim(owner,now){
    label(owner);return this.#write(null,now,scope=>{
      if(scope.owner!==null&&scope.lease_until>now)fail('Rewards lease held');
      const generation=scope.generation+1;
      this.#run('UPDATE rewards_scope SET owner=?,generation=?,lease_until=? WHERE singleton=1',owner,generation,now+LEASE_MS);
      return {owner,generation};
    });
  }
  renew(lease,now){return this.#write(lease,now,()=>this.#run('UPDATE rewards_scope SET lease_until=? WHERE singleton=1',now+LEASE_MS));}
  release(lease,now){return this.#write(lease,now,()=>this.#run('UPDATE rewards_scope SET owner=NULL,lease_until=0 WHERE singleton=1'));}
  progress(){const s=this.#scope();return {contextSlot:s.context_slot,spentLamports:s.spent,attempts:s.attempts,halted:!!s.halted};}
  pending(){
    const row=this.#get("SELECT * FROM rewards_transactions WHERE phase IN ('reserved','signed')");
    return row?{id:row.id,phase:row.phase,plan:JSON.parse(row.plan),quote:JSON.parse(row.quote),signed:row.signed?JSON.parse(row.signed):null}:null;
  }
  observeContext(lease,slot,now){
    amount(slot);return this.#write(lease,now,scope=>{
      if(amount(slot)<amount(scope.context_slot))fail('Rewards context regressed');
      this.#run('UPDATE rewards_scope SET context_slot=? WHERE singleton=1',slot);
    });
  }
  reserve(lease,plan,quote,now){
    plan=structuredClone(plan);quote=structuredClone(quote);
    const step=prepareRewardsTransaction(plan,this.#pins);
    const info=rewardsMessage(step,{blockhash:quote.blockhash,lastValidBlockHeight:amount(quote.lastValidBlockHeight)});
    if(quote.messageHash!==info.messageHash||quote.minContextSlot!==info.minContextSlot||amount(quote.contextSlot)<amount(info.minContextSlot)||amount(quote.maxDebitLamports)===0n)fail('Invalid rewards quote');
    return this.#write(lease,now,scope=>{
      if(scope.halted)fail('Rewards journal halted');
      if(this.pending())fail('Rewards transaction pending');
      if(amount(plan.context_slot)<amount(scope.context_slot))fail('Rewards context regressed');
      if(this.#get('SELECT id FROM rewards_transactions WHERE signed IS NOT NULL AND json_extract(quote,\'$.messageHash\')=?',quote.messageHash))fail('Rewards blockhash already used for this message');
      if(scope.attempts>=this.#policy.maxTransactions||amount(scope.spent)+amount(quote.maxDebitLamports)>amount(this.#policy.maxLamports))fail('Rewards budget exhausted');
      this.#run('UPDATE rewards_scope SET attempts=attempts+1,context_slot=? WHERE singleton=1',quote.contextSlot);
      this.#run("INSERT INTO rewards_transactions(phase,plan,quote) VALUES('reserved',?,?)",json(plan),json(quote));
      return this.pending();
    });
  }
  abandonUnsigned(lease,now){return this.#write(lease,now,()=>{
    const pending=this.pending();if(!pending||pending.phase!=='reserved'||pending.signed!==null)fail('Expected unsigned rewards reservation');
    this.#run("UPDATE rewards_transactions SET phase='abandoned' WHERE id=?",pending.id);
  });}
  async recordSigned(lease,signed,clock){
    if(typeof clock!=='function')fail('Rewards signature persistence requires a fresh clock');
    signed=structuredClone(signed);const pending=this.pending();if(!pending||pending.phase!=='reserved')fail('Expected unsigned rewards reservation');
    const step=prepareRewardsTransaction(pending.plan,this.#pins);
    const info=await rewardsSignedStep(step,signed);
    if(info.messageHash!==pending.quote.messageHash||signed.lastValidBlockHeight!==pending.quote.lastValidBlockHeight)fail('Rewards signature differs from reservation');
    this.#write(lease,clock(),()=>{
      const current=this.pending();if(current?.id!==pending.id||current.phase!=='reserved')fail('Rewards reservation changed');
      this.#run("UPDATE rewards_transactions SET phase='signed',signed=? WHERE id=?",json(signed),pending.id);
    });
  }
  authorizeBroadcast(lease,now){return this.#write(lease,now,()=>{
    const row=this.#get("SELECT * FROM rewards_transactions WHERE phase IN ('reserved','signed')");
    if(!row||row.phase!=='signed'||row.signed===null)fail('Expected durably signed rewards packet');
    if(row.broadcast_at&&now-row.broadcast_at<1000)return null;
    this.#run('UPDATE rewards_transactions SET broadcast_at=? WHERE id=?',now,row.id);
    return JSON.parse(row.signed);
  });}
  finish(lease,observation,now){
    observation=structuredClone(observation);amount(observation?.slot);
    return this.#write(lease,now,scope=>{
      const row=this.pending();if(!row||row.phase!=='signed')fail('Expected signed rewards reservation');
      if(amount(observation.slot)<amount(scope.context_slot)||amount(observation.slot)<amount(row.quote.contextSlot))fail('Rewards observation context regressed');
      let debit;
      if(observation.state==='finalized'){
        if(typeof observation.success!=='boolean')fail('Invalid rewards finality');debit=amount(observation.debitLamports);
      }else if(observation.state==='effect'||observation.state==='expired'){
        if(amount(observation.blockHeight)<=amount(row.signed.lastValidBlockHeight))fail('Invalid rewards expiry barrier');
        // An oldest available block is not continuous transaction history. A
        // mutable effect may disappear after execution (e.g. append/cancel).
        // Missing transaction metadata never proves zero fees, in either version.
        debit=amount(row.quote.maxDebitLamports);
      }else fail('Invalid rewards terminal observation');
      const spent=amount(scope.spent)+debit;
      this.#run('UPDATE rewards_scope SET context_slot=?,spent=?,halted=? WHERE singleton=1',observation.slot,spent.toString(),
        spent>amount(this.#policy.maxLamports)||debit>amount(row.quote.maxDebitLamports)?1:0);
      this.#run('UPDATE rewards_transactions SET phase=?,observation=? WHERE id=?',observation.state,json(observation),row.id);
    });
  }
}
