import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { AccountRole, appendTransactionMessageInstructions, createTransactionMessage, createKeyPairSignerFromPrivateKeyBytes,
  getAddressDecoder, getTransactionDecoder, getCompiledTransactionMessageDecoder, getBase64EncodedWireTransaction,
  setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { prepareRelayTransactions, relayStepMessage, signRelayStep } from './transactions.mjs';
import { RelayJournal } from './journal.mjs';
import { connectRelayRpc } from './rpc.mjs';
import { recoverRelayPending } from './writer.mjs';

const required=name=>{const value=process.env[name];if(!value)throw new Error(`Missing ${name}; run scripts/prove-relay-writer.sh`);return value;};
const plans=(await readFile(required('MORSE_RELAY_SETTLEMENT_PLANS_PATH'),'utf8')).trim().split('\n').map(JSON.parse);
const fixtures=(await Promise.all(['MORSE_ADJUDICATION_FIXTURES_PATH','MORSE_RELAY_ANCHORED_FIXTURES_PATH','MORSE_RELAY_MAXIMUM_FIXTURES_PATH']
  .map(async name=>JSON.parse(await readFile(required(name),'utf8'))))).flat();
assert.equal(plans.length,19);assert.equal(fixtures.length,19);
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const decodeKey=bytes=>getAddressDecoder().decode(bytes);
const recoveryPath=required('MORSE_RELAY_STAGE_READ_FIXTURES_PATH');
const lookupRecoveryPath=required('MORSE_RELAY_LOOKUP_READ_FIXTURES_PATH');
const settlementRecoveryPath=required('MORSE_RELAY_SETTLEMENT_READ_FIXTURES_PATH');

class Bridge {
  constructor(){
    const binary=process.env.MORSE_RELAY_SBF_BRIDGE??fileURLToPath(new URL('../../programs/target/debug/examples/relay_writer_bridge',import.meta.url));
    this.child=spawn(binary,[],{stdio:['pipe','pipe','pipe'],env:process.env});this.stderr='';
    this.child.stderr.on('data',value=>{this.stderr+=value;});
    this.exit=once(this.child,'exit');
    this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();
  }
  async ask(request){
    await new Promise((resolve,reject)=>this.child.stdin.write(JSON.stringify(request)+'\n',error=>error?reject(error):resolve()));
    let timer;
    try {
      const next=await Promise.race([this.lines.next(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Bridge timeout: '+this.stderr)),5000);})]);
      assert.equal(next.done,false,this.stderr);return JSON.parse(next.value);
    } finally {clearTimeout(timer);}
  }
  async close(){this.child.stdin.end('{"method":"stop"}\n');const [code]=await this.exit;assert.equal(code,0,this.stderr);}
  async kill(){if(this.child.exitCode===null)this.child.kill('SIGKILL');await this.exit;}
}

async function lookupView(bridge,plan){
  const current=await bridge.ask({method:'context'});
  const account=await bridge.ask({method:'account',address:plan.lookup.address});
  assert.equal(account.owner,'AddressLookupTab1e1111111111111111111111111');
  const raw=Buffer.from(account.data_hex,'hex');
  assert.equal(raw.readUInt32LE(0),1);assert.equal(raw[21],1);
  const addresses=[];for(let n=56;n<raw.length;n+=32)addresses.push(decodeKey(raw.subarray(n,n+32)));
  return {schema_version:1,status:BigInt(current.slot)>raw.readBigUInt64LE(12)?'ready':'warm',address:plan.lookup.address,authority:decodeKey(raw.subarray(22,54)),addresses,contextSlot:current.slot,
    creationSlot:plan.lookup.recent_slot,
    lastExtendedSlot:raw.readBigUInt64LE(12).toString(),deactivationSlot:raw.readBigUInt64LE(4).toString()};
}
// Deliberately construct invalid close attempts outside the production signer
// to keep testing the chain's independent cooldown enforcement.
async function prematureCloseProbe(bridge,plan){
  const context=await bridge.ask({method:'context'}),report=plan.lookup.close;
  const accounts=report.accountKeys.map(address=>({address,role:report.signerKeys.includes(address)?
    (report.writableKeys.includes(address)?AccountRole.WRITABLE_SIGNER:AccountRole.READONLY_SIGNER):
    (report.writableKeys.includes(address)?AccountRole.WRITABLE:AccountRole.READONLY)}));
  let message=createTransactionMessage({version:0});
  message=setTransactionMessageFeePayerSigner(signer,message);
  message=setTransactionMessageLifetimeUsingBlockhash({blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.lastValidBlockHeight)},message);
  message=appendTransactionMessageInstructions([{programAddress:report.programId,accounts,data:Buffer.from(report.dataBase64,'base64')}],message);
  return bridge.ask({method:'send',wire:getBase64EncodedWireTransaction(await signTransactionMessageWithSigners(message))});
}
const accountBytes=async (bridge,address)=>Buffer.from((await bridge.ask({method:'account',address})).data_hex,'hex');
async function captureLookup(bridge,plan,snapshots,status,remaining,stepId){
  const context=await bridge.ask({method:'context'});
  snapshots.push({slot:context.slot,table:await bridge.ask({method:'account',address:plan.lookup.address}),
    clock:await bridge.ask({method:'account',address:'SysvarC1ock11111111111111111111111111111111'}),
    history:await bridge.ask({method:'account',address:'SysvarS1otHashes111111111111111111111111111'}),
    expected_status:status,remaining_blocks:remaining,step_id:stepId});
}
async function captureSettlement(bridge,plan,snapshots,stepId){
  const context=await bridge.ask({method:'context'}),accounts=[];
  for(const address of [plan.log,plan.settlement.accountKeys[3],plan.mint,plan.receipt,plan.setup[0].accountKeys[1],plan.setup[1].accountKeys[1]]){
    accounts.push({address,value:await bridge.ask({method:'account',address})});
  }
  snapshots.push({slot:context.slot,step_id:stepId,accounts});
}

test('fresh Mesh plans and journaled Kit signatures survive restarts and execute real SBF payouts, lookup activation, replay refusal and rent recovery', {timeout:120000},async t=>{
  let lookups=0,batches=0,failedFees=0;
  const recoveries=[];
  const lookupRecoveries=[];
  const settlementRecoveries=[];
  for(let index=0;index<plans.length;index++){
    const plan=plans[index],fixture=fixtures[index];assert.equal(plan.program,fixture.program);
    const pins={program:plan.program,log:plan.log,mint:plan.mint,submitter:signer.address,proofHex:plan.proof_hex};
    const prepared=prepareRelayTransactions(plan,pins);
    const directory=await mkdtemp(join(tmpdir(),'morse-relay-sbf-journal-'));
    const options={path:join(directory,'relay.sqlite'),identity:'local:sbf:relay',pins,
      policy:{perJobLamports:'1000000000',windowLamports:'1000000000',maxJobs:1}};
    let journal=new RelayJournal(options),now=1000;
    journal.accept(plan,now++);let lease=journal.claim('original',now++);
    assert.equal(journal.claimResources(lease,plan.proof_hash,now++),true);
    function restart(){
      journal.close();journal=new RelayJournal(options);now+=30001;
      lease=journal.claim('restarted',now++);assert.ok(lease);
      assert.equal(journal.claimResources(lease,plan.proof_hash,now++),true);
    }
    const bridge=new Bridge();
    const snapshots=[],verified=[],lookupSnapshots=[],settlementSnapshots=[];let received=0,sealed=false;
    recoveries.push({program:plan.program,log_name:fixture.log_name,service_key:fixture.service_key,
      version:fixture.version,submitter:signer.address,proof_hex:plan.proof_hex,snapshots});
    settlementRecoveries.push({program:plan.program,log_name:fixture.log_name,service_key:fixture.service_key,
      version:fixture.version,submitter:signer.address,mint:plan.mint,proof_hex:plan.proof_hex,
      proof_hash:plan.proof_hash,receipt_address:plan.receipt,snapshots:settlementSnapshots});
    try {
      await bridge.ask({method:'initialize',fixture,payer:signer.address});
      async function send(step,view,probe=false){
        const context=await bridge.ask({method:'context'});
        const lifetime={blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.lastValidBlockHeight)};
        let reservation,chain,observed,quote;
        const info=relayStepMessage(step,lifetime,view),rents=new Map();
        for(const allocation of info.rentAllocations){
          rents.set(BigInt(allocation.space),BigInt((await bridge.ask({method:'rent',space:allocation.space})).lamports));
        }
        const genesisHash='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
        // These three responses share a local bank oracle. This exercises
        // the adapter with real SDK rent and SBF balance metadata, not live
        // provider independence/finality. 25,000 covers the tested fees.
        chain=await connectRelayRpc({urls:['https://bank-a.invalid','https://bank-b.invalid','https://bank-c.invalid'],genesisHash},async(_,init)=>{
          const request=parseJsonWithBigInts(init.body),slot=BigInt(context.slot);
          let result;
          if(request.method==='getGenesisHash')result=genesisHash;
          else if(request.method==='getLatestBlockhash')result={context:{slot},value:lifetime};
          else if(request.method==='getFeeForMessage')result={context:{slot},value:25000n};
          else if(request.method==='getMinimumBalanceForRentExemption')result=rents.get(request.params[0]);
          else if(request.method==='getSignatureStatuses')result={context:{slot},value:[{slot,confirmationStatus:'finalized',confirmations:null,err:observed?.meta.err??null}]};
          else if(request.method==='getTransaction')result=observed;
          assert.notEqual(result,undefined,request.method);
          return new Response(stringifyJsonWithBigInts({jsonrpc:'2.0',id:request.id,result}));
        });
        if(!probe){
          quote=await chain.quote(step,view);
          journal.renew(lease,now++);
          reservation=journal.reserve(lease,plan.proof_hash,step.id,quote,now++,view);
        }
        const tx=await signRelayStep(step,signer,lifetime,view);
        let packet=tx;
        if(!probe){
          await journal.recordSigned(lease,reservation.id,tx,now++);
          if(step.kind==='initialize')restart();
          packet=journal.authorizeBroadcast(lease,reservation.id,now++);
          assert.equal(packet.wire,tx.wire);
        }
        const result=await bridge.ask({method:'send',wire:packet.wire});
        if(result.ok){assert.equal(result.signature,tx.signature);assert.ok(result.fee>=5000&&result.fee<=25000);}
        if(probe&&!result.ok&&result.error.includes('InstructionError')){
          observed={slot:BigInt(context.slot),version:0n,transaction:[packet.wire,'base64'],meta:{err:result.error,fee:BigInt(result.fee),
            preBalances:result.pre_balances.map(BigInt),postBalances:result.post_balances.map(BigInt),loadedAddresses:result.loaded_addresses}};
          const failed=await chain.observe(step,packet);
          assert.deepEqual(failed,{state:'finalized',success:false,debitLamports:String(result.fee),slot:context.slot});
          assert.equal(BigInt(result.pre_balances[0])-BigInt(result.post_balances[0]),BigInt(result.fee));
          failedFees++;
        }
        if(!probe){
          assert.equal(result.ok,true,`${index}/${step.id}: ${JSON.stringify(result)}`);
          const balance=await bridge.ask({method:'account',address:signer.address});
          const after={payerBalance:balance.lamports,slot:context.slot};
          if(step.kind==='settle'){
            // The local bank is the finality oracle here. Restart before its
            // result is recorded, then prove the journal still has the exact
            // packet and the bank cannot execute that signature twice.
            restart();assert.equal(journal.pending().signed.wire,packet.wire);
            const retry=journal.authorizeBroadcast(lease,reservation.id,now++);
            const replay=await bridge.ask({method:'send',wire:retry.wire});
            assert.equal(replay.ok,false);assert.match(replay.error,/AlreadyProcessed/);
            assert.equal((await bridge.ask({method:'account',address:signer.address})).lamports,after.payerBalance);
          }
          const netDebit=BigInt(context.payerBalance)-BigInt(after.payerBalance);
          const grossDebit=netDebit>BigInt(result.fee)?netDebit:BigInt(result.fee);
          observed={slot:BigInt(after.slot),version:0n,transaction:[packet.wire,'base64'],meta:{err:null,fee:BigInt(result.fee),
            preBalances:result.pre_balances.map(BigInt),postBalances:result.post_balances.map(BigInt),loadedAddresses:result.loaded_addresses}};
          const recovered=await recoverRelayPending({journal,lease,rpc:chain,now:()=>now++});
          assert.equal(recovered.state,'finalized',`${step.id}: metadata did not authenticate ${stringifyJsonWithBigInts({observed,info:relayStepMessage(step,lifetime,view)})}`);
          assert.equal(journal.transaction(reservation.id).debitLamports,grossDebit.toString());
          assert.ok(journal.progress(plan.proof_hash).done.includes(step.id));
          assert.equal(journal.progress(plan.proof_hash).minContextSlot,after.slot);
          assert.ok(BigInt(quote.maxDebitLamports)>=grossDebit,`${step.id}: full allocation quote covers real SBF debit`);
          if(['initialize','append','seal','verify','close-stage'].includes(step.kind)){
            if(step.kind==='append'){
              const chunk=Buffer.from(plan.stage.append_hex[Number(step.id.split('/')[1])],'hex');
              received=chunk.readUInt16LE(1)+chunk.length-3;
            }
            if(step.kind==='seal')sealed=true;
            if(step.kind==='verify'){
              const message=getCompiledTransactionMessageDecoder().decode(getTransactionDecoder().decode(Buffer.from(packet.wire,'base64')).messageBytes);
              for(let i=1;i<message.instructions.length;i+=2){
                const ordinal=message.instructions[i].data[1];
                const planned=plan.stage.signatures.find(value=>value.ordinal===ordinal);
                verified.push({ordinal,public_key:planned.ed25519_hex.slice(32,96)});
              }
            }
            const closed=step.kind==='close-stage';
            snapshots.push({step_id:step.id,stage:await bridge.ask({method:'account',address:plan.stage.address}),
              log:await bridge.ask({method:'account',address:plan.log}),slot:after.slot,
              expected:{status:closed?'missing':sealed?'sealed':received===plan.proof_hex.length/2?'uploaded':'uploading',
                address:plan.stage.address,total_bytes:plan.proof_hex.length/2,received_bytes:closed?0:received,
                sealed:closed?false:sealed,verified:closed?[]:structuredClone(verified)}});
          }
        }
        return result;
      }
      for(const step of prepared.preparation){
        if(step.id==='setup/0')await captureSettlement(bridge,plan,settlementSnapshots,'before-setup');
        const result=await send(step);assert.equal(result.ok,true,`${index}/${step.id}: ${JSON.stringify(result)}`);
        if(step.kind==='setup')await captureSettlement(bridge,plan,settlementSnapshots,step.id);
        if(step.kind==='verify')batches++;
      }
      let view;
      if(prepared.needsLookup){
        lookups++;
        lookupRecoveries.push({log:plan.log,proof_hex:plan.proof_hex,authority:signer.address,creation_slot:plan.lookup.recent_slot,
          address:plan.lookup.address,addresses:plan.lookup.addresses,snapshots:lookupSnapshots});
        await captureLookup(bridge,plan,lookupSnapshots,'missing',0,'before-create');
        for(const [n,step] of prepared.lookup.entries()){
          const result=await send(step);assert.equal(result.ok,true,JSON.stringify(result));
          await captureLookup(bridge,plan,lookupSnapshots,n===prepared.lookup.length-1?'warm':'extending',0,step.id);
        }
        const warm=await lookupView(bridge,plan);
        await assert.rejects(send(prepared.settlement,warm,true),/lookup/i,'new entries cannot be used in their extension slot');
        await bridge.ask({method:'advance'});view=await lookupView(bridge,plan);
        await captureLookup(bridge,plan,lookupSnapshots,'ready',0,prepared.lookup.at(-1).id);
      }
      const settled=await send(prepared.settlement,view);assert.equal(settled.ok,true,`${index}: ${JSON.stringify(settled)}`);
      await captureSettlement(bridge,plan,settlementSnapshots,'settle');
      assert.ok(settled.units<=1400000);
      const receipt=await accountBytes(bridge,plan.receipt);
      assert.equal(receipt.subarray(0,4).toString('hex'),'4d505201');
      assert.equal(receipt.subarray(40,72).toString('hex'),plan.proof_hash);
      assert.equal(decodeKey(receipt.subarray(72,104)),plan.finder);
      assert.equal(receipt.readBigUInt64LE(240).toString(),plan.estimate.total_slashed_units);
      assert.equal(receipt.readBigUInt64LE(248).toString(),plan.estimate.finder_units);
      journal.recordReceipt(lease,plan.proof_hash,{schema_version:1,proof_hash:plan.proof_hash,mint:plan.mint,
        finder:decodeKey(receipt.subarray(72,104))},now++);
      const finder=plan.settlement.accountKeys[7],locked=plan.settlement.accountKeys[8];
      const paid=(await accountBytes(bridge,finder)).readBigUInt64LE(64);
      assert.equal(paid.toString(),plan.estimate.finder_units);
      assert.equal((await accountBytes(bridge,locked)).readBigUInt64LE(64),BigInt(plan.estimate.total_slashed_units)-paid);
      const repeated=await send(prepared.settlement,view,true);assert.equal(repeated.ok,false);assert.match(repeated.error,/InvalidArgument/);
      assert.equal((await accountBytes(bridge,finder)).readBigUInt64LE(64),paid);
      assert.equal((await send(prepared.cleanup[0])).ok,true);
      const stage=await bridge.ask({method:'account',address:plan.stage.address});assert.ok(!stage||stage.lamports==='0');
      if(prepared.needsLookup){
        assert.equal((await send(prepared.cleanup[1])).ok,true);
        await captureLookup(bridge,plan,lookupSnapshots,'cooling',513,'deactivate-table');
        const rent=BigInt((await bridge.ask({method:'account',address:plan.lookup.address})).lamports);
        await assert.rejects(send(prepared.cleanup[2],undefined,true),/lookup/i);
        assert.equal((await prematureCloseProbe(bridge,plan)).ok,false,'deactivation cooldown is enforced on-chain');
        await bridge.ask({method:'advance_lookup_history'});
        await captureLookup(bridge,plan,lookupSnapshots,'cooling',512,'deactivate-table');
        assert.equal((await prematureCloseProbe(bridge,plan)).ok,false,'a past deactivation slot retained in history still prevents closure');
        await bridge.ask({method:'retire_lookup_history'});
        await captureLookup(bridge,plan,lookupSnapshots,'closable',0,'deactivate-table');
        const before=await bridge.ask({method:'context'});
        // Local bank oracle; the exported account snapshots are independently
        // authenticated by the Mesh cooldown reader in the portable proof.
        const closable={...await lookupView(bridge,plan),status:'closable',remainingBlocks:0};
        const closed=await send(prepared.cleanup[2],closable);assert.equal(closed.ok,true,JSON.stringify(closed));
        const after=await bridge.ask({method:'context'});
        assert.equal(BigInt(after.payerBalance),BigInt(before.payerBalance)+rent-BigInt(closed.fee));
        await captureLookup(bridge,plan,lookupSnapshots,'missing',0,'close-table');
      }
      journal.complete(lease,plan.proof_hash,now++);
      assert.equal(journal.job(plan.proof_hash).state,'complete');
      assert.equal(journal.budget(now++).reservedLamports,'0');
      assert.equal(journal.budget(now++).halted,false);
      await bridge.close();
    } finally {await bridge.kill();journal.close();await rm(directory,{recursive:true,force:true});}
  }
  await writeFile(recoveryPath,JSON.stringify(recoveries));
  await writeFile(lookupRecoveryPath,JSON.stringify(lookupRecoveries));
  await writeFile(settlementRecoveryPath,JSON.stringify(settlementRecoveries));
  assert.ok(lookups>=4);assert.equal(failedFees,plans.length);
  t.diagnostic(`${plans.length} payouts; ${lookups} lookup lifecycles; ${batches} verification batches; ${failedFees} failed-fee observations`);
});
