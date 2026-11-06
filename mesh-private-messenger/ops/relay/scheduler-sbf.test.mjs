import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createKeyPairSignerFromPrivateKeyBytes, getBase58Encoder, getSignatureFromTransaction, getTransactionDecoder } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { RelayJournal } from './journal.mjs';
import { connectRelayRpc } from './rpc.mjs';
import { createRelayScheduler } from './scheduler.mjs';
import { createRelayService } from './service.mjs';
import { createRelayHttpServer } from './http.mjs';

const required=name=>{if(!process.env[name])throw new Error(`Missing ${name}; run prove-relay-writer.sh`);return process.env[name];};
const binary=required('MORSE_RELAY_SCHEDULER_PROOF_BINARY'),bridgeBinary=required('MORSE_RELAY_SBF_BRIDGE');
const plans=(await readFile(required('MORSE_RELAY_SETTLEMENT_PLANS_PATH'),'utf8')).trim().split('\n').map(JSON.parse);
const fixtures=(await Promise.all(['MORSE_ADJUDICATION_FIXTURES_PATH','MORSE_RELAY_ANCHORED_FIXTURES_PATH','MORSE_RELAY_MAXIMUM_FIXTURES_PATH']
  .map(async key=>JSON.parse(await readFile(required(key),'utf8'))))).flat();
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const run=promisify(execFile);
class Bridge{
  constructor(){
    this.child=spawn(bridgeBinary,[],{stdio:['pipe','pipe','pipe'],env:process.env});this.errors='';
    this.child.stderr.on('data',data=>{this.errors+=data;});this.exit=once(this.child,'exit');
    this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();this.queue=Promise.resolve();
  }
  ask(request){
    const result=this.queue.then(async()=>{
      await new Promise((resolve,reject)=>this.child.stdin.write(JSON.stringify(request)+'\n',error=>error?reject(error):resolve()));
      let timer;
      try{
        const line=await Promise.race([this.lines.next(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('SBF bridge timeout '+this.errors)),10000);})]);
        assert.equal(line.done,false,this.errors);return JSON.parse(line.value);
      }finally{clearTimeout(timer);}
    });this.queue=result;return result;
  }
  async close(){if(this.child.exitCode===null)this.child.kill('SIGKILL');await this.exit;}
}
function account(value,config={}){
  if(!value||value.lamports==='0')return null;
  return {owner:value.owner,lamports:BigInt(value.lamports),executable:value.executable,
    data:[(config.dataSlice?Buffer.from(value.data_hex,'hex').subarray(Number(config.dataSlice.offset),Number(config.dataSlice.offset)+Number(config.dataSlice.length)):Buffer.from(value.data_hex,'hex')).toString('base64'),'base64'],rentEpoch:0n};
}
async function oracle(bridge,fixture){
  const servers=[],errors=[],endpoints=[],calls=[];
  for(let i=0;i<3;i++){
    const server=createServer(async(req,res)=>{
      try{
        const parts=[];for await(const part of req)parts.push(part);
        const call=parseJsonWithBigInts(Buffer.concat(parts).toString()),{method,params}=call;calls.push(method);
        const state=await bridge.ask({method:'read_context'}),slot=BigInt(state.slot),config=params[1];
        assert.equal(config.commitment,'finalized');assert.ok(config.minContextSlot<=slot);
        let value;
        if(method==='getAccountInfo')value=account(await bridge.ask({method:'account',address:params[0]}),config);
        else if(method==='getMultipleAccounts')value=await Promise.all(params[0].map(async address=>account(await bridge.ask({method:'account',address}),config)));
        else{
          assert.equal(method,'getProgramAccounts');assert.equal(params[0],fixture.program);value=[];
          for(const source of fixture.before_accounts){
            const current=await bridge.ask({method:'account',address:source.address});
            if(!current||current.owner!==fixture.program)continue;
            const bytes=Buffer.from(current.data_hex,'hex');
            if(config.filters.some(filter=>filter.dataSize!==undefined?Number(filter.dataSize)!==bytes.length:
              !bytes.subarray(Number(filter.memcmp.offset),Number(filter.memcmp.offset)+getBase58Encoder().encode(filter.memcmp.bytes).length)
                .equals(Buffer.from(getBase58Encoder().encode(filter.memcmp.bytes)))))continue;
            value.push({pubkey:source.address,account:account(current,config)});
          }
        }
        res.writeHead(200,{'content-type':'application/json'});res.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:call.id,result:{context:{slot},value}}));
      }catch(error){errors.push(error);res.writeHead(500);res.end('fixture oracle failed');}
    });server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);endpoints.push(`http://127.0.0.1:${server.address().port}`);
  }
  return {endpoints,errors,calls,async close(){await Promise.all(servers.map(server=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();})));}};
}

async function fileThroughHttp(service,bytes,beforeAdmission=()=>{}){
  let received;
  const queued=new Promise(resolve=>{received=resolve;});
  const server=createRelayHttpServer({submit:(wire,options)=>{const result=service.submit(wire,options);received();return result;}});
  try{
    server.listen(0,'127.0.0.1');await once(server,'listening');
    const pending=fetch(`http://127.0.0.1:${server.address().port}/v1/fork-evidence`,{
      method:'POST',headers:{'Content-Type':'application/octet-stream'},body:bytes});
    await queued;beforeAdmission();await service.cycle();
    const response=await pending;return {status:response.status,body:await response.json()};
  }finally{
    await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
    await service.close();
  }
}

test('the durable scheduler uses compiled Mesh decisions and journaled Kit transactions to settle and clean real SBF banks', {timeout:600000},async t=>{
  assert.equal(plans.length,19);assert.equal(fixtures.length,19);
  let payouts=0,waits=0,restarts=0,nativeReads=0,transactions=0,retainedReplays=0;
  for(let index=0;index<plans.length;index++){
    const original=plans[index],fixture=fixtures[index],directory=await mkdtemp(join(tmpdir(),'morse-relay-live-sbf-'));
    const bridge=new Bridge();let journal,server;
    try{
      await bridge.ask({method:'initialize',fixture,payer:signer.address});server=await oracle(bridge,fixture);
      const configuration={program:fixture.program,log_name:fixture.log_name,service_key:fixture.service_key,
        version:fixture.version,mint:original.mint,submitter:signer.address,endpoints:server.endpoints};
      const requestPath=join(directory,'request.json');
      async function read(mode,plan,floor,options={}){
        await writeFile(requestPath,JSON.stringify({configuration,mode,proof_hex:plan.proof_hex,minimum_slot:floor,
          creation_slot:plan.lookup?.recent_slot,addresses:plan.lookup?.addresses,closing:options.closing??false}),{mode:0o600});
        nativeReads++;
        try{
          const result=await run(binary,[requestPath],{timeout:30000,maxBuffer:262144,env:{PATH:'/usr/bin:/bin'}});
          return JSON.parse(result.stdout);
        }catch(error){throw new Error(`case ${index} native ${mode}: ${error.stderr||error.message}; code=${error.code} signal=${error.signal} killed=${error.killed}; RPC ${server.calls.slice(-20).join(",")}`);}
      }
      const verifier={admit:(wire,floor)=>read('admit',{proof_hex:Buffer.from(wire).toString('hex')},floor),
        ...Object.fromEntries(['stage','destinations','receipt','lookup'].map(mode=>[mode,(...args)=>read(mode,...args)]))};
      const options={path:join(directory,'relay.sqlite'),identity:'local:scheduler-sbf',pins:original,
        policy:{perJobLamports:'1000000000',windowLamports:'1000000000',maxJobs:1}};
      journal=new RelayJournal(options);let clock=1000,quoteContext,dropAcks=true,firstRestart=false,settlementRestart=false;
      const observations=new Map(),genesisHash='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
      const rpc=await connectRelayRpc({urls:['https://bank-a.invalid','https://bank-b.invalid','https://bank-c.invalid'],genesisHash},async(_,init)=>{
        const call=parseJsonWithBigInts(init.body);let result,error;
        switch(call.method){
          case 'getGenesisHash':result=genesisHash;break;
          case 'getLatestBlockhash':result={context:{slot:BigInt(quoteContext.slot)},value:{blockhash:quoteContext.blockhash,lastValidBlockHeight:BigInt(quoteContext.lastValidBlockHeight)}};break;
          case 'getFeeForMessage':result={context:{slot:BigInt(quoteContext.slot)},value:25000n};break;
          case 'getMinimumBalanceForRentExemption':result=BigInt((await bridge.ask({method:'rent',space:Number(call.params[0])})).lamports);break;
          case 'sendTransaction':{
            const wire=call.params[0],signature=getSignatureFromTransaction(getTransactionDecoder().decode(Buffer.from(wire,'base64')));
            const context=await bridge.ask({method:'read_context'}),execution=await bridge.ask({method:'send',wire});
            if(execution.ok){
              transactions++;observations.set(signature,{slot:BigInt(context.slot),version:0n,transaction:[wire,'base64'],meta:{err:null,fee:BigInt(execution.fee),
                preBalances:execution.pre_balances.map(BigInt),postBalances:execution.post_balances.map(BigInt),loadedAddresses:execution.loaded_addresses}});
            }else assert.match(execution.error,/AlreadyProcessed/,`${index}: ${JSON.stringify(execution)}`);
            if(dropAcks)error={code:-32000,message:'fixture acknowledgment lost'};else result=signature;break;
          }
          case 'getSignatureStatuses':{
            const value=observations.get(call.params[0][0]),context=await bridge.ask({method:'read_context'});
            result={context:{slot:BigInt(context.slot)},value:[value?{slot:value.slot,confirmations:null,confirmationStatus:'finalized',err:null}:null]};break;
          }
          case 'getTransaction':result=observations.get(call.params[0])??null;break;
          default:throw new Error(`Unexpected fixture writer RPC ${call.method}`);
        }
        return new Response(stringifyJsonWithBigInts({jsonrpc:'2.0',id:call.id,...(error?{error}:{result})}));
      });
      const chain={...rpc,async quote(step,view){quoteContext=await bridge.ask({method:'context'});return rpc.quote(step,view);}};
      let scheduler=createRelayScheduler({journal,verifier,rpc:chain,signer,now:()=>clock++,owner:'initial'}),complete=false;
      const ingress=createRelayService({journal,verifier,scheduler,now:()=>clock++});
      const admission=await fileThroughHttp(ingress,Buffer.from(original.proof_hex,'hex'),()=>assert.equal(journal.jobs().length,0));
      assert.equal(admission.status,202);
      assert.deepEqual(admission.body,{schema_version:1,status:'queued',proof_hash:original.proof_hash,finder:original.finder,duplicate:false});
      for(let turn=0;turn<160;turn++){
        clock+=1001;
        const result=await scheduler.tick();
        assert.equal(server.errors.length,0,server.errors.map(value=>value.stack).join('\n'));
        if(result.state==='waiting'){
          waits++;assert.ok(['lookup-activation','cooldown'].includes(result.reason));
          await bridge.ask({method:result.reason==='cooldown'?'retire_lookup_history':'advance'});
        }
        const pending=journal.pending();
        if(pending&&(!firstRestart||(pending.stepId==='settle'&&!settlementRestart))){
          if(firstRestart)settlementRestart=true;else firstRestart=true;
          const packet=pending.signed;assert.ok(packet);journal.close();journal=new RelayJournal(options);clock+=30001;
          assert.deepEqual(journal.pending().signed,packet);
          scheduler=createRelayScheduler({journal,verifier,rpc:chain,signer,now:()=>clock++,owner:`restart-${clock}`});
          restarts++;dropAcks=false;
        }
        if(result.state==='complete'){complete=true;break;}
      }
      assert.ok(complete,`case ${index} did not complete`);assert.ok(firstRestart&&settlementRestart);
      const job=journal.job(original.proof_hash);assert.equal(job.state,'complete');assert.equal(job.receipt.finder,original.finder);
      assert.equal(job.receipt.total_slashed_units,original.estimate.total_slashed_units);
      assert.equal(journal.pending(),null);assert.equal(journal.budget(clock++).reservedLamports,'0');
      assert.deepEqual(journal.resources(original.proof_hash),[]);
      const stage=await bridge.ask({method:'account',address:original.stage.address});assert.ok(!stage||stage.lamports==='0');
      if(job.plan.settlement.accountCount>32){const table=await bridge.ask({method:'account',address:job.plan.lookup.address});assert.ok(!table||table.lamports==='0');}
      payouts++;
      clock+=7*86400000+60001;
      assert.equal((await scheduler.tick()).state,'idle');assert.equal(journal.jobs().length,0);
      const retained=journal.retention();assert.ok(BigInt(retained.minContextSlot)>=BigInt(job.receipt.context_slot));
      assert.ok(BigInt(retained.lastValidBlockHeight)>0n);
      journal.close();journal=new RelayJournal(options);clock+=30001;restarts++;
      assert.deepEqual(journal.retention(),retained);
      scheduler=createRelayScheduler({journal,verifier,rpc:chain,signer,now:()=>clock++,owner:'after-retention'});
      const before=transactions,retry=createRelayService({journal,verifier,scheduler,now:()=>clock++});
      const paid=await fileThroughHttp(retry,Buffer.from(original.proof_hex,'hex'));
      assert.equal(paid.status,200);assert.deepEqual(paid.body,{schema_version:1,status:'settled',proof_hash:original.proof_hash,finder:original.finder});
      assert.equal(transactions,before);assert.equal(journal.jobs().length,0);assert.equal(journal.pending(),null);retainedReplays++;
    }finally{await server?.close();await bridge.close();journal?.close();await rm(directory,{recursive:true,force:true});}
  }
  assert.equal(payouts,19);assert.equal(restarts,57);assert.equal(waits,8);assert.equal(retainedReplays,19);
  t.diagnostic(`${payouts} actual SBF payouts; ${restarts} scheduler restarts; ${waits} activation/cooldown waits; ${nativeReads} native Mesh reads; ${transactions} transactions; ${retainedReplays} post-retention replays without spending`);
});
