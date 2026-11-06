import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressEncoder, getAddressDecoder, getCompiledTransactionMessageDecoder,
  getTransactionDecoder, getSignatureFromTransaction } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';

import { RewardsJournal } from './journal.mjs';
import { createRewardsPlanner } from './planner.mjs';
import { runRewardsCycle } from './writer.mjs';
import { connectRewardsRpc } from './rpc.mjs';
import { prepareRewardsTransaction, signRewardsTransaction } from './transactions.mjs';

const run=promisify(execFile),genesis='11111111111111111111111111111111';
const required=name=>{assert.ok(process.env[name],`Missing ${name}; run scripts/prove-rewards-v2.sh`);return process.env[name];};
const binary=required('MORSE_REWARDS_V2_OPERATOR_BIN'),bridgeBinary=required('MORSE_REWARDS_V2_SBF_BRIDGE');
const cli=fileURLToPath(new URL('./cli.mjs',import.meta.url));
class Bridge{
  constructor(){
    this.child=spawn(bridgeBinary,[],{stdio:['pipe','pipe','pipe'],env:process.env});
    this.errors='';this.child.stderr.on('data',b=>this.errors+=b);this.child.on('error',e=>this.errors+=e.stack);
    this.exit=once(this.child,'exit');this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();
    this.queue=Promise.resolve();
  }
  ask(request){
    const result=this.queue.then(async()=>{
      this.child.stdin.write(JSON.stringify(request)+'\n');let timer;
      try{
        const line=await Promise.race([this.lines.next(),new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error(`Bridge timeout ${this.errors}`)),30000))]);
        assert.equal(line.done,false,this.errors);const value=JSON.parse(line.value);
        if(value.ok===false&&!value.signature)throw new Error(JSON.stringify(value));return value;
      }finally{clearTimeout(timer);}
    });this.queue=result.catch(()=>{});return result;
  }
  async close(){if(this.child.exitCode===null)this.child.kill('SIGKILL');await this.exit;}
}
const rpcAccount=a=>a===null?null:{...a,lamports:BigInt(a.lamports),space:BigInt(a.space),rentEpoch:0n};

// Three HTTP origins share one disposable bank. Only transport/history visibility
// is controlled here; execution, balances, fees, rent and signatures are real SBF.
async function oracle(bridge){
  const servers=[],urls=[],errors=[],sent=[],records=new Map();
  const control={mode:'normal',hideHistory:false,historyCovered:true};
  async function execute(wire){
    const tx=getTransactionDecoder().decode(Buffer.from(wire,'base64'));
    const signature=getSignatureFromTransaction(tx);
    if(!records.has(signature))records.set(signature,(async()=>{
      const keys=[...getCompiledTransactionMessageDecoder().decode(tx.messageBytes).staticAccounts];
      const before=await bridge.ask({method:'accounts',addresses:keys});
      const receipt=await bridge.ask({method:'execute',wire});
      assert.equal(receipt.ok,true,JSON.stringify(receipt));
      const after=await bridge.ask({method:'accounts',addresses:keys});
      const balances=values=>values.map(a=>a===null?0n:BigInt(a.lamports));
      return {slot:BigInt(receipt.context.slot),version:0n,transaction:[wire,'base64'],meta:{err:null,
        fee:BigInt(receipt.fee_lamports),preBalances:balances(before.value),postBalances:balances(after.value),
        loadedAddresses:{writable:[],readonly:[]}}};
    })());
    await records.get(signature);return signature;
  }
  for(let index=0;index<3;index++){
    const server=createServer(async(req,res)=>{
      try{
        let body='';for await(const chunk of req){body+=chunk;assert.ok(body.length<=32768);}
        const call=parseJsonWithBigInts(body),args=call.params??[];
        const context=await bridge.ask({method:'context'}),slot=BigInt(context.slot);
        let result;
        switch(call.method){
          case 'getGenesisHash':result=genesis;break;
          case 'getLatestBlockhash':
            assert.equal(args[0].commitment,'finalized');assert.ok(args[0].minContextSlot<=slot);
            result={context:{slot},value:{blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.last_valid_block_height)}};break;
          case 'getFeeForMessage':{
            const fee=await bridge.ask({method:'fee'});result={context:{slot},value:BigInt(fee.single_signer_fee_lamports)};break;
          }
          case 'getMinimumBalanceForRentExemption':{
            const rent=await bridge.ask({method:'rent',space:Number(args[0])});result=BigInt(rent.lamports);break;
          }
          case 'getMultipleAccounts':case 'getAccountInfo':{
            const options=args[1];assert.equal(options.commitment,'finalized');assert.ok(options.minContextSlot<=slot);
            const slice=options.dataSlice?{offset:Number(options.dataSlice.offset),length:Number(options.dataSlice.length)}:{};
            const found=await bridge.ask(call.method==='getMultipleAccounts'?{method:'accounts',addresses:args[0],...slice}:{method:'account',address:args[0],...slice});
            result={context:{slot:BigInt(found.context.slot)},value:Array.isArray(found.value)?found.value.map(rpcAccount):rpcAccount(found.value)};break;
          }
          case 'sendTransaction':{
            const wire=args[0];sent.push(wire);assert.equal(args[1].skipPreflight,false);
            if(control.mode==='drop'){res.writeHead(503).end();return;}
            result=await execute(wire);
            if(control.mode==='lost-ack'){res.writeHead(503).end();return;}
            break;
          }
          case 'getSignatureStatuses':{
            assert.equal(args[1].searchTransactionHistory,true);
            const record=control.hideHistory?null:await records.get(args[0][0]);
            result={context:{slot},value:[record?{slot:record.slot,err:null,confirmations:null,confirmationStatus:'finalized'}:null]};break;
          }
          case 'getTransaction':result=control.hideHistory?null:(await records.get(args[0]))??null;break;
          case 'getBlockHeight':assert.equal(args[0].commitment,'finalized');result=BigInt(context.block_height);break;
          case 'getSlot':assert.equal(args[0].commitment,'finalized');result=slot;break;
          case 'getFirstAvailableBlock':result=control.historyCovered?0n:slot+1n;break;
          default:throw new Error(`Unexpected RPC ${call.method}`);
        }
        res.setHeader('content-type','application/json');res.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:call.id,result}));
      }catch(error){errors.push(error.stack);res.writeHead(500).end();}
    });
    server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);urls.push(`http://127.0.0.1:${server.address().port}`);
  }
  return {urls,errors,sent,records,control,async close(){for(const s of servers){s.closeAllConnections();await new Promise(resolve=>s.close(resolve));}}};
}
function rows(path){
  const db=new DatabaseSync(path,{readOnly:true});
  try{return db.prepare('SELECT * FROM rewards_transactions ORDER BY id').all().map(r=>({...r,plan:JSON.parse(r.plan),signed:r.signed?JSON.parse(r.signed):null}));}
  finally{db.close();}
}
async function harness(initialization={}){
  const directory=await mkdtemp(join(tmpdir(),'rewards-v2-sbf-')),bridge=new Bridge();
  let rpc;
  try{
    const seed=new Uint8Array(32).fill(203),payer=await createKeyPairSignerFromPrivateKeyBytes(seed);
    const fixture=await bridge.ask({method:'initialize',payer:payer.address,...initialization});
    assert.equal(fixture.execution,'local-sbf');assert.equal(fixture.signature_verification,true);
    rpc=await oracle(bridge);
    const securityConfig=JSON.stringify({...fixture.pins,schema_version:2,endpoints:rpc.urls,allow_loopback:true});
    const pins={version:2,program:fixture.program,judge:fixture.judge,token:fixture.token,log:fixture.addresses.log,
      mint:fixture.usdc_mint,morse:fixture.addresses.morse,payer:payer.address,
      configuration_hash:createHash('sha256').update(securityConfig).digest('hex')};
    const request={schema_version:2,action:'settle',program:pins.program,mint:pins.mint,log:fixture.log_name,payer:payer.address,epoch:fixture.epoch};
    const securityConfigPath=join(directory,'pins.json'),wallet=join(directory,'payer.json');
    await writeFile(securityConfigPath,securityConfig,{mode:0o600});
    await writeFile(wallet,JSON.stringify([...seed,...getAddressEncoder().encode(payer.address)]),{mode:0o600});
    async function intent(name,value,policy={maxLamports:'1000000000',maxTransactions:128}){
      const requestPath=join(directory,`${name}-request.json`),journalPath=join(directory,`${name}.sqlite`),configPath=join(directory,`${name}.json`);
      await writeFile(requestPath,JSON.stringify(value),{mode:0o600});
      const config={binary,securityConfigPath,logVersion:fixture.log_version,requestPath,walletPaths:[wallet],journalPath,pins,
        rpc:{urls:rpc.urls,genesisHash:genesis,allowLoopback:true},policy};
      await writeFile(configPath,JSON.stringify(config),{mode:0o600});
      return {journalPath,config,configPath,async cycle(){
        let result;try{result=await run(process.execPath,[cli,'--config',configPath],{timeout:60000,maxBuffer:65536});}
        catch(e){throw new Error(`CLI: ${e.stderr||e.message}; RPC: ${rpc.errors.join('\n')}`);}
        assert.deepEqual(rpc.errors,[]);return JSON.parse(result.stdout.trim());
      }};
    }
    async function data(key){const value=await bridge.ask({method:'account',address:key});return value.value?Buffer.from(value.value.data[0],'base64'):null;}
    return {bridge,rpc,fixture,request,intent,data,pins,payer,securityConfig,async close(){await rpc.close();await bridge.close();await rm(directory,{recursive:true,force:true});}};
  }catch(e){if(rpc)await rpc.close();await bridge.close();await rm(directory,{recursive:true,force:true});throw e;}
}

test('CLI processes restart through dropped packet expiry, pruned lost-ack effects, append31, finalize26 and exact asset claims', {timeout:300000},async()=>{
  const h=await harness();
  try{
    const {bridge,rpc,fixture}=h,settle=await h.intent('settle',h.request);
    rpc.control.mode='drop';assert.equal((await settle.cycle()).state,'unacknowledged');
    const first=rows(settle.journalPath)[0];assert.equal(first.plan.action,'open');assert.equal(first.phase,'signed');
    await settle.cycle();assert.deepEqual(rows(settle.journalPath)[0].signed,first.signed);
    await bridge.ask({method:'expire_blockhash'});rpc.control.historyCovered=false;rpc.control.hideHistory=true;
    await settle.cycle();assert.equal(rows(settle.journalPath)[0].phase,'signed','pruned absence retains reservation');
    assert.equal(rows(settle.journalPath).length,1);
    rpc.control.historyCovered=true;assert.equal((await settle.cycle()).state,'expired');
    assert.equal(rows(settle.journalPath)[0].phase,'expired');
    rpc.control.mode='lost-ack';assert.equal((await settle.cycle()).state,'unacknowledged');
    const second=rows(settle.journalPath)[1];assert.notEqual(second.signed.signature,first.signed.signature);
    assert.ok(await h.data(fixture.addresses.epoch));
    await bridge.ask({method:'expire_blockhash'});rpc.control.historyCovered=false;rpc.control.mode='normal';
    assert.equal((await settle.cycle()).state,'effect','authenticated open effect resolves pruned history');
    assert.equal(rows(settle.journalPath).length,2);
    rpc.control.hideHistory=false;rpc.control.historyCovered=true;
    let complete=false;
    for(let pass=0;pass<80;pass++){
      const value=await settle.cycle();
      if(value.state==='complete'){complete=true;break;}
      assert.ok(['broadcast','finalized'].includes(value.state),JSON.stringify(value));
    }
    assert.equal(complete,true);
    const all=rows(settle.journalPath),actions=all.map(r=>r.plan.action);
    assert.ok(actions.includes('begin'));assert.ok(actions.includes('finalize'));
    assert.ok(all.some(r=>r.plan.action==='append'&&r.plan.instructions.at(-1).accountCount===31));
    assert.ok(all.some(r=>r.plan.action==='finalize'&&r.plan.instructions.at(-1).accountCount===26));
    const ledger=await h.data(fixture.addresses.epoch),tokenEpoch=await h.data(fixture.addresses.token_epoch);
    assert.equal(ledger[52],2);assert.equal(ledger[53],64);
    for(const asset of [0,1]){
      const row=17,claim=await h.intent(`claim-${asset}`,{...h.request,action:'claim',row,asset});
      const witness=fixture.witnesses[row],destination=asset?witness.payout_morse_ata:witness.payout_usdc_ata;
      const previous=await h.data(destination),before=previous?previous.readBigUInt64LE(64):0n;
      const earned=asset?tokenEpoch.readBigUInt64LE(264+row*16):ledger.readBigUInt64LE(224+row*128+120);
      assert.ok(earned>0n);
      rpc.control.mode='lost-ack';assert.equal((await claim.cycle()).state,'unacknowledged');
      const packet=rows(claim.journalPath)[0].signed;
      rpc.control.mode='normal';assert.equal((await claim.cycle()).state,'finalized');
      assert.deepEqual(rows(claim.journalPath)[0].signed,packet);
      assert.equal((await h.data(destination)).readBigUInt64LE(64)-before,earned);
      assert.equal((await claim.cycle()).state,'complete');
      assert.equal((await claim.cycle()).state,'complete');assert.equal(rows(claim.journalPath).length,1);
    }
    console.log(JSON.stringify({proof:'v2-cli-kit-journal-sbf',signedAttempts:all.length+2,bankExecutions:rpc.records.size,appendPackets:actions.filter(a=>a==='append').length,
      claims:2,processRestartEveryCycle:true,fixtureReused:fixture.provenance.fixture_reused,fixtureSha256:fixture.provenance.fixture_sha256,programs:fixture.provenance.programs}));
  }finally{await h.close();}
});

test('restarted bounded settlement cancels an expired stage and replans through the real program', {timeout:90000},async()=>{
  const h=await harness();
  try{
    const intent=await h.intent('expiry',{...h.request,epoch_count:'2'});
    for(const action of ['open','begin']){
      assert.equal((await intent.cycle()).state,'broadcast');
      assert.equal(rows(intent.journalPath).at(-1).plan.action,action);
      assert.equal((await intent.cycle()).state,'finalized');
    }
    await h.bridge.ask({method:'advance_clock',seconds:3600});
    assert.equal((await intent.cycle()).state,'broadcast');
    assert.equal(rows(intent.journalPath).at(-1).plan.action,'cancel');
    assert.equal((await intent.cycle()).state,'finalized');
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],0);
    assert.equal((await intent.cycle()).state,'broadcast');assert.equal(rows(intent.journalPath).at(-1).plan.action,'begin');
    assert.ok(rows(intent.journalPath).every(row=>row.plan.epoch===h.request.epoch));
  }finally{await h.close();}
});

test('lost append fees remain charged when cancellation erases its effect and transaction history has a hole', {timeout:90000},async()=>{
  const h=await harness();
  try{
    const intent=await h.intent('append-hole',h.request);
    for(const action of ['open','begin']){
      assert.equal((await intent.cycle()).state,'broadcast');
      assert.equal(rows(intent.journalPath).at(-1).plan.action,action);
      assert.equal((await intent.cycle()).state,'finalized');
    }
    h.rpc.control.mode='lost-ack';
    const sent=await intent.cycle();assert.equal(sent.state,'unacknowledged');
    const packet=rows(intent.journalPath).at(-1);assert.equal(packet.plan.action,'append');
    const landed=await h.rpc.records.get(packet.signed.signature);assert.equal(landed.meta.fee,5000n);
    await h.bridge.ask({method:'advance_clock',seconds:3600});
    h.rpc.control.mode='normal';
    const canceller=await h.intent('other-keeper',h.request);
    assert.equal((await canceller.cycle()).state,'broadcast');
    assert.equal(rows(canceller.journalPath).at(-1).plan.action,'cancel');
    assert.equal((await canceller.cycle()).state,'finalized');
    h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=true;
    const result=await intent.cycle();assert.equal(result.state,'expired');
    assert.equal(BigInt(result.spentLamports)-BigInt(sent.spentLamports),BigInt(JSON.parse(packet.quote).maxDebitLamports),
      'oldest available block is not complete history; absent mutable effect cannot erase spent fees');
  }finally{await h.close();}
});

test('bounded settlement schedule resumes one journal across finalized epochs without resetting context or spending', {timeout:300000},async()=>{
  const h=await harness();
  try{
    const schedule=await h.intent('range',{...h.request,action:'settle',epoch_count:'2'});
    assert.equal((await schedule.cycle()).state,'broadcast');
    let advanced;
    for(let pass=0;pass<80;pass++){
      const result=await schedule.cycle();
      if(result.state==='advanced'){advanced=result;break;}
      assert.ok(['broadcast','finalized'].includes(result.state),JSON.stringify(result));
    }
    assert.ok(advanced,'Mesh must authenticate completion and durably advance');
    assert.equal(advanced.epoch,(BigInt(h.request.epoch)+1n).toString());
    const prior=rows(schedule.journalPath),spent=BigInt(advanced.spentLamports);
    const originalLedger=await h.data(h.fixture.addresses.epoch);
    assert.ok(spent>0n);assert.equal(prior.at(-1).plan.action,'finalize');
    const waiting=await schedule.cycle();
    assert.equal(waiting.state,'waiting');assert.equal(waiting.reason,'waiting:week-end');
    assert.equal(waiting.contextSlot,advanced.contextSlot);assert.equal(waiting.spentLamports,advanced.spentLamports);
    await h.bridge.ask({method:'advance_clock',seconds:604800});
    let completed;
    for(let pass=0;pass<20;pass++){
      const result=await schedule.cycle();
      if(result.state==='complete'){completed=result;break;}
      assert.ok(['broadcast','finalized'].includes(result.state),JSON.stringify(result));
    }
    assert.ok(completed);assert.ok(BigInt(completed.contextSlot)>BigInt(advanced.contextSlot));
    assert.ok(BigInt(completed.spentLamports)>spent);assert.ok(completed.attempts>advanced.attempts);
    assert.deepEqual(await h.data(h.fixture.addresses.epoch),originalLedger,'later epochs preserve old entitlements');
    const next=rows(schedule.journalPath).slice(prior.length);
    assert.deepEqual(next.map(r=>r.plan.action),['open','attendance-open','seal','begin','finalize']);
    assert.ok(next.every(r=>r.plan.epoch===advanced.epoch));
    assert.equal((await schedule.cycle()).state,'complete');assert.equal(rows(schedule.journalPath).length,prior.length+next.length);
  }finally{await h.close();}
});

async function until(intent,state,limit=80){
  for(let pass=0;pass<limit;pass++){
    const result=await intent.cycle();if(result.state===state)return result;
    assert.ok(['broadcast','finalized','advanced','effect','unacknowledged'].includes(result.state),JSON.stringify(result));
  }
  assert.fail(`did not reach ${state}`);
}
function scope(path){
  const db=new DatabaseSync(path,{readOnly:true});
  try{return db.prepare('SELECT * FROM rewards_scope').get();}finally{db.close();}
}

test('scheduled lost finalize acknowledgment and pruned older packets cannot advance before reconciliation', {timeout:120000},async()=>{
  const h=await harness({row_count:3});
  try{
    const intent=await h.intent('pending-range',{...h.request,action:'settle',epoch_count:'2'});
    h.rpc.control.mode='drop';assert.equal((await intent.cycle()).state,'unacknowledged');
    const first=rows(intent.journalPath)[0];
    await h.bridge.ask({method:'expire_blockhash'});h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=false;
    for(let restart=0;restart<2;restart++){
      assert.equal((await intent.cycle()).epoch,h.request.epoch);
      assert.deepEqual(rows(intent.journalPath),[first]);assert.equal(scope(intent.journalPath).spent,'0');
    }
    h.rpc.control.historyCovered=true;assert.equal((await intent.cycle()).state,'expired');
    h.rpc.control.mode='normal';h.rpc.control.hideHistory=false;
    while(rows(intent.journalPath).filter(r=>r.phase==='finalized').length<3)await intent.cycle();
    h.rpc.control.mode='lost-ack';const lost=await intent.cycle();assert.equal(lost.state,'unacknowledged');
    const finalize=rows(intent.journalPath).at(-1);assert.equal(finalize.plan.action,'finalize');
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],2,'bank has completed while journal still owns old packet');
    assert.equal(lost.epoch,h.request.epoch);assert.equal(finalize.phase,'signed');
    h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=false;
    await h.bridge.ask({method:'expire_blockhash'});
    assert.equal((await intent.cycle()).state,'effect');
    assert.deepEqual(rows(intent.journalPath).at(-1).signed,finalize.signed);
    assert.equal((await intent.cycle()).state,'advanced');
    assert.equal(rows(intent.journalPath).length,5,'no new epoch packet until old reservation is terminal');
    assert.ok(BigInt(scope(intent.journalPath).spent)>=BigInt(JSON.parse(first.quote).maxDebitLamports)+BigInt(JSON.parse(finalize.quote).maxDebitLamports));
  }finally{await h.close();}
});

test('aggregate transaction and lamport caps refuse the next epoch across CLI restarts', {timeout:120000},async()=>{
  for(const cap of ['transactions','lamports','exact-lamports']){
    const h=await harness({row_count:3});
    try{
      const rent=await h.bridge.ask({method:'rent',space:8416}),tokenRent=await h.bridge.ask({method:'rent',space:1280});
      // Three selected rows fit the existing USDC subsidy; no reserve CPI
      // creates a receipt. Quotes still conservatively reserve its rent.
      const firstDebit=BigInt(rent.lamports)+BigInt(tokenRent.lamports)+20000n;
      const nextQuote=BigInt(rent.lamports)+BigInt(tokenRent.lamports)+5000n;
      const policy={maxTransactions:cap==='transactions'?4:128,maxLamports:cap==='transactions'?'1000000000':(firstDebit+nextQuote-(cap==='lamports'?1n:0n)).toString()};
      const intent=await h.intent(`cap-${cap}`,{...h.request,action:'settle',epoch_count:'2'},policy);
      const advanced=await until(intent,'advanced');assert.equal(advanced.attempts,4);
      assert.equal(BigInt(advanced.spentLamports),firstDebit);
      await h.bridge.ask({method:'advance_clock',seconds:604800});
      if(cap==='exact-lamports'){
        const allowed=await intent.cycle();assert.equal(allowed.state,'broadcast');assert.equal(allowed.attempts,5);
        assert.equal((await intent.cycle()).state,'finalized');
      }
      const before=rows(intent.journalPath),sent=h.rpc.sent.length,budgetBefore=scope(intent.journalPath);
      for(let restart=0;restart<2;restart++)await assert.rejects(intent.cycle(),/budget exhausted/);
      assert.deepEqual(rows(intent.journalPath),before);assert.equal(h.rpc.sent.length,sent);
      assert.equal(scope(intent.journalPath).spent,budgetBefore.spent);assert.equal(scope(intent.journalPath).attempts,budgetBefore.attempts);
    }finally{await h.close();}
  }
});

test('external completion advances without spending, but a superseded completion read and invalid plans cannot publish', {timeout:120000},async()=>{
  const h=await harness({row_count:3});let a,b;
  try{
    const other=await h.intent('external',h.request);await until(other,'complete');
    const scheduled=await h.intent('external-range',{...h.request,action:'settle',epoch_count:'2'});
    const {config}=scheduled,request=JSON.parse(await readFile(config.requestPath,'utf8'));
    const planner=await createRewardsPlanner({binary:config.binary,tempRoot:join(config.journalPath+'-planner'),
      securityConfig:(await readFile(config.securityConfigPath,'utf8')).trim(),logVersion:config.logVersion,pins:config.pins});
    const options={path:config.journalPath,pins:config.pins,request,policy:config.policy};
    a=new RewardsJournal(options);b=new RewardsJournal(options);let now=100;
    const ctx={journal:a,lease:a.claim('stale',now),now:()=>++now,pins:config.pins,signers:[],rpc:{},
      planner:{async plan(request,floor){const plan=await planner.plan(request,floor);now+=30001;b.claim('takeover',now);return plan;}}};
    await assert.rejects(runRewardsCycle(ctx),/lease/);
    assert.equal(a.progress().epoch,h.request.epoch);assert.equal(a.progress().spentLamports,'0');assert.equal(a.progress().contextSlot,'0');
    b.close();b=undefined;now+=30001;const lease=a.claim('current',now);
    const plan=await planner.plan(a.planningRequest());
    for(const invalid of [{...plan,next_epoch:null},{...plan,next_epoch:(BigInt(h.request.epoch)+2n).toString()},{...plan,epoch:plan.next_epoch}]){
      assert.throws(()=>a.acceptPlan(lease,invalid,++now),/schedule/);
      assert.equal(a.progress().epoch,h.request.epoch);
    }
    a.release(lease,++now);a.close();a=undefined;
    const advanced=await scheduled.cycle();assert.equal(advanced.state,'advanced');assert.equal(advanced.attempts,0);assert.equal(advanced.spentLamports,'0');
    assert.deepEqual(rows(scheduled.journalPath),[]);
    assert.equal((await scheduled.cycle()).state,'waiting');
    await h.bridge.ask({method:'advance_clock',seconds:604800});
    const externalNext=await h.intent('external-next',{...h.request,epoch:(BigInt(h.request.epoch)+1n).toString()});
    await until(externalNext,'complete');
    const watch=await h.intent('watch-range',request);
    const result=await run(process.execPath,[cli,'--config',watch.configPath,'--watch'],{timeout:20000,maxBuffer:65536});
    const outputs=result.stdout.trim().split('\n').map(line=>JSON.parse(line));
    assert.deepEqual(outputs.map(o=>o.state),['advanced','complete'],'watch continues across the completion transition');
    assert.equal(outputs.at(-1).attempts,0);assert.equal(outputs.at(-1).spentLamports,'0');

  }finally{a?.close();b?.close();await h.close();}
});

test('empty and all-excluded schedules carry every unallocated dollar through two epochs and stop at the bound', {timeout:120000},async()=>{
  for(const initialization of [{row_count:0},{row_count:3,all_excluded:true}]){
    const h=await harness(initialization);
    try{
      const addresses=h.fixture.addresses,before=await h.data(addresses.pool);
      const tokenBefore=await h.data(addresses.token_pool),vaultBefore=await h.data(addresses.pool_morse_vault);
      assert.ok(before.readBigUInt64LE(196)>0n,'fixture carries a nonzero dollar unit');
      const intent=await h.intent('zero-range',{...h.request,action:'settle',epoch_count:'2'});
      const advanced=await until(intent,'advanced');
      const firstRows=rows(intent.journalPath);
      assert.deepEqual(firstRows.map(r=>r.plan.action),initialization.row_count===0?['open','begin','finalize']:['open','begin','append','finalize']);
      await h.bridge.ask({method:'advance_clock',seconds:604800});
      const complete=await until(intent,'complete');assert.equal(complete.scheduleComplete,true);
      const after=await h.data(addresses.pool),tokenAfter=await h.data(addresses.token_pool);
      assert.equal(after.readBigUInt64LE(180),BigInt(h.request.epoch)+2n);
      for(const offset of [188,196,204,212])assert.equal(after.readBigUInt64LE(offset),before.readBigUInt64LE(offset));
      assert.equal(tokenAfter.readBigUInt64LE(260),tokenBefore.readBigUInt64LE(260));
      assert.equal(tokenAfter.readBigUInt64LE(268),tokenBefore.readBigUInt64LE(268));
      assert.deepEqual(await h.data(addresses.pool_morse_vault),vaultBefore);
      for(const address of [addresses.epoch,addresses.next_epoch]){
        const ledger=await h.data(address);assert.equal(ledger[52],2);assert.equal(ledger.readBigUInt64LE(144),0n);
        assert.equal(ledger.readBigUInt64LE(152),before.readBigUInt64LE(196));
      }
      const all=rows(intent.journalPath);assert.ok(all.every(r=>BigInt(r.plan.epoch)<BigInt(h.request.epoch)+2n));
      assert.ok(BigInt(complete.contextSlot)>BigInt(advanced.contextSlot));
      assert.equal((await intent.cycle()).state,'complete');assert.equal(rows(intent.journalPath).length,all.length);
    }finally{await h.close();}
  }
});

async function executeAction(intent,action){
  assert.equal((await intent.cycle()).state,'broadcast');
  const row=rows(intent.journalPath).at(-1);assert.equal(row.plan.action,action);
  assert.equal((await intent.cycle()).state,'finalized');return row;
}
async function externalAssessment(h,plan){
  await h.bridge.ask({method:'expire_blockhash'});
  const life=await h.bridge.ask({method:'context'});
  const step=prepareRewardsTransaction(plan,h.pins);
  const signed=await signRewardsTransaction(step,[h.payer],{blockhash:life.blockhash,lastValidBlockHeight:BigInt(life.last_valid_block_height)});
  const receipt=await h.bridge.ask({method:'execute',wire:signed.wire});assert.equal(receipt.ok,true,JSON.stringify(receipt));
  return receipt;
}

test('continuous CLI grace recovery and new threshold crossing cancel fully collected stages; no-op assessments allow finalize', {timeout:120000},async()=>{
  const h=await harness({row_indices:[0,17,63]});
  try{
    const intent=await h.intent('continuous',{...h.request,epoch_count:'2'}),a=h.fixture.addresses;
    for(const action of ['open','begin','append'])await executeAction(intent,action);
    const bondBefore=await h.data(a.bond1),pendingBefore=await h.data(a.pending1);
    const vaultKey=getAddressDecoder().decode(bondBefore.subarray(136,168)),vaultBefore=await h.data(vaultKey);
    const principal=bondBefore.readBigUInt64LE(168),revision=(await h.data(a.economics)).readBigUInt64LE(168);
    assert.ok(bondBefore.readBigUInt64LE(200)>0n);
    await h.bridge.ask({method:'fixture_price',price:'2000000'});
    const recovered=await executeAction(intent,'assess');
    assert.equal(Buffer.from(recovered.plan.instructions.at(-1).dataBase64,'base64')[0],45);
    assert.equal((await h.data(a.bond1)).readBigUInt64LE(200),0n);
    assert.equal((await h.data(a.economics)).readBigUInt64LE(168),revision+1n);
    assert.equal((await h.data(a.epoch))[52],1,'assessment is allowed during active collection');
    assert.equal((await h.data(a.bond1)).readBigUInt64LE(168),principal);
    assert.deepEqual(await h.data(a.pending1),pendingBefore,'pending collateral is never applied');
    if(vaultBefore)assert.deepEqual(await h.data(vaultKey),vaultBefore);
    await executeAction(intent,'cancel');await executeAction(intent,'begin');
    await h.bridge.ask({method:'fixture_price',price:'1000000'});
    const crossed=await executeAction(intent,'assess');
    assert.ok((await h.data(a.bond1)).readBigUInt64LE(200)>0n);
    assert.equal((await h.data(a.economics)).readBigUInt64LE(168),revision+2n);
    await executeAction(intent,'cancel');await executeAction(intent,'begin');
    const economics=await h.data(a.economics),bond=await h.data(a.bond1);
    for(let pass=0;pass<2;pass++)await externalAssessment(h,crossed.plan);
    assert.deepEqual(await h.data(a.economics),economics,'actual no-op tag45 does not invalidate collection');
    assert.deepEqual(await h.data(a.bond1),bond);assert.deepEqual(await h.data(a.pending1),pendingBefore);
    const advanced=await until(intent,'advanced');assert.equal(advanced.epoch,(BigInt(h.request.epoch)+1n).toString());
    const all=rows(intent.journalPath);assert.equal(all.filter(r=>r.plan.action==='assess').length,2);
    assert.ok(all.every(r=>Buffer.from(r.plan.instructions.at(-1).dataBase64,'base64')[0]!==36));
    assert.equal((await h.data(a.epoch))[52],2);
    assert.ok(BigInt(advanced.spentLamports)>0n);
  }finally{await h.close();}
});

test('pending assessment packets retain exact identity through expiry, pruned history, source changes, and lost acknowledgement', {timeout:120000},async()=>{
  const h=await harness({row_indices:[0,17,63]});
  try{
    const intent=await h.intent('assessment-restart',h.request);
    for(const action of ['open','begin','append'])await executeAction(intent,action);
    await h.bridge.ask({method:'fixture_price',price:'2000000'});
    h.rpc.control.mode='drop';assert.equal((await intent.cycle()).state,'unacknowledged');
    const first=rows(intent.journalPath).at(-1);assert.equal(first.plan.action,'assess');
    await h.bridge.ask({method:'expire_blockhash'});h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=false;
    for(let restart=0;restart<2;restart++){
      await intent.cycle();assert.deepEqual(rows(intent.journalPath).at(-1),first);
    }
    await h.bridge.ask({method:'fixture_source_revision',revision:'2'});
    await assert.rejects(intent.cycle(),/collateral_operator|assessment/);
    assert.deepEqual(rows(intent.journalPath).at(-1),first,'pin failure cannot replace an unresolved packet');
    await h.bridge.ask({method:'fixture_source_revision',revision:'1'});
    h.rpc.control.historyCovered=true;
    const spentBefore=BigInt(scope(intent.journalPath).spent);
    const expired=await intent.cycle();assert.equal(expired.state,'expired');
    assert.equal(BigInt(expired.spentLamports)-spentBefore,BigInt(JSON.parse(first.quote).maxDebitLamports));
    h.rpc.control.mode='lost-ack';h.rpc.control.hideHistory=false;
    assert.equal((await intent.cycle()).state,'unacknowledged');
    const second=rows(intent.journalPath).at(-1);assert.equal(second.plan.action,'assess');
    assert.notEqual(second.signed.signature,first.signed.signature);
    h.rpc.control.mode='normal';h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=false;
    await h.bridge.ask({method:'expire_blockhash'});
    assert.equal((await intent.cycle()).state,'effect');
    assert.deepEqual(rows(intent.journalPath).at(-1).signed,second.signed);
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],1);
    h.rpc.control.hideHistory=false;h.rpc.control.historyCovered=true;
    await executeAction(intent,'cancel');
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],0);
    assert.equal((await until(intent,'complete')).state,'complete');
  }finally{await h.close();}
});

test('assessment and settlement share aggregate fee and transaction caps across process restarts', {timeout:120000},async()=>{
  for(const cap of ['transactions','lamports']){
    const h=await harness({row_indices:[0,17,63]});
    try{
      const rent=await h.bridge.ask({method:'rent',space:8416}),tokenRent=await h.bridge.ask({method:'rent',space:1280});
      const spent=BigInt(rent.lamports)+BigInt(tokenRent.lamports)+15000n;
      const policy={maxTransactions:cap==='transactions'?4:128,maxLamports:cap==='lamports'?(spent+5000n).toString():'1000000000'};
      const intent=await h.intent('shared-cap',h.request,policy);
      for(const action of ['open','begin','append'])await executeAction(intent,action);
      await h.bridge.ask({method:'fixture_price',price:'2000000'});
      await executeAction(intent,'assess');
      const before=rows(intent.journalPath),sent=h.rpc.sent.length;
      for(let restart=0;restart<2;restart++)await assert.rejects(intent.cycle(),/budget exhausted/);
      assert.deepEqual(rows(intent.journalPath),before);assert.equal(h.rpc.sent.length,sent);
      assert.equal(scope(intent.journalPath).spent,(spent+5000n).toString());
      assert.equal((await h.data(h.fixture.addresses.epoch))[52],1);
    }finally{await h.close();}
  }
});

test('stale assessment reads and quotes cannot persist or broadcast; external code/source changes fail closed', {timeout:120000},async()=>{
  const h=await harness({row_indices:[0,17,63]});
  try{
    await h.bridge.ask({method:'fixture_price',price:'2000000'});
    for(const boundary of ['plan','quote','sign']){
      const intent=await h.intent('lease-'+boundary,h.request),{config}=intent;
      const planner=await createRewardsPlanner({binary,tempRoot:config.journalPath+'-planner',securityConfig:h.securityConfig,logVersion:config.logVersion,pins:h.pins});
      const rpc=await connectRewardsRpc(config.rpc);
      const options={path:config.journalPath,pins:h.pins,request:h.request,policy:config.policy};
      const a=new RewardsJournal(options),b=new RewardsJournal(options);let now=100,sends=0;
      try{
        const takeover=()=>{now+=30001;b.claim('takeover',now);};
        const ctx={journal:a,lease:a.claim('stale',now),now:()=>++now,pins:h.pins,signers:[boundary==='sign'?{...h.payer,async signTransactions(...args){const signed=await h.payer.signTransactions(...args);takeover();return signed;}}:h.payer],
          planner:{...planner,async plan(request,floor){const plan=await planner.plan(request,floor);assert.equal(plan.action,'assess');if(boundary==='plan')takeover();return plan;}},
          rpc:{...rpc,async quote(step){const quote=await rpc.quote(step);if(boundary==='quote')takeover();return quote;},async broadcast(){sends++;}}};
        await assert.rejects(runRewardsCycle(ctx),/lease/);assert.equal(sends,0);
        assert.equal(a.pending()?.phase??null,boundary==='sign'?'reserved':null);
        assert.equal(a.progress().spentLamports,'0');assert.equal(a.progress().attempts,boundary==='sign'?1:0);
      }finally{a.close();b.close();}
    }
    const effectIntent=await h.intent('lease-effect',h.request),config=effectIntent.config;
    const effectPlanner=await createRewardsPlanner({binary,tempRoot:config.journalPath+'-planner',securityConfig:h.securityConfig,logVersion:config.logVersion,pins:h.pins});
    const effectRpc=await connectRewardsRpc(config.rpc);
    const options={path:config.journalPath,pins:h.pins,request:h.request,policy:config.policy};
    const owner=new RewardsJournal(options),replacement=new RewardsJournal(options);let effectNow=100;
    try{
      h.rpc.control.mode='drop';
      const ctx={journal:owner,lease:owner.claim('effect-stale',effectNow),now:()=>++effectNow,pins:h.pins,signers:[h.payer],rpc:effectRpc,
        planner:{...effectPlanner,async effect(...args){const value=await effectPlanner.effect(...args);effectNow+=30001;replacement.claim('effect-new',effectNow);return value;}}};
      assert.equal((await runRewardsCycle(ctx)).state,'unacknowledged');
      const original=owner.pending(),before=owner.progress(),sent=h.rpc.sent.length;
      assert.equal(original.plan.action,'assess');
      await h.bridge.ask({method:'expire_blockhash'});h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=true;
      await assert.rejects(runRewardsCycle(ctx),/lease/);
      assert.deepEqual(owner.pending(),original);assert.deepEqual(owner.progress(),before);assert.equal(h.rpc.sent.length,sent);
    }finally{owner.close();replacement.close();h.rpc.control.mode='normal';h.rpc.control.hideHistory=false;}
    const fresh=await h.intent('pin-change',h.request);
    await h.bridge.ask({method:'fixture_code_slot',role:'judge_data',slot:'1'});
    assert.equal((await fresh.cycle()).reason,'waiting:code-pins');assert.deepEqual(rows(fresh.journalPath),[]);
    await h.bridge.ask({method:'fixture_code_slot',role:'judge_data',slot:'0'});
    await h.bridge.ask({method:'fixture_source_revision',revision:'2'});
    assert.equal((await fresh.cycle()).reason,'waiting:source-pins');assert.deepEqual(rows(fresh.journalPath),[]);
    await h.bridge.ask({method:'fixture_source_revision',revision:'1'});
    await executeAction(fresh,'assess');
    for(const action of ['open','begin','append'])await executeAction(fresh,action);
    await h.bridge.ask({method:'fixture_source_revision',revision:'2'});
    await executeAction(fresh,'cancel');
    assert.equal((await fresh.cycle()).reason,'waiting:source-pins');
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],0);

  }finally{await h.close();}
});

test('directory assessment uses its fourteen-role packet and reconciles a lost acknowledgement through pruned history', {timeout:60000},async()=>{
  const h=await harness({row_count:0,directory_morse:true});
  try{
    const intent=await h.intent('directory-assessment',h.request),a=h.fixture.addresses;
    const pending=await h.data(a.directory_pending),bond=await h.data(a.directory);
    h.rpc.control.mode='lost-ack';assert.equal((await intent.cycle()).state,'unacknowledged');
    const first=rows(intent.journalPath)[0];assert.equal(first.plan.action,'assess');
    assert.equal(first.plan.assessment.subject,null);assert.equal(first.plan.instructions.at(-1).accountCount,14);
    assert.equal((await h.data(a.directory)).readBigUInt64LE(168),bond.readBigUInt64LE(168));
    assert.deepEqual(await h.data(a.directory_pending),pending);
    h.rpc.control.mode='normal';h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=false;
    await h.bridge.ask({method:'expire_blockhash'});
    assert.equal((await intent.cycle()).state,'effect');
    assert.deepEqual(rows(intent.journalPath)[0].signed,first.signed);
    h.rpc.control.hideHistory=false;h.rpc.control.historyCovered=true;
    assert.equal((await until(intent,'complete')).state,'complete');
    assert.equal(rows(intent.journalPath).filter(r=>r.plan.action==='assess').length,1);
  }finally{await h.close();}
});

test('durable assessment rotation reaches a later witness even when the earlier directory needs another transition', {timeout:60000},async()=>{
  const h=await harness({row_indices:[0,17,63],directory_morse:true});
  try{
    const intent=await h.intent('assessment-rotation',h.request);
    const first=await executeAction(intent,'assess');assert.equal(first.plan.assessment.subject,null);
    await h.bridge.ask({method:'fixture_price',price:'2000000'});
    const next=await executeAction(intent,'assess');
    assert.notEqual(next.plan.assessment.subject,null,'a changed directory cannot starve a later due witness across restarts');
    assert.equal(next.plan.assessment.subject.public_key,h.fixture.witnesses[2].key_hex);
    const directory=await executeAction(intent,'assess');assert.equal(directory.plan.assessment.subject,null);
    assert.equal((await until(intent,'complete')).state,'complete');
  }finally{await h.close();}
});
