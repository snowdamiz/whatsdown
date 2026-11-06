import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createRequire} from 'node:module';
import {createInterface} from 'node:readline';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {prepareRewardsTransaction,signRewardsTransaction} from '../../ops/rewards/transactions.mjs';
const product=path.resolve(import.meta.dirname,'../..'), publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const compiler=process.env.MESHC||path.join(publicRoot,'target/debug/meshc');
const require=createRequire(path.join(product,'ops/rewards/package.json'));
const kit=require('@solana/kit'),{parseJsonWithBigInts,stringifyJsonWithBigInts}=require('@solana/rpc-spec-types');
const bridgePath=process.env.MORSE_REWARDS_SBF_BRIDGE||path.join(product,'programs/target/debug/examples/rewards_writer_bridge');
const operator=process.env.MORSE_REWARDS_TEST_OPERATOR_BIN||path.resolve(product,'../.morse/witness-proof/rewards-test-operator');
class Bridge {
 constructor(){this.child=spawn(bridgePath,[],{stdio:['pipe','pipe','pipe'],env:{...process.env,MORSE_JUDGE_SBF_PATH:process.env.MORSE_JUDGE_SBF_PATH||path.join(product,'programs/target/deploy/morse_judge.so'),MORSE_REWARDS_SBF_PATH:process.env.MORSE_REWARDS_SBF_PATH||path.join(product,'programs/target/deploy/morse_rewards.so')}});this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();this.pending=Promise.resolve();this.errors='';this.child.stderr.on('data',x=>this.errors+=x);}
 ask(value){const next=this.pending.then(async()=>{this.child.stdin.write(JSON.stringify(value)+'\n');const line=await this.lines.next();assert.equal(line.done,false,this.errors);return JSON.parse(line.value);});this.pending=next.catch(()=>{});return next;}
 close(){this.child.kill('SIGKILL');}
}
test('weekly treasury handoff funds actual rewards SBF once and accepts only its permanent exact receipt',{timeout:120000},async()=>{
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'morse-week-funding-')),bridge=new Bridge(),servers=[];let malformed='';
 try{
  const payer=await kit.createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11)),funder=await kit.createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(12));
  const fixture=await bridge.ask({method:'initialize',payer:payer.address,funder:funder.address});
  for(let index=0;index<3;index++){
   const server=http.createServer(async(request,response)=>{try{
    let body='';for await(const chunk of request)body+=chunk;const query=parseJsonWithBigInts(body);let result;
    if(query.method==='getGenesisHash')result=kit.getBase58Decoder().decode(new Uint8Array(32).fill(0x11));
    else if(query.method==='getBlockTime')result=BigInt((await bridge.ask({method:'context'})).unix_timestamp);
    else{
     assert.equal(query.params[1].commitment,'finalized');const config=query.params[1],slice=config.dataSlice?{offset:Number(config.dataSlice.offset),length:Number(config.dataSlice.length)}:{};
     const found=query.method==='getMultipleAccounts'?await bridge.ask({method:'accounts',addresses:query.params[0],...slice}):await bridge.ask({method:'account',address:query.params[0],...slice});
     function account(value){if(value===null)return null;let next={...value,lamports:BigInt(value.lamports),space:BigInt(value.space),rentEpoch:0n};if(value.space==='192'&&malformed==='owner')next.owner='11111111111111111111111111111111';if(value.space==='192'&&malformed==='amount'){const bytes=Buffer.from(next.data[0],'base64');bytes.writeBigUInt64LE(bytes.readBigUInt64LE(112)+1n,112);next.data=[bytes.toString('base64'),'base64'];}return next;}
     result={context:{slot:BigInt(found.context.slot)},value:Array.isArray(found.value)?found.value.map(account):account(found.value)};
    }
    response.writeHead(200,{'content-type':'application/json'});response.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:query.id,result}));
   }catch(error){response.writeHead(500);response.end(String(error));}});server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);
  }
  const endpoints=servers.map(server=>`http://127.0.0.1:${server.address().port}`),program=path.join(temporary,'funding');await fs.mkdir(program);
  await fs.writeFile(path.join(program,'mesh.toml'),`[package]\nname="funding-proof"\nversion="0.1.0"\n[dependencies]\nmessenger-protocol={path=${JSON.stringify(path.join(product,'packages/messenger-protocol'))}}\n`);
  for(const relative of ['payment/revenue_policy.mpl','payment/treasury.mpl','payment/treasury_outcome.mpl','payment/treasury_rewards.mpl','payment/verify.mpl','payment/observation.mpl','storage/treasury.mpl','storage/treasury_packet.mpl','storage/treasury_nonce.mpl','storage/treasury_funding.mpl','runtime/treasury_signing.mpl','runtime/treasury.mpl','runtime/treasury_funding.mpl']){const target=path.join(program,relative);await fs.mkdir(path.dirname(target),{recursive:true});await fs.copyFile(path.join(product,'services/credit-issuer',relative),target);}
  await fs.copyFile(path.join(import.meta.dirname,'fixtures/funding.mpl.fixture'),path.join(program,'main.mpl'));
  const executable=path.join(program,'proof'),built=spawnSync(compiler,['build','--opt-level','2',program,'-o',executable],{encoding:'utf8'});assert.equal(built.status,0,built.stdout+built.stderr);
  async function executeClient(mode,extra={},expected=true){const input=path.join(temporary,'input.json');await fs.writeFile(input,JSON.stringify({...fixture,provider_a:endpoints[0],provider_b:endpoints[1],mode,...extra}));const child=spawn(executable,[],{env:{...process.env,TREASURY_INPUT:input}});let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);const [code]=await once(child,'close');if(expected)assert.equal(code,0,stdout+stderr);else assert.notEqual(code,0,'forged receipt accepted');return stdout.trim();}
  const batch_id=await executeClient('init');const prepared=JSON.parse(await executeClient('prepare',{batch_id}));assert.equal(prepared.state,0);assert.equal(prepared.amount,'1000000');assert.equal(prepared.request.kind,0);
  const requestPath=path.join(temporary,'request.json'),intent={...prepared.request,configuration:{judge:fixture.judge,log_name:fixture.log_name,service_key:'11'.repeat(32),version:1,endpoints}};
  let fundPacket,packets=0;
  for(let count=0;count<3;count++){
   await fs.writeFile(requestPath,JSON.stringify(intent));const child=spawn(operator,['--input',requestPath],{env:process.env});let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);const [code]=await once(child,'close');assert.equal(code,0,stdout+stderr);const plan=JSON.parse(stdout);if(plan.status==='complete')break;
   const step=prepareRewardsTransaction(plan,{program:fixture.program,judge:fixture.judge,log:fixture.log,mint:fixture.mint,payer:payer.address});await bridge.ask({method:'expire_blockhash'});const context=await bridge.ask({method:'context'}),lifetime={blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.last_valid_block_height)};
   const signers=plan.signer_keys.map(key=>{assert.ok(key===payer.address||key===funder.address);return key===payer.address?payer:funder;});const signed=await signRewardsTransaction(step,signers,lifetime);const sent=await bridge.ask({method:'send',transaction:signed.wire});assert.equal(sent.ok,true,JSON.stringify(sent));packets++;if(plan.action==='fund')fundPacket={step,signers};
  }
  assert.ok(fundPacket,'weekly handoff never funded');const funded=await bridge.ask({method:'state'});assert.equal(funded.accounted,'1000000');assert.equal(funded.subsidy,'0');
  malformed='owner';await executeClient('reconcile',{intent_id:prepared.intent_id},false);malformed='amount';await executeClient('reconcile',{intent_id:prepared.intent_id},false);malformed='';
  const confirmed=JSON.parse(await executeClient('reconcile',{intent_id:prepared.intent_id}));assert.equal(confirmed.state,1);assert.equal(confirmed.intent_id,prepared.intent_id);
  await bridge.ask({method:'expire_blockhash'});const context=await bridge.ask({method:'context'}),repeat=await signRewardsTransaction(fundPacket.step,fundPacket.signers,{blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.last_valid_block_height)});assert.equal((await bridge.ask({method:'send',transaction:repeat.wire})).ok,true);assert.deepEqual(await bridge.ask({method:'state'}),funded);
  await bridge.ask({method:'warp',unix_timestamp:((BigInt(fixture.epoch)+2n)*604800n+10n).toString()});const replay=JSON.parse(await executeClient('prepare',{batch_id}));assert.equal(replay.state,1);assert.equal(replay.intent_id,prepared.intent_id);assert.equal((await bridge.ask({method:'state'})).accounted,'1000000');
  const report={schema_version:1,passed:true,actual_rewards_sbf:true,actual_spl_cpi:true,weekly_amount_units:'5000003',witness_funded_units:'1000000',policy_version:Number(process.env.TREASURY_REVENUE_POLICY||'1'),operations_units:process.env.TREASURY_REVENUE_POLICY==='2'?'2500001':'4000003',burn_units:process.env.TREASURY_REVENUE_POLICY==='2'?'1500000':'0',reserve_units:process.env.TREASURY_REVENUE_POLICY==='2'?2:0,fifths_carry:process.env.TREASURY_REVENUE_POLICY==='2'?null:3,kind:0,permanent_receipt:true,two_provider_clock_receipt_snapshot:true,wrong_owner_rejected:true,wrong_amount_rejected:true,fresh_signature_retry_no_double_fund:true,rollover_reuses_funded_intent:true,packets,real_funds:false};if(process.env.TREASURY_REPORT)await fs.writeFile(process.env.TREASURY_REPORT,JSON.stringify(report,null,2)+'\n');console.log('TREASURY_FUNDING_JSON='+JSON.stringify(report));
 }finally{bridge.close();for(const server of servers)await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}
});
