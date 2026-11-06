import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
const HERE=path.dirname(fileURLToPath(import.meta.url)),PRODUCT=path.resolve(HERE,'../..');
const PUBLIC=process.env.MESH_LANG_ROOT||path.resolve(PRODUCT,'../mesh-lang');
const MESHC=process.env.MESHC||path.join(PUBLIC,'target/debug/meshc');
const kit=createRequire(path.join(PRODUCT,'ops/rewards/package.json'))('@solana/kit');
const base58=b=>kit.getBase58Decoder().decode(b),fixed=n=>base58(Buffer.alloc(32,n));
const sql=statement=>{const result=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',['-X','-At','-v','ON_ERROR_STOP=1','-c',statement],{encoding:'utf8',env:process.env});assert.equal(result.status,0,result.stderr);return result.stdout.trim();};
const run=(binary,args,env=process.env)=>new Promise((resolve,reject)=>{const child=spawn(binary,args,{cwd:PRODUCT,env});let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.once('error',reject);child.once('close',code=>resolve({code,stdout,stderr}));});
function rpcAccount(a){if(a.missing)return null;return {owner:a.owner,lamports:Number(a.lamports),space:Number(a.space),executable:a.executable,rentEpoch:0,data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64']};}
const clean=env=>{const value={...env};delete value.CARGO_TARGET_DIR;delete value.MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH;delete value.MORSE_TOKEN_CARRY_FIXTURES_PATH;delete value.MORSE_TOKEN_BURN_FIXTURES_PATH;return value;};

test('actual issuer CLI reserves once across restart and external owner executes its exact randomized24-chunk burn offline',{timeout:300000},async()=>{
 const work=await fs.mkdtemp(path.join(os.tmpdir(),'morse-burn-cli-')),servers=[];
 let requests=0,sends=0,phase='ready',bank,execution,unavailable=false;
 try{
  assert.ok(process.env.MESSENGER_ISSUER_TEST_DATABASE_URL,'run through owned-PG prove.py');
  let binary=process.env.CREDIT_ISSUER_BIN;
  if(!binary){binary=path.join(work,'issuer');const built=await run(MESHC,['build',path.join(PRODUCT,'services/credit-issuer'),'-o',binary]);assert.equal(built.code,0,built.stdout+built.stderr);}
  const nativeNow=Math.floor(Date.now()/1000),readyPath=path.join(work,'ready.json'),executionPath=path.join(work,'execution.json'),requestPath=path.join(work,'request.json');
  const sbfEnv=clean({...process.env,MORSE_CREDIT_BURN_NATIVE_NOW:String(nativeNow),MORSE_CREDIT_BURN_INITIAL_READY_PATH:readyPath,MORSE_CREDIT_BURN_EXECUTION_EXPORT_PATH:executionPath});
  const cargoArgs=['test','--locked','--manifest-path','programs/Cargo.toml','-p','morse-token','--features','svm,dex','--test','token_svm','missed_input_is_closed_once','--','--nocapture'];
  const initialized=await run('cargo',cargoArgs,sbfEnv);assert.equal(initialized.code,0,initialized.stdout+initialized.stderr);
  bank=JSON.parse(await fs.readFile(readyPath,'utf8'));
  for(let index=0;index<2;index++){
   const server=http.createServer(async(req,res)=>{try{let body='';for await(const b of req)body+=b;const query=JSON.parse(body);requests++;if(query.method==='sendTransaction'){sends++;throw Error('issuer broadcast forbidden');}
    if(unavailable&&index===1){res.writeHead(503);res.end();return;}
    let result;
    if(query.method==='getGenesisHash')result=bank.program;
    else{assert.equal(query.method,'getMultipleAccounts');assert.equal(query.params[1].commitment,'finalized');
     const snapshot=phase==='ready'?bank:phase==='funded'?execution.funded:execution.closed;
     assert.deepEqual(query.params[0],snapshot.accounts.map(a=>a.address));
     result={context:{slot:Number(snapshot.context_slot)},value:snapshot.accounts.map(rpcAccount)};
    }
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:query.id,result}));
   }catch(error){res.writeHead(500);res.end(String(error));}});
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
  }
  const urls=servers.map(s=>`http://127.0.0.1:${s.address().port}`),keys=path.join(work,'keys');await fs.mkdir(keys,{mode:0o700});
  const pin=`witness-a ${'33'.repeat(32)} Test`,security=['3','11'.repeat(32),'22'.repeat(32),'16','1','1',pin,'-','0','https://credits.example','2','1','1',pin].join('\n');
  const rewards=fixed(54),[pool]=await kit.getProgramDerivedAddress({programAddress:rewards,seeds:['pool']});
  const env={...process.env,MORSE_CREDITS_MODE:'off',MESSENGER_CREDITS_PURPOSE:'test',MORSE_LIGHTNING_MODE:'off',MORSE_TREASURY_MODE:'test',MORSE_BURN_MODE:'test',MESSENGER_CREDIT_REVENUE_POLICY:'2',
   MESSENGER_ISSUER_DATABASE_URL:process.env.MESSENGER_ISSUER_TEST_DATABASE_URL,MESSENGER_ISSUER_SECURITY_CONFIG:security,MESSENGER_CREDIT_STORAGE_DIR:keys,
   MESSENGER_CREDIT_USDC_MINT:bank.usdc,MESSENGER_CREDIT_SOLANA_RPC_URL:urls[0],MESSENGER_DELIVERY_INTERNAL_URL:'http://127.0.0.1:18998',
   MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN:'a'.repeat(32),MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN:'b'.repeat(32),
   MESSENGER_TREASURY_RPC_A:urls[0],MESSENGER_TREASURY_RPC_B:urls[1],MESSENGER_TREASURY_GENESIS:bank.program,MESSENGER_TREASURY_OWNER:bank.treasury,
   MESSENGER_TREASURY_FEE_PAYER:fixed(11),MESSENGER_TREASURY_NONCE_AUTHORITY:fixed(12),MESSENGER_TREASURY_NONCE_ACCOUNT:fixed(13),MESSENGER_TREASURY_REWARDS_PROGRAM:rewards,MESSENGER_TREASURY_REWARDS_POOL:pool,
   MESSENGER_TREASURY_BURN_PROGRAM:bank.program,MESSENGER_TREASURY_BURN_GOVERNANCE:bank.governance,MESSENGER_TREASURY_BURN_FACTORY:bank.factory,MESSENGER_TREASURY_BURN_PROGRAM_SLOT:bank.program_slot};
  const invoke=async(args,expected=true,overrides={})=>{const value=await run(binary,['treasury',...args],{...env,...overrides});if(expected){assert.equal(value.code,0,value.stdout+value.stderr);return JSON.parse(value.stdout);}assert.notEqual(value.code,0,'unexpected operator success');return value;};
  const status=await invoke(['status']);assert.equal(status.provisioned,false);assert.match(status.config_hash,/^[0-9a-f]{64}$/);
  const mintHex=Buffer.from(kit.getBase58Encoder().encode(bank.usdc)).toString('hex');
  let carries=[0n,0n,0n];
  for(const [index,gross] of [233333334n,166666666n].entries()){
   const before=carries,shares=[2n,3n,5n].map((n,i)=>(gross*n+before[i])/10n);carries=[2n,3n,5n].map((n,i)=>(gross*n+before[i])%10n);
   sql(`INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_before,burn_carry_after,operations_carry_before,operations_carry_after,reserve_before,reserve_after,membership_hash,policy_version,policy_hash) SELECT ${2700+index},0,0,decode('${mintHex}','hex'),decode('${status.config_hash}','hex'),${gross},${shares[0]},${shares[1]},${shares[2]},${before[0]},${carries[0]},${before[1]},${carries[1]},${before[2]},${carries[2]},${before.reduce((a,b)=>a+b,0n)/10n},${carries.reduce((a,b)=>a+b,0n)/10n},decode(repeat('aa',32),'hex'),2,policy_hash FROM issuer_revenue_policies WHERE policy_version=2`);
  }
  sql('INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) SELECT batch_id,burn FROM issuer_treasury_weekly WHERE policy_version=2');
  assert.equal(sql('SELECT SUM(amount)::text||\':\'||SUM(witness)::text||\':\'||SUM(burn)::text||\':\'||SUM(operations)::text FROM issuer_treasury_weekly'),'400000000:80000000:120000000:200000000');
  await invoke(['burn-request',bank.epoch,'0'],false,{MORSE_BURN_MODE:'off'});
  const plans=await Promise.all(Array.from({length:6},()=>invoke(['burn-request',bank.epoch,'0']))),plan=plans[0];
  for(const other of plans)assert.deepEqual(other,plan);
  assert.equal(plan.state,'pending');assert.equal(plan.cash,'120000000');assert.equal(plan.carry,'0');assert.equal(plan.weights.length,24);assert.equal(plan.entropy.length,24);
  assert.ok(new Set(plan.weights).size>1);assert.ok(new Set(plan.entropy).size>1);
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_intents'),'1');assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members'),'2');
  await fs.writeFile(requestPath,JSON.stringify(plan));
  const sent=await run('cargo',cargoArgs,{...sbfEnv,MORSE_CREDIT_BURN_FUND_REQUEST_PATH:requestPath});assert.equal(sent.code,0,sent.stdout+sent.stderr);assert.match(sent.stderr,/MORSE_CREDIT_BURN_CLI_SBF/);
  execution=JSON.parse(await fs.readFile(executionPath,'utf8'));phase='funded';
  assert.equal(execution.cash_debited,'120000000');assert.equal(execution.actual_chunks,24);assert.equal(execution.actual_jupiter_raydium,true);assert.equal(execution.replay_no_second_cash_transfer,true);
  unavailable=true;await invoke(['burn-reconcile',plan.intent_id],false);assert.equal(sql('SELECT state FROM issuer_treasury_burn_intents'),'0');assert.equal(sql('SELECT SUM(amount) FROM issuer_treasury_burn_liabilities WHERE state=0'),'120000000');
  unavailable=false;const recovered=await invoke(['burn-reconcile',plan.intent_id]);assert.equal(recovered.state,'funded');assert.equal(recovered.intent_id,plan.intent_id);assert.equal(recovered.funding_hash,plan.funding_hash);
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_liabilities WHERE state=1'),'2');
  phase='closed';const restart=await invoke(['burn-request',bank.epoch,'0']);assert.equal(restart.state,'funded');assert.equal(restart.intent_id,plan.intent_id);assert.equal(restart.instruction,undefined);
  assert.equal(sends,0);assert.ok(requests>0);
  const report={schema_version:1,passed:true,actual_compiled_issuer_cli:true,concurrent_requests:6,immutable_members:2,gross_units:'400000000',witness_units:'80000000',burn_units:'120000000',operations_units:'200000000',reserve_units:0,actual_sbf:true,actual_router_dex:true,randomized_chunks:24,burned_units:execution.burned_units,ambiguous_rpc_keeps_pending:true,hard_process_restart_same_intent:true,issuer_broadcasts:0,real_funds:false,program_source:'archived_qualified_sbf',boundary:'Synthetic accounting rows; exact emitted external-owner instruction executes locally. Loopback RPC mirrors actual isolated bank states; no live finality/feed/market or production activation claim.'};
  if(process.env.BURN_CLI_REPORT)await fs.writeFile(process.env.BURN_CLI_REPORT,JSON.stringify(report,null,2)+'\n');
  console.log('MORSE_CREDIT_BURN_CLI_JSON='+JSON.stringify(report));
 }finally{for(const server of servers)await new Promise(resolve=>server.close(resolve));await fs.rm(work,{recursive:true,force:true});}
});
