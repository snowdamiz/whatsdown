import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import test from 'node:test';

const here=import.meta.dirname,product=path.resolve(here,'../..');
const publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const meshc=process.env.MESHC||path.join(publicRoot,'target/debug/meshc');
const kit=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/kit');
const base58=b=>kit.getBase58Decoder().decode(b),fixed=n=>base58(Buffer.alloc(32,n));
const run=(binary,args,env=process.env)=>new Promise((resolve,reject)=>{
 const child=spawn(binary,args,{cwd:product,env});let stdout='',stderr='';
 child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 child.once('error',reject);child.once('close',code=>resolve({code,stdout,stderr}));
});
const sql=statement=>{const r=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',
 ['-X','-At','-v','ON_ERROR_STOP=1','-c',statement],{encoding:'utf8',env:process.env});
 assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
const clean=env=>{const copy={...env};for(const name of Object.keys(copy))if(name==='CARGO_TARGET_DIR'
 || name.startsWith('MORSE_TOKEN_')&&name.endsWith('_PATH')
 || name.startsWith('MORSE_CREDIT_BURN_'))delete copy[name];return copy;};

test('actual issuer restart releases only quorum-proved permanent empty week, then funds the same liabilities once offline',
 {timeout:360000},async()=>{
 const work=await fs.mkdtemp(path.join(os.tmpdir(),'morse-expiry-cli-')),servers=[];
 let phase='absence',unavailable=false,requests=0,sends=0,root,ready,expired,execution;
 try{
  assert.ok(process.env.MESSENGER_ISSUER_TEST_DATABASE_URL,'use owned-PG prove.py');
  let binary=process.env.CREDIT_ISSUER_BIN;
  if(!binary){binary=path.join(work,'issuer');const r=await run(meshc,['build',path.join(product,'services/credit-issuer'),'-o',binary]);assert.equal(r.code,0,r.stdout+r.stderr);}
  const nativeNow=Math.floor(Date.now()/1000),fixture=path.join(work,'tombstone.json'),
   readyPath=path.join(work,'ready.json'),expiryPath=path.join(work,'external-expiry.json'),
   expiryRequestPath=path.join(work,'expiry-request.json'),fundRequestPath=path.join(work,'fund-request.json'),
   executionPath=path.join(work,'execution.json');
  const sbfEnv={...clean(process.env),MORSE_TOKEN_SBF_PATH:process.env.MORSE_TOKEN_SBF_PATH,
   MORSE_TOKEN_DEX_BIN_DIR:process.env.MORSE_TOKEN_DEX_BIN_DIR,
   MORSE_TOKEN_EXPIRY_FIXTURES_PATH:fixture,MORSE_CREDIT_BURN_NATIVE_NOW:String(nativeNow),
   MORSE_CREDIT_BURN_NEXT_READY_PATH:readyPath,MORSE_CREDIT_BURN_EXECUTION_EXPORT_PATH:executionPath};
  const cargoArgs=['test','--locked','--manifest-path','programs/Cargo.toml','-p','morse-token',
   '--features','svm,dex','--test','token_svm','expired_unfunded_week_is_permanent','--','--nocapture'];
  let sbfRun=0;const sbf=async(extra={})=>{const r=await run('cargo',cargoArgs,{...sbfEnv,...extra});await fs.writeFile(path.join(work,`sbf-${sbfRun++}.log`),r.stdout+r.stderr);assert.equal(r.code,0,r.stdout+r.stderr);return r;};
  await sbf();root=JSON.parse(await fs.readFile(fixture,'utf8'));ready=JSON.parse(await fs.readFile(readyPath,'utf8'));
  const image=await fs.readFile(process.env.MORSE_TOKEN_SBF_PATH);
  function bankAccounts(){return phase==='absence'?root.before_expiry.accounts:
   phase==='expired'?expired.accounts:phase==='ready'?ready.accounts:
   phase==='funded'?execution.funded.accounts:execution.closed.accounts;}
  for(let index=0;index<2;index++){
   const server=http.createServer(async(req,res)=>{try{
    let body='';for await(const b of req)body+=b;assert.ok(body.length<32768);const q=JSON.parse(body);requests++;
    if(q.method==='sendTransaction'){sends++;throw Error('issuer must not broadcast');}
    if(unavailable&&index===1){res.writeHead(503);res.end();return;}
    let result;
    if(q.method==='getGenesisHash')result=root.program;
    else{
     assert.equal(q.method,'getMultipleAccounts');assert.equal(q.params[1].commitment,'finalized');
     const rows=bankAccounts(),snapshot=phase==='absence'?root.before_expiry:
      phase==='expired'?expired:phase==='ready'?ready:phase==='funded'?execution.funded:execution.closed;
     const accounts=new Map(rows.map(a=>[a.address,a]));
     result={context:{slot:Number(snapshot.context_slot)},value:q.params[0].map(key=>{
      const a=accounts.get(key);if(!a||a.missing)return null;
      let bytes=Buffer.from(a.data_hex,'hex');
      if(key===root.accounts[8].address)bytes=Buffer.concat([bytes.subarray(0,45),image]);
      const slice=q.params[1].dataSlice;if(slice)bytes=bytes.subarray(slice.offset,slice.offset+slice.length);
      return {owner:a.owner,lamports:Number(a.lamports),space:Number(a.space),executable:a.executable,
       rentEpoch:0,data:[bytes.toString('base64'),'base64']};
     })};
    }
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:q.id,result}));
   }catch(error){res.writeHead(500);res.end(String(error));}});
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
  }
  const urls=servers.map(s=>`http://127.0.0.1:${s.address().port}`),keys=path.join(work,'keys');await fs.mkdir(keys,{mode:0o700});
  const pin=`witness-a ${'33'.repeat(32)} Test`,security=['3','11'.repeat(32),'22'.repeat(32),'16','1','1',pin,'-','0','https://credits.example','2','1','1',pin].join('\n');
  const rewards=fixed(54),[pool]=await kit.getProgramDerivedAddress({programAddress:rewards,seeds:['pool']});
  const env={...process.env,MORSE_CREDITS_MODE:'off',MESSENGER_CREDITS_PURPOSE:'test',MORSE_LIGHTNING_MODE:'off',MORSE_TREASURY_MODE:'test',MORSE_BURN_MODE:'test',MESSENGER_CREDIT_REVENUE_POLICY:'2',
   MESSENGER_ISSUER_DATABASE_URL:process.env.MESSENGER_ISSUER_TEST_DATABASE_URL,MESSENGER_ISSUER_SECURITY_CONFIG:security,MESSENGER_CREDIT_STORAGE_DIR:keys,
   MESSENGER_CREDIT_USDC_MINT:root.usdc,MESSENGER_CREDIT_SOLANA_RPC_URL:urls[0],MESSENGER_DELIVERY_INTERNAL_URL:'http://127.0.0.1:18998',
   MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN:'a'.repeat(32),MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN:'b'.repeat(32),
   MESSENGER_TREASURY_RPC_A:urls[0],MESSENGER_TREASURY_RPC_B:urls[1],MESSENGER_TREASURY_GENESIS:root.program,MESSENGER_TREASURY_OWNER:root.treasury,
   MESSENGER_TREASURY_FEE_PAYER:fixed(11),MESSENGER_TREASURY_NONCE_AUTHORITY:fixed(12),MESSENGER_TREASURY_NONCE_ACCOUNT:fixed(13),MESSENGER_TREASURY_REWARDS_PROGRAM:rewards,MESSENGER_TREASURY_REWARDS_POOL:pool,
   MESSENGER_TREASURY_BURN_PROGRAM:root.program,MESSENGER_TREASURY_BURN_GOVERNANCE:root.governance,MESSENGER_TREASURY_BURN_FACTORY:root.factory,MESSENGER_TREASURY_BURN_PROGRAM_SLOT:root.program_slot};
  const invoke=async(args,ok=true)=>{const r=await run(binary,['treasury',...args],env);
   if(ok){assert.equal(r.code,0,r.stdout+r.stderr);return JSON.parse(r.stdout);}
   assert.notEqual(r.code,0,'unexpected operator success: '+r.stdout);return r;};
  const status=await invoke(['status']);
  const seedDir=path.join(work,'seed');await fs.mkdir(seedDir);
  await fs.writeFile(path.join(seedDir,'mesh.toml'),`[package]\nname="expiry-seed"\nversion="0.1.0"\n[dependencies]\ncredit-issuer={path=${JSON.stringify(path.join(product,'services/credit-issuer'))}}\n`);
  await fs.copyFile(path.join(here,'seed.mpl.fixture'),path.join(seedDir,'main.mpl'));
  const seedBin=path.join(work,'seed-bin'),built=await run(meshc,['build',seedDir,'-o',seedBin]);assert.equal(built.code,0,built.stdout+built.stderr);
  const seeded=await run(seedBin,[],{...env,BURN_EXPIRY_FIXTURE:fixture,BURN_EXPIRY_CONFIG_HASH:status.config_hash});assert.equal(seeded.code,0,seeded.stdout+seeded.stderr);
  const oldId=seeded.stdout.trim();assert.match(oldId,/^[0-9a-f]{64}$/);
  await invoke(['burn-reconcile',oldId],false);
  assert.equal(sql('SELECT state FROM issuer_treasury_burn_intents'),'0');
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members WHERE NOT released'),'2');
  const expiryPlans=await Promise.all(Array.from({length:6},()=>invoke(['burn-expire-request',root.epoch]))),expiryPlan=expiryPlans[0];
  for(const other of expiryPlans)assert.deepEqual(other,expiryPlan);
  assert.equal(expiryPlan.state,'expiry_pending');assert.equal(expiryPlan.intent_id,oldId);
  await fs.writeFile(expiryRequestPath,JSON.stringify(expiryPlan));
  // Setup may include a slow compiler. Refresh using a genuine SBF oracle
  // observation, never a rewritten RPC timestamp or a weaker freshness bound.
  sbfEnv.MORSE_CREDIT_BURN_NATIVE_NOW=String(Math.floor(Date.now()/1000));
  const expiredRun=await sbf({MORSE_CREDIT_BURN_EXPIRE_REQUEST_PATH:expiryRequestPath,MORSE_CREDIT_BURN_EXPIRE_EXECUTION_PATH:expiryPath});
  assert.match(expiredRun.stderr,/MORSE_CREDIT_BURN_EXPIRE_CLI_SBF/);expired=JSON.parse(await fs.readFile(expiryPath,'utf8'));phase='expired';
  unavailable=true;await invoke(['burn-reconcile',oldId],false);
  assert.equal(sql('SELECT state FROM issuer_treasury_burn_intents'),'0');
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members WHERE released'),'0');
  unavailable=false;const ended=await invoke(['burn-reconcile',oldId]);assert.equal(ended.state,'expired_unfunded');assert.equal(ended.instruction,undefined);
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members WHERE released'),'2');
  assert.equal((await invoke(['burn-request',root.epoch,'0'])).state,'expired_unfunded');
  ready=JSON.parse(await fs.readFile(readyPath,'utf8'));
  phase='ready';const funding=await Promise.all(Array.from({length:6},()=>invoke(['burn-request',ready.epoch,'0']))),plan=funding[0];
  for(const other of funding)assert.deepEqual(other,plan);
  assert.equal(plan.state,'pending');assert.equal(plan.cash,'120000000');assert.notEqual(plan.intent_id,oldId);
  assert.ok(new Set(plan.weights).size>1);assert.ok(new Set(plan.entropy).size>1);
  await fs.writeFile(fundRequestPath,JSON.stringify(plan));
  const fundedRun=await sbf({MORSE_CREDIT_BURN_FUND_REQUEST_PATH:fundRequestPath});assert.match(fundedRun.stderr,/MORSE_CREDIT_BURN_CLI_SBF/);
  execution=JSON.parse(await fs.readFile(executionPath,'utf8'));assert.equal(execution.cash_debited,'120000000');assert.equal(execution.actual_chunks,24);
  phase='funded';assert.equal((await invoke(['burn-reconcile',plan.intent_id])).state,'funded');
  assert.equal((await invoke(['burn-reconcile',oldId])).state,'expired_unfunded');
  phase='closed';assert.equal((await invoke(['burn-request',ready.epoch,'0'])).state,'funded');
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members'),'4');
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_members WHERE released'),'2');
  assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_burn_liabilities WHERE state=1'),'2');
  assert.equal(sends,0);assert.ok(requests>0);
  const report={schema_version:1,passed:true,actual_compiled_issuer_cli:true,concurrent_expiry_preparations:6,concurrent_future_reservations:6,
   exact_external_rent_payer_sbf:true,absence_never_releases:true,ambiguous_rpc_keeps_pending:true,immutable_history_rows:4,released_old_members:2,
   future_cash_units:'120000000',randomized_chunks:24,actual_jupiter_raydium_spl:true,old_receipt_inert_after_future_funding:true,issuer_broadcasts:0,real_funds:false,
   boundary:'Synthetic prior accounting and old reservation. Actual compiled operator instructions execute in isolated SBF with real SPL/router CPIs; loopback RPC mirrors those banks, without live consensus, market, feed or activation claims.'};
  if(process.env.BURN_EXPIRY_ARTIFACT_DIR){await fs.mkdir(process.env.BURN_EXPIRY_ARTIFACT_DIR,{recursive:true});
   for(const name of ['tombstone.json','ready.json','expiry-request.json','external-expiry.json','fund-request.json','execution.json','sbf-0.log','sbf-1.log','sbf-2.log'])await fs.copyFile(path.join(work,name),path.join(process.env.BURN_EXPIRY_ARTIFACT_DIR,name));}
  if(process.env.BURN_EXPIRY_CLI_REPORT)await fs.writeFile(process.env.BURN_EXPIRY_CLI_REPORT,JSON.stringify(report,null,2)+'\n');
  console.log('MORSE_TOKEN_EXPIRY_CLI '+JSON.stringify(report));
 }finally{for(const s of servers)await new Promise(resolve=>s.close(resolve));await fs.rm(work,{recursive:true,force:true});}
});
