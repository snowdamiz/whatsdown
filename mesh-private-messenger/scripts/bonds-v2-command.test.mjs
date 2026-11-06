import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test,{after} from 'node:test';
let builtWork=null;
after(()=>{if(builtWork)fs.rmSync(builtWork,{recursive:true,force:true});});
let binary=process.env.MORSE_CLI_BIN;
const fixture=process.env.MORSE_BONDS_V2_FIXTURES;
const corpus=fixture?JSON.parse(fs.readFileSync(fixture)):null;
const fixtures=corpus?.snapshots??[];
const find=name=>{const value=fixtures.find(s=>s.name===name);assert(value,name);return value;};
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let integer = BigInt(`0x${bytes.toString('hex')}`), result = '';
  while (integer) { result = alphabet[Number(integer % 58n)] + result; integer /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = `1${result}`; }
  return result;
}
const bytes = (s, role) => Buffer.from(s.accounts[role].data_hex, 'hex');
const key = (s, role, at) => base58(bytes(s, role).subarray(at, at + 32));
const number = (s, role, at) => bytes(s, role).readBigUInt64LE(at).toString();
function configuration(s, endpoints) {
  const witnesses = Object.keys(s.accounts).filter(role => /^witness\d+$/.test(role)).map(role => {
    const b = bytes(s, role); return { witness_id: b.subarray(8, 8 + b[4]).toString(), public_key: b.subarray(72, 104).toString('hex') };
  });
  return {
    schema_version: 1, scope: 'local-fixture', endpoints, epochs: ['1'], minimum_context_slot: s.context_slot, max_age_seconds: '900',
    pins: { program: s.token_program, governance: key(s, 'token_config', 4), program_slot: number(s, 'token_data', 4), usdc: s.accounts.usdc.address, treasury: key(s, 'token_config', 80), factory: key(s, 'token_config', 112) },
    collateral: { schema_version: 2, judge: s.program, judge_slot: number(s, 'judge_data', 4), rewards: s.rewards_program, rewards_slot: number(s, 'rewards_data', 4), rewards_governance: key(s, 'pool', 4), log_name: s.log_name, log_version: bytes(s, 'log')[4], service_public_key: bytes(s, 'log').subarray(72, 104).toString('hex'), morse_mint: s.accounts.morse.address, network_started: number(s, 'pool', 164), witnesses, proofs: s.accounts.proof ? [bytes(s, 'proof').subarray(40, 72).toString('hex')] : [] },
  };
}



test('explicit v2 bond mode rejects malformed schema without needing legacy security configuration',{timeout:150000},async()=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'morse-cli-v2-config-'));
 try{
  if(!binary){
   builtWork=work;binary=path.join(work,'morse');
   const compiler=process.env.MESHC??fileURLToPath(new URL('../../mesh-lang/target/debug/meshc',import.meta.url));
   const source=process.env.MORSE_CLI_SOURCE??fileURLToPath(new URL('../clients/mesh-cli',import.meta.url));
   const built=spawnSync(compiler,['build',source,'--output',binary,'--opt-level','2'],{encoding:'utf8',timeout:140000});assert.equal(built.status,0,built.stdout+built.stderr);
  }
  const input=path.join(work,'schema.json');fs.writeFileSync(input,'{"schema_version":0}');
  const result=spawnSync(binary,['bonds','--log','morse-main','--v2-config',input],{env:{...process.env,MESSENGER_SECURITY_CONFIG:'',MORSE_BOND_MINT:''},encoding:'utf8',timeout:10000});
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.match(result.stderr,/bonds_v2_schema/);
 }finally{
  // A supplied fixture executable remains caller-owned.
  if(process.env.MORSE_CLI_BIN)fs.rmSync(work,{recursive:true,force:true});
 }
});

test('explicit v2 CLI authenticates fresh owned mixed-asset custody and refuses drift without legacy fallback',{skip:!binary||!fixture,timeout:120000},async()=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'morse-cli-v2-bonds-'));
 let selected=find('fresh-active-mixed'),modes=['good','good','good'],requests=0;const cliTrace=[];
 const failures=[];let delayedClock=0;
 const servers=modes.map((_,n)=>http.createServer(async(req,res)=>{
  try{
   let body='';for await(const part of req)body+=part;
   const rpc=JSON.parse(body);requests++;assert.equal(req.method,'POST');assert.equal(rpc.method,'getMultipleAccounts');
   assert.deepEqual(rpc.params[1],{commitment:'finalized',encoding:'base64',minContextSlot:Number(selected.context_slot),dataSlice:{offset:0,length:8416}});
   assert(rpc.params[0].length<=100);
   if(modes[n]==='outage'){res.writeHead(503).end();return;}
   const source=modes[n]==='other'?find('fresh-pending-mixed'):selected;
   const byAddress=new Map(Object.values(source.accounts).map(x=>[x.address,x]));
   const values=rpc.params[0].map(address=>{
    const a=byAddress.get(address);assert(a,address);
    return a.missing?null:{owner:a.owner,lamports:Number(a.lamports),executable:a.executable,rentEpoch:0,space:Number(a.space),data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64']};
   });
   const index=role=>rpc.params[0].indexOf(source.accounts[role].address);
   if(modes[n]==='delayed'){
    const i=index('clock'),data=Buffer.from(values[i].data[0],'base64');data.writeBigInt64LE(BigInt(delayedClock),32);values[i].data[0]=data.toString('base64');await new Promise(resolve=>setTimeout(resolve,800));
   }
   if(['stale','future'].includes(modes[n])){
    const i=index('clock'),data=Buffer.from(values[i].data[0],'base64');data.writeBigInt64LE(BigInt(Math.floor(Date.now()/1000)+(modes[n]==='future'?60:-901)),32);values[i].data[0]=data.toString('base64');
   }
   if(modes[n]==='partial')values.pop();
   if(modes[n]==='wrong-owner')values[1].owner=source.accounts.usdc.owner;
   res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({jsonrpc:'2.0',id:1,result:{context:{slot:Number(source.context_slot)},value:values}}));
  }catch(e){failures.push(String(e));res.writeHead(500).end();}
 }));
 try{
  for(const server of servers){server.listen(0,'127.0.0.1');await once(server,'listening');}
  const endpoints=servers.map(s=>`http://127.0.0.1:${s.address().port}`);
  let config=configuration(selected,endpoints);
  const invoke=async(value=config,extra=[])=>{
   const file=path.join(work,'configuration.json');fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value));
   const child=spawn(binary,['bonds','--log',selected.log_name,'--v2-config',file,...extra],{env:{...process.env,MESSENGER_SECURITY_CONFIG:'',MORSE_BOND_MINT:''}});
   let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
   const timer=setTimeout(()=>child.kill('SIGKILL'),20000);
   try{const[code,signal]=await once(child,'exit');assert.equal(signal,null);
    cliTrace.push({case_index:cliTrace.length+1,pid:child.pid,binary,modes:[...modes],snapshot:selected.name,configuration_sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex'),code,stdout,stderr});
    if(process.env.MORSE_BONDS_V2_EVIDENCE){fs.mkdirSync(process.env.MORSE_BONDS_V2_EVIDENCE,{recursive:true});fs.writeFileSync(path.join(process.env.MORSE_BONDS_V2_EVIDENCE,'cli-trace.json'),JSON.stringify(cliTrace,null,2)+'\n');}
    return{code,stdout,stderr};}finally{clearTimeout(timer);}
  };
  const refuse=async(pattern,value=config)=>{const result=await invoke(value);assert.equal(result.code,1,result.stdout+result.stderr);assert.equal(result.stdout,'');assert.match(result.stderr,pattern);};
  let result=await invoke();assert.equal(result.code,0,result.stderr);let report=JSON.parse(result.stdout);
  assert.equal(report.mode,'v2');assert.equal(report.bond_layout,'MBD2-only');assert.equal(report.provider_independence,'not-established');assert.equal(report.valuation.availability,'unavailable');assert.equal(report.rows.length,3);
  const morse=report.rows.find(x=>x.asset==='MORSE');assert.equal(morse.principal_units,'50000000');assert.equal(morse.pending_liability_units,'0');assert.equal(morse.donation_surplus_units,'17');assert(report.rows.filter(x=>x.asset==='USDC').every(x=>x.mint===config.pins.usdc));
  modes=['outage','good','good'];assert.equal((await invoke()).code,0);
  modes=['other','good','outage'];await refuse(/bonds_v2_rpc_disagreed/);
  for(const mode of ['future','stale','partial','wrong-owner']){modes=[mode,mode,'good'];await refuse(/bonds_v2_(future_clock|stale_clock|rpc_unavailable)/);}
  modes=['delayed','delayed','delayed'];delayedClock=Math.floor(Date.now()/1000);await refuse(/bonds_v2_stale_clock/,{...config,max_age_seconds:'1'});
  modes=['good','good','good'];await refuse(/bonds_v2_release_mismatch/,{...config,collateral:{...config.collateral,judge_slot:(BigInt(config.collateral.judge_slot)+1n).toString()}});
  const before=requests;
  for(const bad of [{...config,schema_version:0},{...config,legacy_collateral:{}},{...config,collateral:undefined},{...config,endpoints:[endpoints[0],endpoints[0],endpoints[2]]},{...config,max_age_seconds:'0'},{...config,max_age_seconds:'86401'},{...config,minimum_context_slot:'01'},{...config,collateral:{...config.collateral,log_name:'other-log'}},{...config,collateral:{...config.collateral,morse_mint:config.pins.usdc}},' '.repeat(32769)])await refuse(/./,bad);
  assert.equal(requests,before,'invalid explicit configuration must not perform RPC');
  selected=find('v2-context-legacy-rows');config=configuration(selected,endpoints);await refuse(/bonds_v2_requires_MBD2/);
  selected=find('legacy-v1');config=configuration(selected,endpoints);await refuse(/bonds_v2_rpc_unavailable/);
  selected=find('fresh-pending-mixed');config=configuration(selected,endpoints);result=await invoke();assert.equal(result.code,0,result.stderr);report=JSON.parse(result.stdout);const pending=report.rows.find(x=>x.asset==='MORSE');assert.equal(pending.principal_units,'50000000');assert.equal(pending.pending_recorded_units,'1');assert.equal(pending.pending_liability_units,'1');assert.equal(pending.vault_balance_units,'50000018');assert.equal(pending.donation_surplus_units,'17');
  if(process.env.MORSE_BONDS_V2_HISTORY){
   const historical=JSON.parse(fs.readFileSync(process.env.MORSE_BONDS_V2_HISTORY));selected=historical.snapshots.find(x=>x.name==='token-active');config=configuration(selected,endpoints);await refuse(/bonds_v2_stale_clock/);
  }
  assert.deepEqual(failures,[]);
  if(process.env.MORSE_BONDS_V2_EVIDENCE){fs.mkdirSync(process.env.MORSE_BONDS_V2_EVIDENCE,{recursive:true});fs.writeFileSync(path.join(process.env.MORSE_BONDS_V2_EVIDENCE,'pending-report.json'),JSON.stringify(report,null,2)+'\n');fs.writeFileSync(path.join(process.env.MORSE_BONDS_V2_EVIDENCE,'result.json'),JSON.stringify({status:'passed',requests,scope:'Actual owned SBF snapshots replayed; no new chain execution by CLI, no live release or provider independence.'},null,2)+'\n');}
 }finally{for(const server of servers){server.closeAllConnections();await new Promise(r=>server.close(r));}fs.rmSync(work,{recursive:true,force:true});}
});
