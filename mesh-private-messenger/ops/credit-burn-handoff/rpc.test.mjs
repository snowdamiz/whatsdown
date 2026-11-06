import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const PRODUCT=path.resolve(HERE,'../..');
const PUBLIC=process.env.MESH_LANG_ROOT||path.resolve(PRODUCT,'../mesh-lang');
const MESHC=process.env.MESHC||path.join(PUBLIC,'target/debug/meshc');
async function run(executable,args,env={}) {
 return new Promise((resolve,reject)=>{const child=spawn(executable,args,{cwd:PRODUCT,env:{...process.env,...env},stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.once('error',reject);child.once('close',code=>code===0?resolve(output):reject(new Error(`${executable} exit${code}\n${output}`)));});
}
function rpcAccount(a){if(a.missing)return null;return {owner:a.owner,lamports:Number(a.lamports),space:Number(a.space),executable:a.executable,rentEpoch:0,data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64']};}
const clone=value=>JSON.parse(JSON.stringify(value));
test('pinned burn RPC uses finalized canonical banks and never sends a transaction',{timeout:240000},async()=>{
 const work=await fs.mkdtemp(path.join(os.tmpdir(),'morse-burn-rpc-'));
 const ready=JSON.parse(await fs.readFile(path.join(HERE,'fixtures/ready-accounts.json'),'utf8'));
 const carry=JSON.parse(await fs.readFile(path.join(HERE,'fixtures/carry-accounts.json'),'utf8'));
 const servers=[];const calls=[];let selected;
 try{
  await fs.writeFile(path.join(work,'mesh.toml'),`[package]\nname="credit-burn-rpc-proof"\nversion="0.1.0"\n[dependencies]\ncredit-issuer={path=${JSON.stringify(path.join(PRODUCT,'services/credit-issuer'))}}\n`);
  await fs.copyFile(path.join(HERE,'rpc-client.mpl.fixture'),path.join(work,'main.mpl'));
  const binary=path.join(work,'client');
  await run(MESHC,['build',work,'-o',binary]);
  for(let index=0;index<2;index++){
   const server=http.createServer(async(req,res)=>{try{let body='';for await(const b of req)body+=b;const query=JSON.parse(body);calls.push({index,query});assert.notEqual(query.method,'sendTransaction');let result;
    if(query.method==='getGenesisHash')result=selected.wrongGenesis&&index===0?'11111111111111111111111111111111':ready.program;
    else{
     assert.equal(query.method,'getMultipleAccounts');assert.equal(query.params[1].commitment,'finalized');assert.equal(query.params[1].dataSlice.offset,0);
     const funding=selected.operation==='funding';assert.equal(query.params[0].length,funding?12:22);assert.equal(query.params[1].dataSlice.length,funding?2240:5728);
     let snapshot=funding?carry.snapshots[index===1&&selected.closed?4:2]:ready;
     assert.deepEqual(query.params[0],snapshot.accounts.map(a=>a.address));
     let accounts=clone(snapshot.accounts);
     if(selected.badOwner&&index===0)accounts[funding?5:21].owner='11111111111111111111111111111111';
     if(selected.disagree&&index===1){let b=Buffer.from(accounts[21].data_hex,'hex');b.writeBigUInt64LE(b.readBigUInt64LE(64)+1n,64);accounts[21].data_hex=b.toString('hex');}
     if(selected.donation&&index===1){let b=Buffer.from(accounts[20].data_hex,'hex');b.writeBigUInt64LE(b.readBigUInt64LE(64)+5000000n,64);accounts[20].data_hex=b.toString('hex');}
     if(selected.wrongFunding&&index===1){let b=Buffer.from(accounts[5].data_hex,'hex');b.fill(255,192,224);accounts[5].data_hex=b.toString('hex');}
     result={context:{slot:Number(snapshot.context_slot)},value:accounts.map(rpcAccount)};
    }
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:selected.wrongID&&index===0?query.id+1:query.id,result}));
   }catch(error){res.writeHead(500);res.end(String(error));}});
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
  }
  const urls=servers.map(s=>`http://127.0.0.1:${s.address().port}`);
  const scenarios=[{name:'ready',operation:'ready'},{name:'donation',operation:'ready',donation:true},{name:'wrong-id',operation:'ready',wrongID:true,error:true},{name:'wrong-genesis',operation:'ready',wrongGenesis:true,error:true},{name:'wrong-owner',operation:'ready',badOwner:true,error:true},{name:'different-source-balance',operation:'ready',disagree:true,error:true},{name:'active-and-closed',operation:'funding',closed:true},{name:'wrong-funding-hash',operation:'funding',wrongFunding:true,error:true},{name:'funding-owner',operation:'funding',badOwner:true,error:true},{name:'plain-http-production',operation:'ready',production:true,error:true},{name:'duplicate-provider',operation:'ready',duplicate:true,error:true}];
  for(const scenario of scenarios){selected=scenario;const output=await run(binary,[],{BURN_READY_FIXTURE:path.join(HERE,'fixtures/ready-accounts.json'),BURN_RPC_URLS:(scenario.duplicate?[urls[0],urls[0]]:urls).join(','),BURN_RPC_OPERATION:scenario.operation,BURN_EXPECT_ERROR:scenario.error?'1':'0',BURN_TEST_MODE:scenario.production?'0':'1'});assert.match(output,scenario.error?/MORSE_CREDIT_BURN_RPC_REJECT/:/MORSE_CREDIT_BURN_RPC_OK/);}
  assert.ok(calls.length>0);assert.equal(calls.filter(c=>c.query.method==='sendTransaction').length,0);
  console.log(`MORSE_CREDIT_BURN_RPC cases=${scenarios.length} actual_sbf_snapshots_loopback_only broadcasts=0`);
 }finally{for(const server of servers)await new Promise(resolve=>server.close(resolve));await fs.rm(work,{recursive:true,force:true});}
});
