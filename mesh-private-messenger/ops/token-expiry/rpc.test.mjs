import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
const product=path.resolve(import.meta.dirname,'../..'),publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const meshc=process.env.MESHC||path.join(publicRoot,'target/debug/meshc');
const {parseJsonWithBigInts,stringifyJsonWithBigInts}=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/rpc-spec-types');
const execute=(binary,env)=>new Promise((resolve,reject)=>{const child=spawn(binary,[],{env,cwd:product});let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));});
test('compiled Mesh expiry bank uses pinned finalized RPC, exact pair quorum and strict absence without any sends',{timeout:180000},async()=>{
 const work=await fs.mkdtemp(path.join(os.tmpdir(),'morse-expiry-rpc-')),servers=[];
 let mode='expired',sends=0,requests=0,redirects=0;
 try{
  const fixture=process.env.MORSE_TOKEN_EXPIRY_FIXTURES_PATH||path.join(product,'ops/token-expiry/fixtures/tombstone.json');
  const root=JSON.parse(await fs.readFile(fixture,'utf8')),keys=root.accounts.map(a=>a.address);
  await fs.writeFile(path.join(work,'mesh.toml'),`[package]\nname="expiry-rpc-proof"\nversion="0.1.0"\n[dependencies]\ncredit-issuer={path=${JSON.stringify(path.join(product,'services/credit-issuer'))}}\n`);
  await fs.copyFile(path.join(import.meta.dirname,'rpc-client.mpl.fixture'),path.join(work,'main.mpl'));
  const binary=path.join(work,'client'),built=spawnSync(meshc,['build',work,'-o',binary],{cwd:product,encoding:'utf8'});assert.equal(built.status,0,built.stdout+built.stderr);
  for(let index=0;index<2;index++){
   const server=http.createServer(async(req,res)=>{try{
    requests++;if(req.url==='/forbidden'){redirects++;throw Error('redirect followed');}
    let text='';for await(const b of req){text+=b;assert.ok(text.length<=16384);}
    const query=parseJsonWithBigInts(text);assert.equal(query.jsonrpc,'2.0');
    if(query.method==='sendTransaction'){sends++;throw Error('expiry reader must never broadcast');}
    if(mode==='redirect'){res.writeHead(302,{location:'/forbidden'});res.end();return;}
    if(mode==='oversized'&&query.method==='getMultipleAccounts'){res.writeHead(200);res.end('x'.repeat(65537));return;}
    if(mode==='unavailable'&&index===1){res.writeHead(503);res.end();return;}
    let result;
    if(query.method==='getGenesisHash')result=mode==='wrong_genesis'?'11111111111111111111111111111111':root.program;
    else{
     assert.equal(query.method,'getMultipleAccounts');assert.deepEqual(query.params[0],keys);assert.equal(query.params[1].commitment,'finalized');assert.deepEqual(query.params[1].dataSlice,{offset:0n,length:320n});
     const rows=root.accounts.map(a=>({owner:a.owner,lamports:BigInt(a.lamports),space:BigInt(a.space),executable:a.executable,rentEpoch:0n,data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64']}));
     let slot=BigInt(root.context_slot);
     const patch=(at,mutate)=>{const b=Buffer.from(rows[at].data[0],'base64');mutate(b);rows[at].data=[b.toString('base64'),'base64'];};
     if(mode==='absent'||mode==='prefunded'){rows[5]=null;rows[6]=null;if(mode==='prefunded')for(const at of [5,6])rows[at]={owner:'11111111111111111111111111111111',lamports:77n,space:0n,executable:false,rentEpoch:0n,data:['','base64']};}
     if(mode==='missing_pair')rows[6]=null;
     if(mode==='wrong_owner')rows[5].owner='11111111111111111111111111111111';
     if(mode==='wrong_epoch')patch(5,b=>b.writeBigUInt64LE(b.readBigUInt64LE(132)+1n,132));
     if(mode==='wrong_release')patch(8,b=>b.writeBigUInt64LE(1n,4));
     if(mode==='disagree'&&index===1)patch(8,b=>{b[13]^=1;});
     if(mode==='progression'&&index===1){slot++;patch(4,b=>{b.writeBigUInt64LE(slot,0);b.writeBigInt64LE(b.readBigInt64LE(32)+1n,32);});}
     if(mode==='large_slot'){slot=9007199254740993n;patch(4,b=>b.writeBigUInt64LE(slot,0));}
     if(mode==='fractional_slot')slot=100.5;
     if(mode==='future_receipt'){
      const b=Buffer.from(rows[5].data[0],'base64'),r=Buffer.from(rows[6].data[0],'base64'),time=b.readBigUInt64LE(148);
      b.writeBigUInt64LE(time+2n,148);r.writeBigUInt64LE(time+2n,180);createHash('sha256').update(b).digest().copy(r,220);
      rows[5].data=[b.toString('base64'),'base64'];rows[6].data=[r.toString('base64'),'base64'];patch(4,b=>b.writeBigUInt64LE(time+1n,32));
     }
     result={context:{slot},value:rows};
    }
    res.writeHead(200,{'content-type':'application/json'});res.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:mode==='wrong_id'?query.id+1n:query.id,result}));
   }catch(error){res.writeHead(500);res.end(String(error));}});
   await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
  }
  const urls=servers.map(s=>`http://127.0.0.1:${s.address().port}/rpc`),env={...process.env,BURN_EXPIRY_FIXTURE:fixture,BURN_EXPIRY_URLS:urls.join(',')};delete env.CARGO_TARGET_DIR;
  const cases=[];
  for(const name of ['expired','absent','prefunded','progression','large_slot']){mode=name;const result=await execute(binary,env);assert.equal(result.code,0,name+': '+result.stdout+result.stderr);assert.match(result.stdout,name==='absent'||name==='prefunded'?/^absent:/:/^expired:/);if(name==='large_slot')assert.match(result.stdout,/:9007199254740993\s*$/);cases.push(name);}
  for(const name of ['wrong_id','wrong_genesis','missing_pair','wrong_owner','wrong_epoch','wrong_release','disagree','fractional_slot','future_receipt','redirect','oversized','unavailable']){mode=name;const result=await execute(binary,env);assert.notEqual(result.code,0,name+' accepted: '+result.stdout);cases.push(name);}
  mode='expired';for(const extra of [{BURN_EXPIRY_URLS:[urls[0],urls[0]].join(',')},{BURN_EXPIRY_TEST_MODE:'0'}]){const result=await execute(binary,{...env,...extra});assert.notEqual(result.code,0,'invalid provider configuration accepted');}
  assert.equal(sends,0);assert.equal(redirects,0);assert.ok(requests>0);
  console.log('MORSE_TOKEN_EXPIRY_RPC '+JSON.stringify({passed:true,actual_compiled_mesh:true,cases:cases.length+2,finalized_only:true,retained_actual_sbf_frames:true,broadcasts:0,live_chain:false}));
 }finally{for(const s of servers)await new Promise(resolve=>s.close(resolve));await fs.rm(work,{recursive:true,force:true});}
});
