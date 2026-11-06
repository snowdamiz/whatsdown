import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
const product = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const proof = process.env.MORSE_PROOF_DIR || path.resolve(product, '../.morse/witness-proof');
const fixturePath = process.env.MORSE_TOKEN_CARRY_FIXTURES_PATH || path.join(proof,'token-carry-fixtures.json');
const compiler = process.env.MESHC || path.join(process.env.MESH_LANG_ROOT || path.resolve(product,'../mesh-lang'),'target/debug/meshc');
function base58(bytes) {
  let value = BigInt('0x'+bytes.toString('hex')); let out='';
  const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  while(value){out=alphabet[Number(value%58n)]+out;value/=58n;}
  for(const byte of bytes){if(byte)break;out='1'+out;}
  return out;
}
test('actual SBF carry accounts through strict loopback RPC and sealed exact-packet restart', { timeout:180000 }, async () => {
  const fixture=JSON.parse(fs.readFileSync(fixturePath,'utf8')).snapshots.find(a=>a.name==='legacy-closed');
  const keys=fixture.accounts.map(a=>a.address);
  const accounts=fixture.accounts.map(a=>a.missing ? null : ({ owner:a.owner,executable:a.executable,lamports:Number(a.lamports),rentEpoch:0,space:Number(a.space),data:[Buffer.from(a.data_hex,'hex').toString('base64'),'base64'] }));
  const seen=new Map(), problems=[]; let retries=0, redirects=0, sends=0, packet;
  const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'morse-carry-rpc-')));
  fs.mkdirSync(path.join(directory,'key'),{mode:0o700});
  const server=http.createServer(async (request,response)=>{
    try {
      assert.equal(request.method,'POST');let body='';for await(const part of request){body+=part;assert(body.length<16384);}
      const rpc=JSON.parse(body);assert.equal(rpc.jsonrpc,'2.0');
      seen.set(request.url,(seen.get(request.url)||0)+1);
      if(request.url==='/must-not-send')throw new Error('expired packet was broadcast');
      if(request.url.startsWith('/send-')){
        assert.equal(rpc.id,2);assert.equal(rpc.method,'sendTransaction');
        assert.deepEqual(rpc.params[1],{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:0,minContextSlot:Number(fixture.context_slot)});
        if(packet)assert.equal(rpc.params[0],packet);else packet=rpc.params[0];sends++;
        const bytes=Buffer.from(packet,'base64');assert.equal(bytes[0],2);
        if(request.url==='/send-ambiguous'){response.writeHead(503).end('ambiguous');return;}
        response.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({jsonrpc:'2.0',id:request.url==='/send-wrong-id'?3:2,result:request.url==='/send-wrong-signature'?base58(Buffer.alloc(64,1)):base58(bytes.subarray(1,65))}));return;
      }
      assert.equal(rpc.id,1);assert.equal(rpc.method,'getMultipleAccounts');assert.deepEqual(rpc.params[0],keys);
      assert.deepEqual(rpc.params[1],{commitment:'finalized',encoding:'base64',minContextSlot:Number(fixture.context_slot),dataSlice:{offset:0,length:2240}});
      if(request.url==='/redirect-target'){redirects++;throw new Error('redirect followed');}
      if(request.url==='/redirect'){response.writeHead(307,{location:'/redirect-target'}).end();return;}
      if(request.url==='/oversized'){response.writeHead(200).end('x'.repeat(131073));return;}
      if(request.url==='/retry'&&++retries===1){response.writeHead(503).end('retry');return;}
      const result={context:{slot:Number(fixture.context_slot)},value:structuredClone(accounts)};
      const output={jsonrpc:'2.0',id:request.url==='/wrong-id'?2:1,result};
      const change=(index,fn)=>{const bytes=Buffer.from(result.value[index].data[0],'base64');fn(bytes);result.value[index].data[0]=bytes.toString('base64');};
      if(request.url==='/failure'){delete output.result;output.error={code:-32004,message:'missing'};}
      if(request.url==='/stale')result.context.slot--;
      if(request.url==='/numeric-string')result.context.slot=fixture.context_slot;
      if(request.url.startsWith('/wrong-owner'))result.value[2].owner=fixture.payer;
      if(request.url==='/reordered')[result.value[2],result.value[3]]=[result.value[3],result.value[2]];
      if(request.url==='/missing')result.value[9]=null;
      if(request.url==='/bad-receipt')change(9,b=>b[212]^=1);
      if(request.url==='/bad-carry')change(7,b=>b.writeBigUInt64LE(1n,100));
      if(request.url==='/insufficient-carry')change(8,b=>b.writeBigUInt64LE(1n,64));
      if(request.url==='/bad-mint')change(1,b=>b.writeUInt32LE(1,0));
      if(request.url==='/wrong-space')result.value[5].space++;
      if(request.url==='/truncated')result.value[5].data[0]=Buffer.from(result.value[5].data[0],'base64').subarray(0,100).toString('base64');
      if(request.url.startsWith('/donation-'))change(8,b=>b.writeBigUInt64LE(request.url.endsWith('a')?230000020n:230000021n,64));
      if(request.url.startsWith('/upgrade-'))change(11,b=>b.writeBigUInt64LE(1n,4));
      response.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify(output));
    }catch(error){problems.push(error.stack);response.writeHead(500).end('fixture error');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const run=(file,stage)=>new Promise((resolve,reject)=>{
    const env={...process.env,MORSE_TOKEN_CARRY_FIXTURES_PATH:fixturePath,MORSE_TOKEN_CARRY_RPC:`http://127.0.0.1:${server.address().port}`,MORSE_TOKEN_CARRY_JOURNAL_PATH:path.join(directory,'journal.sqlite'),MORSE_TOKEN_CARRY_JOURNAL_KEY:path.join(directory,'key'),MORSE_TOKEN_CARRY_JOURNAL_STAGE:stage};delete env.CARGO_TARGET_DIR;
    const child=spawn(compiler,['test',file],{cwd:product,env,stdio:['ignore','pipe','pipe']});let log='';child.stdout.on('data',d=>log+=d);child.stderr.on('data',d=>log+=d);child.on('error',reject);child.on('close',code=>resolve({code,log}));
  });
  try {
    for(const [file,stage] of [['ops/token-v2/burn_carry_rpc.test.mpl','write'],['ops/token-v2/burn_carry_journal.test.mpl','write'],['ops/token-v2/burn_carry_journal.test.mpl','restart']]){
      const r=await run(file,stage);process.stdout.write(r.log);assert.equal(r.code,0,r.log);
    }
    assert.equal(redirects,0);assert.equal(sends,4);assert.equal(seen.get('/must-not-send'),undefined);assert.deepEqual(problems,[]);
    assert.equal(retries,2);assert(seen.size>=30);console.log(`MORSE_TOKEN_CARRY_TRANSPORT ${seen.size} endpoint cases; exact packet after ambiguous response and sealed process restart`);
  }finally{await new Promise(resolve=>server.close(resolve));fs.rmSync(directory,{recursive:true,force:true});}
});
