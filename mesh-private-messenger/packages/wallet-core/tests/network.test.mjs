// Local only: real Rust signer, actual Mesh durable journal/RPC client and
// real System/SPL/ATA SBF programs. No live provider, key or funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {createHmac,createPrivateKey,sign} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
const product=path.resolve(import.meta.dirname,'../../..');
const publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const sdkBridge=process.env.WALLET_FIXTURE_BRIDGE||path.join(product,'packages/wallet-core/target/debug/examples/wallet_fixture_bridge');
const oracle=process.env.WALLET_PAYMENT_ORACLE||path.join(product,'programs/target/debug/examples/credit_payment_fixture');
const kit=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/kit');
const address=bytes=>kit.getAddressDecoder().decode(bytes);
const run=(cmd,args=[],opts={})=>new Promise((resolve,reject)=>{const child=spawn(cmd,args,opts);let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));});
const sync=(cmd,value)=>{const child=spawnSync(cmd,[],{input:JSON.stringify(value),encoding:'utf8'});assert.equal(child.status,0,child.stderr);return JSON.parse(child.stdout);};
const signer=()=>{let value=createHmac('sha512','ed25519 seed').update(Buffer.alloc(32,1)).digest();for(const index of [44,501,0,0]){const child=Buffer.alloc(37);value.copy(child,1,0,32);child.writeUInt32BE(index+0x80000000,33);value=createHmac('sha512',value.subarray(32)).update(child).digest();}return createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),value.subarray(0,32)]),format:'der',type:'pkcs8'});};
const mutate=(wire,offset)=>{const changed=Buffer.from(wire);changed[offset]^=1;changed.set(sign(null,changed.subarray(65),signer()),1);return changed;};
test('native wallet journals before send and replays one exact payment across ambiguity/restart',{timeout:180000},async()=>{
 const temporary=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'morse-wallet-network-')));const project=path.join(temporary,'network-proof');await fs.mkdir(project);
 const payerHex=sync(sdkBridge,{}).address_hex;
 const servers=[];let preparingCall;let height=100,hashTag=4,heights=0;let mode='wrong-id',latest=0,sends=0,executions=0,seenWire,caseData,ack=false;
 try{
  await fs.writeFile(path.join(project,'mesh.toml'),`[package]\nname="network-proof"\nversion="0.1.0"\n[dependencies]\nmobile={path=${JSON.stringify(path.join(product,'packages/mobile-core'))}}\n`);
  await fs.copyFile(path.join(product,'packages/wallet-core/tests/network.mpl.fixture'),path.join(project,'main.mpl'));await fs.mkdir(path.join(project,'payment'));await fs.copyFile(path.join(product,'services/credit-issuer/payment/verify.mpl'),path.join(project,'payment/verify.mpl'));
  const built=await run(process.env.MESHC||path.join(publicRoot,'target/debug/meshc'),['build',project,'--opt-level',process.env.WALLET_NETWORK_OPT_LEVEL||'2']);assert.equal(built.code,0,built.stdout+built.stderr);
  for(let index=0;index<3;index++){
   const server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;const request=JSON.parse(body);res.setHeader('content-type','application/json');res.setHeader('connection','close');
    if(request.method==='getBlockHeight'){heights++;assert.equal(request.id,43);assert.deepEqual(request.params,[{commitment:'confirmed'}]);return res.end(JSON.stringify({jsonrpc:'2.0',id:43,result:height}));}
    if(request.method==='getTransaction'){assert.equal(request.id,41);assert.equal(request.params[0],kit.getBase58Decoder().decode(Buffer.from(seenWire,'hex').subarray(1,65)));return res.end(caseData.response);}
    if(request.method==='getLatestBlockhash'){
     latest++;if(preparingCall)assert.equal((await preparingCall('recover')).status,0,'intent must be durable before first provider call');assert.equal(request.id,41);assert.deepEqual(request.params,[{commitment:'confirmed'}]);
     const result={context:{slot:100000},value:{blockhash:address(Buffer.alloc(32,hashTag)),lastValidBlockHeight:hashTag===4?123:223}};
     return res.end(JSON.stringify({jsonrpc:'2.0',id:mode==='wrong-id'?99:41,result},(_k,v)=>typeof v==='bigint'?v.toString():v).replace('"9007199254740993"','9007199254740993'));
    }
    assert.equal(request.method,'sendTransaction');assert.equal(request.id,42);sends++;
    assert.deepEqual(request.params[1],{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:0,minContextSlot:100000});
    const wire=Buffer.from(request.params[0],'base64');assert.equal(wire.toString('base64'),request.params[0]);assert.equal(wire.toString('hex'),seenWire,'retry changed exact signed packet');
    if(!caseData.executed){
     // Commit and issuance signature must be durable BEFORE the RPC server sees
     // a single packet. This starts another OS process reading the same DB/key.
     const recovered=await caseData.call('recover');assert.equal(recovered.status,2);assert.equal(recovered.wire_hex,seenWire);
     const purchase=await caseData.call('purchase');assert.equal(purchase.stage,2);assert.ok(purchase.issue_hex.includes(wire.subarray(1,65).toString('hex')));
     const fixture={version:'legacy',asset:caseData.asset,payer:caseData.payer,mint:caseData.mint,source:caseData.source,destination:caseData.destination,deposit:caseData.deposit,wire_hex:seenWire};
     const executed=sync(oracle,{fixture,block_time:caseData.now,replay_count:3});assert.equal(executed.replay_rejections,3);executions++;
     caseData.response=executed.response.replace(/"data_hex":"([0-9a-f]*)"/g,(_all,hex)=>'"data":'+JSON.stringify(kit.getBase58Decoder().decode(Buffer.from(hex,'hex'))));caseData.executed=true;
     // The chain executed the payment, but the caller never receives an ack.
     req.socket.destroy();return;
    }
    if(ack)return res.end(JSON.stringify({jsonrpc:'2.0',id:42,result:kit.getBase58Decoder().decode(wire.subarray(1,65))}));
    if(index===1)return res.end(JSON.stringify({jsonrpc:'2.0',id:43,result:kit.getBase58Decoder().decode(wire.subarray(1,65))}));
    return res.end(JSON.stringify({jsonrpc:'2.0',id:42,result:kit.getBase58Decoder().decode(Buffer.alloc(64,88))}));
   });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
  }
  const endpoints=servers.map(s=>`http://127.0.0.1:${s.address().port}`);
  let malformedRejected=0,expiredRejected=0;
  for(const asset of [1,0]){
   const storage=path.join(temporary,`key-${asset}`);await fs.mkdir(storage,{mode:0o700});const database=path.join(temporary,`wallet-${asset}.db`);const now=Math.floor(Date.now()/1000);height=100;hashTag=4;
   let purchaseID;const invoke=async(action,extra={})=>{const result=await run(path.join(project,'network-proof'),[],{env:{...process.env,WALLET_STORAGE:storage,WALLET_ISSUER:path.join(temporary,`issuer-${asset}.sealed`),WALLET_DATABASE:database,WALLET_ACTION:action,WALLET_ASSET:String(asset),WALLET_NOW:String(now),WALLET_PURCHASE:purchaseID||'',WALLET_PAYER:payerHex,WALLET_ENDPOINTS:endpoints.join(','),...extra}});assert.equal(result.code,0,result.stdout+result.stderr);return JSON.parse(result.stdout);};
   const call=async(action,extra)=>{const result=await invoke(action,extra);assert.equal(result.error,undefined,JSON.stringify(result));return result;};
   const boot=await call('bootstrap');purchaseID=boot.purchase_id_hex;
   preparingCall=call;mode='wrong-id';const failed=await invoke('prepare');assert.equal(failed.error,'wallet_rpc_unavailable');assert.equal((await call('recover')).status,0);assert.equal(sends,asset===1?0:10);
   mode='good';let prepared=await call('prepare');assert.equal(prepared.status,1);assert.equal(prepared.blockhash_hex,Buffer.alloc(32,4).toString('hex'));
   preparingCall=undefined;let beforeLatest=latest;assert.deepEqual(await call('prepare'),prepared);assert.equal(latest,beforeLatest,'live unsigned hash should be reused');
   const oldPrompt=sync(sdkBridge,{quote_hex:boot.quote_hex,blockhash_hex:prepared.blockhash_hex});
   height=124;hashTag=6;const refreshed=await call('prepare');assert.equal(refreshed.blockhash_hex,Buffer.alloc(32,6).toString('hex'),'expired unsigned hash must refresh');assert.equal(refreshed.status,1);
   assert.ok((await invoke('commit',{WALLET_WIRE:oldPrompt.wire_hex})).error,'stale prompt cannot commit after hash refresh');
   beforeLatest=latest;prepared=refreshed;
   assert.equal((await invoke('prepare',{WALLET_PAYER:Buffer.alloc(32,91).toString('hex')})).error,'wallet_payment_payer_changed');
   const signed=sync(sdkBridge,{quote_hex:boot.quote_hex,blockhash_hex:prepared.blockhash_hex});const wire=Buffer.from(signed.wire_hex,'hex');seenWire=signed.wire_hex;
   // Authenticate signed invalid input, not only damaged signatures. Changes
   // to amount/ref/destination/program/hash all retain a valid Ed25519 signer.
   const quote=Buffer.from(boot.quote_hex,'hex');const reference=quote.subarray(4,36),destination=quote.subarray(68,100),hash=Buffer.from(prepared.blockhash_hex,'hex');
   for(const offset of [wire.length-1,wire.indexOf(reference,65),wire.indexOf(destination,65),wire.indexOf(hash,65)]){
    assert.ok(offset>=65);const bad=mutate(wire,offset);assert.ok((await invoke('commit',{WALLET_WIRE:bad.toString('hex')})).error);malformedRejected++;
   }
   assert.equal((await invoke('commit',{WALLET_WIRE:seenWire,WALLET_NOW:String(now+900)})).error,'invalid_payment_quote');expiredRejected++;
   const foreign=sync(sdkBridge,{seed_tag:2,quote_hex:boot.quote_hex,blockhash_hex:prepared.blockhash_hex});assert.equal((await invoke('commit',{WALLET_WIRE:foreign.wire_hex})).error,'wallet_payment_payer_changed');
   height=224;assert.equal((await invoke('commit',{WALLET_WIRE:seenWire})).error,'wallet_payment_blockhash_expired','prompt must not commit a dead blockhash');height=124;
   const competing=await Promise.all(Array.from({length:4},()=>invoke('commit',{WALLET_WIRE:seenWire})));assert.ok(competing.some(value=>value.status===2));for(const value of competing)if(value.error)assert.ok(['credit_wallet_changed','wallet_payment_changed'].includes(value.error),value.error);
   const committed=await call('recover');assert.equal(committed.status,2);const signedHeightReads=heights;const signedLatestReads=latest;assert.deepEqual(await call('prepare'),committed);assert.equal(heights,signedHeightReads);assert.equal(latest,signedLatestReads);assert.equal(committed.wire_hex,seenWire);
   assert.deepEqual(await call('commit',{WALLET_WIRE:seenWire,WALLET_NOW:String(now+1000)}),committed,'exact committed replay survives expiry');
   const different=sync(sdkBridge,{quote_hex:boot.quote_hex,blockhash_hex:Buffer.alloc(32,5).toString('hex')});assert.equal((await invoke('commit',{WALLET_WIRE:different.wire_hex})).error,'wallet_payment_packet_changed');
   const payer=address(Buffer.from(signed.address_hex,'hex')),mint=address(Buffer.alloc(32,7)),deposit=address(quote.subarray(36,68)),dest=address(destination);const token=kit.address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');const source=asset===1?payer:(await kit.getProgramDerivedAddress({programAddress:kit.address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'),seeds:[kit.getAddressEncoder().encode(payer),kit.getAddressEncoder().encode(token),kit.getAddressEncoder().encode(mint)]}))[0];
   caseData={asset,payer,mint,deposit,destination:dest,source,now,call,executed:false};ack=false;
   const ambiguous=await call('submit');assert.equal(ambiguous.status,2);assert.equal(ambiguous.wire_hex,seenWire);assert.equal((await call('recover')).signature_hex,wire.subarray(1,65).toString('hex'));
   // Restart after an executed-but-timeout send: exact saved packet only, no
   // blockhash/RNG/signing callback. Expired quote cannot trigger a second pay.
   const retries=await Promise.all([call('submit'),call('submit')]);for(const retry of retries){assert.equal(retry.status,2);assert.equal(retry.wire_hex,seenWire);}
   const beforeExpired=sends;const expired=await call('submit',{WALLET_NOW:String(now+1000)});assert.equal(expired.status,2);assert.equal(sends,beforeExpired,'expired recovery must not cause a first late payment');
   ack=true;const recovered=await call('submit');assert.equal(recovered.status,3);assert.equal(recovered.wire_hex,seenWire);assert.equal(latest,beforeLatest);const ackHeights=heights;const ackLatest=latest;height=999;hashTag=7;assert.deepEqual(await call('prepare'),recovered);assert.equal(heights,ackHeights);assert.equal(latest,ackLatest);
   const afterExpiry=await call('finalize',{WALLET_NOW:String(now+1000)});assert.deepEqual(afterExpiry,{stage:3,tokens:100});assert.equal(sends,beforeExpired+1,'issuer recovery must not send another payment');
  }
  assert.equal(executions,2);assert.equal(sends,20);
  const report={schema_version:1,passed:true,local_only:true,opt_level:Number(process.env.WALLET_NETWORK_OPT_LEVEL||2),assets:['SOL','USDC'],actual_sbf_payments:executions,svm_duplicate_rejections:6,ambiguous_submissions:2,exact_packet_network_attempts:sends,restarted_processes:true,expired_unsigned_rejections:expiredRejected,authenticated_malformed_packets_rejected:malformedRejected,wrong_rpc_id_rejected:true,wrong_returned_signature_rejected:true,journal_and_issue_signature_before_send:true,new_signature_after_uncertainty:false,expired_recovery_broadcasts:0,post_expiry_finalized_tokens:200,concurrent_committers:8,concurrent_ambiguous_retries:4,payer_substitution_rejected:true,unsigned_hash_refreshes:2,stale_prompt_commits_rejected:2,signed_hash_refreshes:0,expired_blockhash_commit_rejections:2};
  if(process.env.WALLET_NETWORK_REPORT)await fs.writeFile(process.env.WALLET_NETWORK_REPORT,JSON.stringify(report,null,2)+'\n');console.log('WALLET_NETWORK_JSON='+JSON.stringify(report));
 }finally{for(const server of servers)await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}
});
