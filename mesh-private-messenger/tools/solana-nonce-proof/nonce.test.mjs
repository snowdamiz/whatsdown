// Test-only public fixed keys; no network, deployment or live fund capability.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawn,spawnSync} from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import http from 'node:http';
const product=path.resolve(import.meta.dirname,'../..');
const publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const compiler=process.env.MESHC||path.join(publicRoot,'target/debug/meshc');
const binary=process.env.SOLANA_NONCE_ORACLE||path.join(product,'programs/target/debug/morse-solana-nonce-proof');
const kit=createRequire(path.join(product,'ops/rewards/package.json'))('@solana/kit');
const fixture=path.join(import.meta.dirname,'fixtures/client.mpl.fixture');
const run=(command,args,options={})=>new Promise((resolve,reject)=>{
  const child=spawn(command,args,options);let stdout='',stderr='';
  child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
  child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));
});
function bank(){
  const child=spawn(binary,[],{stdio:['pipe','pipe','pipe']});
  const pending=[];let errors='';
  child.stderr.on('data',chunk=>errors+=chunk);
  readline.createInterface({input:child.stdout}).on('line',line=>pending.shift()?.resolve(JSON.parse(line)));
  child.stdin.on('error',error=>{for(const value of pending.splice(0))value.reject(new Error(`${error.message}: ${errors}`));});
  child.on('error',error=>{for(const value of pending.splice(0))value.reject(error);});
  child.on('exit',code=>{for(const value of pending.splice(0))value.reject(new Error(`oracle exit ${code}: ${errors}`));});
  return {call:value=>new Promise((resolve,reject)=>{pending.push({resolve,reject});child.stdin.write(JSON.stringify(value)+'\n');}),close:()=>child.stdin.end()};
}
const keys=new Map([1,2,3,4].map(index=>{
  const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,index)]),format:'der',type:'pkcs8'});
  const address=kit.getAddressDecoder().decode(createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32));
  return [address,key];
}));
function alternatePacket(packet,amount){
  const bytes=Buffer.from(packet,'hex'),count=bytes[0];
  const decoded=kit.getCompiledTransactionMessageDecoder().decode(bytes.subarray(1+64*count));
  const data=Buffer.alloc(12);data.writeUInt32LE(2);data.writeBigUInt64LE(BigInt(amount),4);
  const instructions=decoded.instructions.map((ix,index)=>index===decoded.instructions.length-1?{...ix,data}:ix);
  return signed(Buffer.from(kit.getCompiledTransactionMessageEncoder().encode({...decoded,instructions})).toString('hex'));
}
function signed(messageHex){
  const message=Buffer.from(messageHex,'hex');
  const decoded=kit.getCompiledTransactionMessageDecoder().decode(message);
  const count=decoded.header.numSignerAccounts;assert.ok(count>0&&count<128);
  const signatures=decoded.staticAccounts.slice(0,count).map(address=>{assert.ok(keys.has(address),'unknown fixture signer');return sign(null,message,keys.get(address));});
  return Buffer.concat([Buffer.from([count]),...signatures,message]).toString('hex');
}
test('public Mesh nonce bytes match SDK and actual bank preserves at-most-once on success and failure',{timeout:120000},async()=>{
  const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'morse-nonce-proof-'));
  const local=bank();let server,response='',queried='',rpcCalls=0;
  try{
    server=http.createServer(async(request,res)=>{
      let body='';for await(const chunk of request)body+=chunk;
      const parsed=JSON.parse(body);assert.equal(parsed.id,41);assert.equal(parsed.method,'getTransaction');
      assert.equal(parsed.params[0],queried);assert.deepEqual(parsed.params[1],{encoding:'base64',commitment:'finalized',maxSupportedTransactionVersion:0});
      rpcCalls++;res.writeHead(200,{'content-type':'application/json','connection':'close'});res.end(response);
    });
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    const program=path.join(temporary,'nonce-client');await fs.mkdir(program);
    await fs.writeFile(path.join(program,'mesh.toml'),`[package]\nname="nonce-client"\nversion="0.1.0"\n[dependencies]\nmesh-solana={path=${JSON.stringify(path.join(publicRoot,'packages/mesh-solana'))}}\nmessenger-protocol={path=${JSON.stringify(path.join(product,'packages/messenger-protocol'))}}\n`);
    await fs.copyFile(fixture,path.join(program,'main.mpl'));
    for(const relative of ['payment/revenue_policy.mpl','payment/treasury.mpl','payment/treasury_outcome.mpl','payment/verify.mpl','payment/observation.mpl','storage/treasury.mpl','runtime/treasury_signing.mpl']){
      const target=path.join(program,relative);await fs.mkdir(path.dirname(target),{recursive:true});
      await fs.copyFile(path.join(product,'services/credit-issuer',relative),target);
    }
    for(const opt of ['0','2']){
      const executable=path.join(program,`client-${opt}`);
      const built=spawnSync(compiler,['build','--opt-level',opt,'-o',executable,program],{encoding:'utf8'});
      assert.equal(built.status,0,built.stdout+built.stderr);
      let state=await local.call({method:'expire'}), treasury=false, preparedState;
      async function reconcile(packet,result,badId=false){
        const input=path.join(program,'outcome.json');
        const signature=Buffer.from(packet,'hex').subarray(1,65);
        queried=kit.getBase58Decoder().decode(signature);
        response=badId?result.rpc_response.replace('"id":41','"id":42'):result.rpc_response;
        await fs.writeFile(input,JSON.stringify({mode:'outcome',signature_hex:signature.toString('hex'),wire_hex:packet,expected_success:result.ok,...(treasury?{...preparedState,treasury:true}:{})}));
        const checked=await run(executable,[],{env:{...process.env,NONCE_INPUT:input,NONCE_OUTCOME_RPC:`http://127.0.0.1:${server.address().port}`}});
        if(badId)assert.notEqual(checked.code,0,'mismatched outcome RPC id accepted');
        else{assert.equal(checked.code,0,checked.stdout+checked.stderr);assert.equal(checked.stdout,result.ok?'success\n':'failure\n');}
      }
      async function prepare(amount){
        const input=path.join(program,'input.json');await fs.writeFile(input,JSON.stringify({...state,amount,...(treasury?{mode:'treasury'}:{})}));
        const mesh=spawnSync(executable,[],{encoding:'utf8',env:{...process.env,NONCE_INPUT:input,NONCE_PAYER_SEED:'01'.repeat(32),NONCE_AUTHORITY_SEED:'02'.repeat(32),NONCE_SOURCE_SEED:'04'.repeat(32)}});
        assert.equal(mesh.status,0,mesh.stdout+mesh.stderr);
        preparedState={...state,amount};
        const prepared=JSON.parse(mesh.stdout.trim());
        const expected=await local.call({method:'oracle_message',amount});
        // Both account orderings are legal. Independently preserve SDK roles
        // and instructions while reindexing its unsigned permission classes
        // into the public package's deterministic discovery order.
        const decoder=kit.getCompiledTransactionMessageDecoder();
        const actualMessage=Buffer.from(prepared.message_hex,'hex');
        const actual=decoder.decode(actualMessage),sdk=decoder.decode(Buffer.from(expected.message_hex,'hex'));
        assert.deepEqual(actual.header,sdk.header);
        assert.equal(actual.staticAccounts[0],sdk.staticAccounts[0]);
        const classes=value=>{const h=value.header,k=value.staticAccounts,s=h.numSignerAccounts,r=h.numReadonlySignerAccounts,u=h.numReadonlyNonSignerAccounts;
          return [k.slice(0,s-r),k.slice(s-r,s),k.slice(s,k.length-u),k.slice(k.length-u)].map(group=>[...group].sort());};
        assert.deepEqual(classes(actual),classes(sdk));
        const remap=index=>actual.staticAccounts.indexOf(sdk.staticAccounts[index]);
        const normalized={...sdk,staticAccounts:actual.staticAccounts,instructions:sdk.instructions.map(ix=>({...ix,programAddressIndex:remap(ix.programAddressIndex),accountIndices:ix.accountIndices.map(remap)}))};
        assert.equal(actualMessage.toString('hex'),Buffer.from(kit.getCompiledTransactionMessageEncoder().encode(normalized)).toString('hex'),'full Mesh message differs after SDK account-order normalization');
        assert.equal(expected.advance.data_hex,'04000000');
        assert.equal(prepared.wire_hex,signed(prepared.message_hex),'public writer packet differs from independent OpenSSL signing');
        return prepared.wire_hex;
      }
      const amount='9007199254740993';
      const before=state;
      const packet=await prepare(amount);
      const result=await local.call({method:'send',wire_hex:packet});
      assert.equal(result.ok,true,JSON.stringify(result));
      assert.notEqual(result.after.nonce,before.nonce);
      await reconcile(packet,result);
      await reconcile(packet,result,true);
      assert.equal(BigInt(result.before.source_balance)-BigInt(result.after.source_balance),BigInt(amount));
      assert.equal(BigInt(result.after.destination_balance)-BigInt(result.before.destination_balance),BigInt(amount));
      const replay=await local.call({method:'send',wire_hex:packet});
      assert.equal(replay.ok,false);assert.match(replay.error,/BlockhashNotFound|AlreadyProcessed/);
      assert.equal(replay.fee,'0');assert.deepEqual(replay.before,replay.after);
      const nonceReplay=await local.call({method:'send',wire_hex:alternatePacket(packet,'42')});
      assert.equal(nonceReplay.ok,false);assert.match(nonceReplay.error,/BlockhashNotFound/);
      assert.equal(nonceReplay.fee,'0');assert.deepEqual(nonceReplay.before,nonceReplay.after);
      state=await local.call({method:'expire'});
      const failedPacket=await prepare('18446744073709551615');
      const failure=await local.call({method:'send',wire_hex:failedPacket});
      assert.equal(failure.ok,false);assert.match(failure.error,/InstructionError/);
      assert.notEqual(failure.before.nonce,failure.after.nonce,'failed transfer must still consume nonce');
      assert.ok(BigInt(failure.fee)>0n);
      await reconcile(failedPacket,failure);
      assert.equal(failure.before.source_balance,failure.after.source_balance);
      assert.equal(failure.before.destination_balance,failure.after.destination_balance);
      const failedReplay=await local.call({method:'send',wire_hex:failedPacket});
      assert.equal(failedReplay.ok,false);assert.match(failedReplay.error,/BlockhashNotFound|AlreadyProcessed/);
      assert.equal(failedReplay.fee,'0');assert.deepEqual(failedReplay.before,failedReplay.after);
      const failedNonceReplay=await local.call({method:'send',wire_hex:alternatePacket(failedPacket,'43')});
      assert.equal(failedNonceReplay.ok,false);assert.match(failedNonceReplay.error,/BlockhashNotFound/);
      assert.equal(failedNonceReplay.fee,'0');assert.deepEqual(failedNonceReplay.before,failedNonceReplay.after);
      treasury=true;
      state=await local.call({method:'expire'});
      const treasuryPacket=await prepare('123456789');
      const treasurySuccess=await local.call({method:'send',wire_hex:treasuryPacket});
      assert.equal(treasurySuccess.ok,true,JSON.stringify(treasurySuccess));
      await reconcile(treasuryPacket,treasurySuccess);
      const treasuryReplay=await local.call({method:'send',wire_hex:treasuryPacket});
      assert.equal(treasuryReplay.ok,false);assert.deepEqual(treasuryReplay.before,treasuryReplay.after);
      state=await local.call({method:'expire'});
      const treasuryFailedPacket=await prepare('18446744073709551615');
      const treasuryFailure=await local.call({method:'send',wire_hex:treasuryFailedPacket});
      assert.equal(treasuryFailure.ok,false);assert.notEqual(treasuryFailure.before.nonce,treasuryFailure.after.nonce);
      await reconcile(treasuryFailedPacket,treasuryFailure);
    }
    const report={schema_version:1,passed:true,public_mesh:true,public_signed_packet_builder:true,opt_levels:[0,2],official_nonce_sdk:'3.3.0',official_system_interface:'3.3.0',bank:'Agave Bank 4.3.2',signatures_verified:true,full_message_matches:8,account_order_normalized:true,nonce_advancements:8,successful_transfers:4,failed_transfers_consuming_nonce:4,exact_replays_rejected:6,distinct_signature_consumed_nonce_replays_rejected:4,compiled_mesh_rpc_outcomes:8,mismatched_outcome_rpc_ids_rejected:2,treasury_canonical_signing:true,treasury_actual_bank_outcomes:4,above_2pow53:true,real_funds:false};
    if(process.env.SOLANA_NONCE_REPORT)await fs.writeFile(process.env.SOLANA_NONCE_REPORT,JSON.stringify(report,null,2)+'\n');
    assert.equal(rpcCalls,10);
    console.log('SOLANA_NONCE_JSON='+JSON.stringify(report));
  }finally{local.close();if(server)await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}
});
