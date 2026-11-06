// Offline custody proof. Fixed publicly known seeds never receive live funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {createRequire} from 'node:module';
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
const run=(command,args,options={})=>new Promise((resolve,reject)=>{
  const child=spawn(command,args,options);let stdout='',stderr='';
  child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
  child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr}));
});
function bank(){
  const child=spawn(binary,[],{stdio:['pipe','pipe','pipe']});let errors='';const pending=[];
  child.stderr.on('data',chunk=>errors+=chunk);
  readline.createInterface({input:child.stdout}).on('line',line=>pending.shift()?.resolve(JSON.parse(line)));
  child.on('exit',code=>{for(const item of pending.splice(0))item.reject(new Error(`bank exit${code}: ${errors}`));});
  child.stdin.on('error',error=>{for(const item of pending.splice(0))item.reject(error);});
  return {call:query=>new Promise((resolve,reject)=>{pending.push({resolve,reject});child.stdin.write(JSON.stringify(query)+'\n');}),close:()=>child.stdin.end()};
}
async function copyModules(program){
  for(const relative of ['payment/revenue_policy.mpl','payment/treasury.mpl','payment/treasury_outcome.mpl','payment/verify.mpl','payment/observation.mpl','storage/treasury.mpl','storage/treasury_packet.mpl','storage/treasury_nonce.mpl','payment/treasury_batch.mpl','payment/treasury_batch_types.mpl','payment/treasury_batch_outcome.mpl','storage/treasury_batch.mpl','runtime/treasury_batch.mpl','runtime/treasury_signing.mpl','runtime/treasury.mpl']){
    const target=path.join(program,relative);await fs.mkdir(path.dirname(target),{recursive:true});
    await fs.copyFile(path.join(product,'services/credit-issuer',relative),target);
  }
}
test('actual paid underpayment refunds once after lost acknowledgment, process restart and unresolved nonce history',{timeout:120000},async()=>{
  const temporary=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'morse-treasury-proof-')));
  const local=bank(),servers=[],history=new Map();const batchMode=process.env.TREASURY_BATCH_PROOF==='1',failureMode=process.env.TREASURY_BATCH_FAILURE==='1';
  let sends=0,visibility=batchMode?'visible':'hidden',purchaseSignature='',movementId='',redirect=false,redirectRequests=0;const purchaseSignatures=new Set();
  const unpinned=http.createServer(async(request,response)=>{for await(const _chunk of request){}redirectRequests++;response.writeHead(503);response.end();});
  await new Promise(resolve=>unpinned.listen(0,'127.0.0.1',resolve));
  let state=await local.call({method:'expire'});const original=state,usdc=original.rail==='usdc',units=usdc?'4999999':'123456789';
  try{
    for(let provider=0;provider<2;provider++){
      const server=http.createServer(async(request,response)=>{
        try{
          let body='';for await(const chunk of request)body+=chunk;
          const query=JSON.parse(body);let result;
          if(redirect&&provider===0){response.writeHead(303,{location:`http://127.0.0.1:${unpinned.address().port}/unpinned`});response.end();return;}
          if(query.method==='getGenesisHash')result=JSON.stringify(state.cluster);
          else if(query.method==='getAccountInfo'){
            assert.equal(query.params[0],state.address);assert.equal(query.params[1].commitment,'finalized');
            result=`{"context":{"slot":1},"value":{"owner":${JSON.stringify(state.account.owner)},"data":[${JSON.stringify(state.account.data_base64)},"base64"],"lamports":${state.account.lamports},"rentEpoch":0,"executable":false}}`;
          }else if(query.method==='getTransaction'){
            assert.deepEqual(query.params[1],{encoding:'base64',commitment:'finalized',maxSupportedTransactionVersion:0});
            const signature=query.params[0];
            const visible=purchaseSignatures.has(signature)||visibility==='visible'||(visibility==='mixed'&&provider===0);
            const observed=visible?history.get(signature):undefined;
            result=observed?observed.rpc_response.match(/"result":(.*)}$/)[1].replace(/"data_hex":"([a-f0-9]*)"/g,(_match,hex)=>`"data":"${kit.getBase58Decoder().decode(Buffer.from(hex,'hex'))}"`):'null';
          }else if(query.method==='sendTransaction'){
            assert.equal(provider,0);sends++;
            const packet=Buffer.from(query.params[0],'base64'),signature=packet.subarray(1,65);
            const sql=`SELECT encode(packet,'hex') AS packet FROM issuer_treasury_attempts WHERE transaction_signature=decode('${signature.toString('hex')}','hex') UNION ALL SELECT encode(packet,'hex') FROM issuer_treasury_batch_attempts WHERE transaction_signature=decode('${signature.toString('hex')}','hex')`;
            const recorded=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',['-X','-At','-c',sql],{encoding:'utf8',env:process.env});
            assert.equal(recorded.status,0,recorded.stderr);assert.equal(recorded.stdout.trim(),packet.toString('hex'),'network preceded durable packet commit');
            if(batchMode)await local.call({method:'expire'}); // Real bank blockhash progression, never nonce byte mutation.
            const executed=await local.call({method:'send',wire_hex:packet.toString('hex')});
            assert.equal(executed.ok,!failureMode,JSON.stringify(executed));
            if(usdc)assert.ok(executed.sbf_logs.some(line=>line.includes('Tokenkeg')&&line.includes('invoke')),'missing actual SPL SBF invocation');
            state=executed.after;
            history.set(kit.getBase58Decoder().decode(signature),executed);
            response.destroy();return; // Actual execution, lost acknowledgment.
          }else throw new Error(`unexpected RPC ${query.method}`);
          response.writeHead(200,{'content-type':'application/json','connection':'close'});
          response.end(`{"jsonrpc":"2.0","id":${query.id},"result":${result}}`);
        }catch(error){response.writeHead(500);response.end(String(error));}
      });
      await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);
    }
    const program=path.join(temporary,'client');await fs.mkdir(program);
    await fs.writeFile(path.join(program,'mesh.toml'),`[package]\nname="treasury-proof"\nversion="0.1.0"\n[dependencies]\nmessenger-protocol={path=${JSON.stringify(path.join(product,'packages/messenger-protocol'))}}\n`);
    await copyModules(program);await fs.copyFile(path.join(import.meta.dirname,'fixtures/treasury.mpl.fixture'),path.join(program,'main.mpl'));
    const executable=path.join(program,'client');
    const built=await run(compiler,['build','--opt-level','2',program,'-o',executable]);assert.equal(built.code,0,built.stdout+built.stderr);
    const keyDir=path.join(temporary,'keys');await fs.mkdir(keyDir,{mode:0o700});
    const providers=servers.map(server=>`http://127.0.0.1:${server.address().port}`);
    const env={...process.env,TREASURY_KEY_DIR:keyDir,TREASURY_SOURCE_SEED:'04'.repeat(32),TREASURY_FEE_SEED:'01'.repeat(32),TREASURY_AUTHORITY_SEED:'02'.repeat(32),TREASURY_BUYER_SEED:'05'.repeat(32)};
    let sequence=0;
    async function client(mode,extra={},success=true){
      const input=path.join(temporary,`input-${sequence++}.json`);await fs.writeFile(input,JSON.stringify({...original,provider_a:providers[0],provider_b:providers[1],mode,...extra}));
      const result=await run(executable,[],{env:{...env,TREASURY_INPUT:input,...(extra.quote_index===1?{TREASURY_SOURCE_SEED:'06'.repeat(32)}:{})}});
      if(success)assert.equal(result.code,0,result.stdout+result.stderr);else assert.notEqual(result.code,0,'unsafe recovery accepted provider disagreement');
      return result.stdout.trim();
    }
    assert.equal(await client('init'),'initialized');
    const packet=Buffer.from(await client('purchase'),'hex');
    const message=packet.subarray(65),buyer=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,5)]),format:'der',type:'pkcs8'});
    assert.deepEqual(packet.subarray(1,65),sign(null,message,buyer));
    const decoded=kit.getCompiledTransactionMessageDecoder().decode(message);
    assert.equal(decoded.header.numSignerAccounts,1);assert.equal(decoded.instructions.length,1);
    assert.equal(Buffer.from(decoded.instructions[0].data).readBigUInt64LE(usdc?1:4),BigInt(units));
    purchaseSignature=kit.getBase58Decoder().decode(packet.subarray(1,65));purchaseSignatures.add(purchaseSignature);
    const payment=await local.call({method:'send',wire_hex:packet.toString('hex')});assert.equal(payment.ok,true,JSON.stringify(payment));
    history.set(purchaseSignature,payment);state=payment.after;
    if(usdc&&!batchMode)state=await local.call({method:'close_buyer_ata'});
    redirect=true;await client('observe',{payment_signature:packet.subarray(1,65).toString('hex')},false);
    assert.equal(redirectRequests,0,'pinned provider RPC followed a redirect');redirect=false;
    const observed=JSON.parse(await client('observe',{payment_signature:packet.subarray(1,65).toString('hex')}));
    assert.equal(observed.state,0);assert.equal(observed.amount,units);movementId=observed.id;
    if(batchMode){
      
      const otherKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,6)]),format:'der',type:'pkcs8'});
      const source=kit.getAddressDecoder().decode(createPublicKey(otherKey).export({format:'der',type:'spki'}).subarray(-32));
      const other={source,quote_index:1};assert.equal(await client('init',other),'initialized');
      const second=Buffer.from(await client('purchase',other),'hex'),signature=kit.getBase58Decoder().decode(second.subarray(1,65));purchaseSignatures.add(signature);
      const paid=await local.call({method:'send',wire_hex:second.toString('hex')});assert.equal(paid.ok,true,JSON.stringify(paid));history.set(signature,paid);state=paid.after;
      const next=JSON.parse(await client('observe',{...other,payment_signature:second.subarray(1,65).toString('hex')}));assert.equal(next.state,0);
      if(usdc)state=await local.call({method:'close_buyer_ata'});
      const ids=[observed.id,next.id];
      const reserved=await Promise.all(Array.from({length:4},(_,index)=>client('batch_prepare',{movement_ids:index%2?ids:[...ids].reverse()}).then(JSON.parse)));
      assert.ok(reserved.every(value=>value.id===reserved[0].id&&value.state===0));const batchId=reserved[0].id;
      await client('batch_prepare',{movement_ids:[ids[0],ids[0]]},false);
      await client('batch_prepare',{movement_ids:[ids[0]]},false);
      await client('run',{movement_id:ids[0]},false);
      if(failureMode){
        assert.equal(usdc,false);const drain=Buffer.from(await client('drain',other),'hex');
        const spent=await local.call({method:'send',wire_hex:drain.toString('hex')});assert.equal(spent.ok,true,JSON.stringify(spent));state=spent.after;const before=state;
        visibility='visible';const failed=JSON.parse(await client('batch_run',{batch_id:batchId}));assert.equal(failed.state,3);assert.equal(sends,1);
        assert.equal(state.source_balance,before.source_balance,'earlier successful member effect survived failed packet');
        const check=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',['-X','-At','-c',`SELECT COUNT(*)::text||':'||MIN(state)::text||':'||MAX(state)::text||':'||SUM(fee)::text FROM issuer_treasury_movements WHERE batch_id=decode('${batchId}','hex')`],{encoding:'utf8',env:process.env});
        assert.equal(check.status,0,check.stderr);const parts=check.stdout.trim().split(':');assert.deepEqual(parts.slice(0,3),['2','3','3']);
        const executed=history.get(kit.getBase58Decoder().decode(Buffer.from(failed.signature,'hex')));assert.equal(parts[3],executed.fee);
        assert.notEqual(state.nonce,before.nonce,'actual Agave failed durable nonce was not advanced');
        const reset=JSON.parse(await client('batch_retry',{batch_id:batchId}));assert.equal(reset.state,0);assert.equal(reset.id,batchId);assert.equal(reset.members,2);assert.equal(sends,1);
        const attempt=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',['-X','-At','-c',`SELECT COUNT(*)::text||':'||MIN(state)::text FROM issuer_treasury_batch_attempts WHERE batch_id=decode('${batchId}','hex')`],{encoding:'utf8',env:process.env});assert.equal(attempt.status,0,attempt.stderr);assert.equal(attempt.stdout.trim(),'1:3');
        const report={passed:true,members:2,whole_packet_atomic:true,all_members_failed:true,nonce_consumed_on_failure:true,fees_conserved:true,explicit_retry_preserves_members_and_attempt:true,total_sends:sends,real_funds:false};
        if(process.env.TREASURY_REPORT)await fs.writeFile(process.env.TREASURY_REPORT,JSON.stringify(report,null,2)+'\n');console.log('TREASURY_BATCH_FAILURE_JSON='+JSON.stringify(report));return;
      }
      visibility='hidden';const attempted=JSON.parse(await client('batch_run',{batch_id:batchId}));
      assert.equal(attempted.state,1);assert.equal(sends,1,'two ready payments must share one immutable signed packet');
      const blocked=JSON.parse(await client('batch_run',{batch_id:batchId}));assert.equal(blocked.state,4);assert.equal(sends,1);
      visibility='mixed';await client('batch_reconcile',{batch_id:batchId},false);assert.equal(sends,1);
      visibility='visible';const recovered=JSON.parse(await client('batch_reconcile',{batch_id:batchId}));assert.equal(recovered.state,2);assert.equal(recovered.signature,attempted.signature);assert.equal(sends,1);
      const audit=spawnSync(process.env.CREDIT_TEST_PSQL||'psql',['-X','-At','-c',`SELECT COUNT(*)::text||':'||COUNT(DISTINCT encode(transaction_signature,'hex'))::text||':'||SUM(fee)::text||':'||SUM(rent)::text FROM issuer_treasury_movements WHERE batch_id=decode('${batchId}','hex')`],{encoding:'utf8',env:process.env});
      assert.equal(audit.status,0,audit.stderr);const fields=audit.stdout.trim().split(':');assert.equal(fields[0],'2');assert.equal(fields[1],'1');
      const executed=history.get(kit.getBase58Decoder().decode(Buffer.from(attempted.signature,'hex')));assert.equal(fields[2],executed.fee);
      if(usdc)assert.ok(BigInt(fields[3])>0n,'missing ATA rent allocation');else assert.equal(fields[3],'0');
      for(const server of servers)await new Promise(resolve=>server.close(resolve));servers.length=0;
      assert.equal(JSON.parse(await client('batch_run',{batch_id:batchId})).state,2);assert.equal(sends,1);
      const report={passed:true,asset:usdc?'USDC':'SOL',members:2,actual_packet:true,immutable_membership_races:4,duplicate_and_overlap_rejected:true,nonce_lane_shared:true,fees_conserved:true,rent_conserved:true,lost_ack_restart:true,missing_history_blocked:true,finalized_same_signature:true,total_sends:sends,real_funds:false};
      if(process.env.TREASURY_REPORT)await fs.writeFile(process.env.TREASURY_REPORT,JSON.stringify(report,null,2)+'\n');console.log('TREASURY_BATCH_JSON='+JSON.stringify(report));
      return;
    }
    const attempted=JSON.parse(await client('run',{movement_id:movementId}));
    assert.equal(attempted.state,1);assert.equal(sends,1);assert.equal(attempted.signature.length,128);
    assert.equal(BigInt(usdc?payment.after.source_token_balance:payment.after.source_balance)-BigInt(usdc?state.source_token_balance:state.source_balance),BigInt(units),'refund amount included unrelated preexisting source funds');
    assert.equal(BigInt(usdc?state.buyer_token_balance:state.buyer_balance)-BigInt(usdc?payment.after.buyer_token_balance:payment.after.buyer_balance),BigInt(units),'refund did not return original payer');
    const blocked=JSON.parse(await client('run',{movement_id:movementId}));assert.equal(blocked.state,4);assert.equal(blocked.signature,attempted.signature);assert.equal(sends,1);
    visibility='mixed';await client('run',{movement_id:movementId},false);assert.equal(sends,1);
    visibility='visible';const recovered=JSON.parse(await client('run',{movement_id:movementId}));
    assert.equal(recovered.state,2);assert.equal(recovered.signature,attempted.signature);assert.equal(sends,1);
    for(const server of servers)await new Promise(resolve=>server.close(resolve));servers.length=0;
    const cached=JSON.parse(await client('run',{movement_id:movementId}));assert.equal(cached.state,2);assert.equal(sends,1);
    const report={schema_version:1,passed:true,bank:usdc?'LiteSVM0.17 real SPL/ATA SBF':'Agave Bank4.3.2',asset:usdc?'USDC':'SOL',missing_refund_ata_created:usdc,real_signed_purchase:true,independent_openssl_signature:true,two_provider_observation:true,underpayment_units:units,unrelated_source_balance_untouched:true,durable_packet_before_send:true,lost_ack_after_execution:true,process_restart:true,storage_key_file_restart:true,nonce_changed_missing_history_blocked:true,provider_disagreement_rejected:true,finalized_recovery_same_signature:true,total_refund_sends:sends,pinned_rpc_redirects_rejected:true,real_funds:false};
    if(process.env.TREASURY_REPORT)await fs.writeFile(process.env.TREASURY_REPORT,JSON.stringify(report,null,2)+'\n');
    console.log('TREASURY_RPC_JSON='+JSON.stringify(report));
  }finally{local.close();await new Promise(resolve=>unpinned.close(resolve));for(const server of servers)await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});}
});
