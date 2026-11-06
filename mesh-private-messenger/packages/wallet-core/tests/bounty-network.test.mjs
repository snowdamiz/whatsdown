// Local-only full Mesh network/journal + actual SDK + real SPL/ATA execution.
// Repeated01 is a public fixture seed. No production RPC, keys or funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';

const product = path.resolve(import.meta.dirname, '../../..');
const publicRoot = process.env.MESH_LANG_ROOT || path.resolve(product, '../mesh-lang');
const kit = createRequire(path.join(product, 'ops/rewards/package.json'))('@solana/kit');
const bridge = process.env.WALLET_FIXTURE_BRIDGE || path.join(product, 'packages/wallet-core/target/debug/examples/wallet_fixture_bridge');
const oracle = process.env.WALLET_PAYMENT_ORACLE || path.join(product, 'programs/target/debug/examples/credit_payment_fixture');
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const address = bytes => kit.getAddressDecoder().decode(bytes);
const raw = value => Buffer.from(kit.getAddressEncoder().encode(value));
const run = (command, args=[], options={}) => new Promise((resolve,reject) => {
  const child = spawn(command,args,options); let stdout='',stderr='';
  child.stdout.on('data',b=>stdout+=b); child.stderr.on('data',b=>stderr+=b);
  child.on('error',reject); child.on('close',code=>resolve({code,stdout,stderr}));
});
const sync = (binary,input) => {
  const result=spawnSync(binary,[],{input:JSON.stringify(input),encoding:'utf8'});
  assert.equal(result.status,0,result.stderr); return JSON.parse(result.stdout);
};
const account = (owner,data) => ({owner,lamports:10000000,executable:false,rentEpoch:0,data:[data.toString('base64'),'base64'],space:data.length});

test('bounty native network persists before send and resolves lost acknowledgment through finalized token deltas', {timeout:180000}, async () => {
  const directory=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'morse-bounty-network-')));
  const project=path.join(directory,'bounty-network-proof'), servers=[];
  const identity=sync(bridge,{bounty_count:1}), payer=Buffer.from(identity.address_hex,'hex');
  const finder=Buffer.from(identity.bounties[0].address_hex,'hex'), destination=Buffer.alloc(32,41), mint=Buffer.alloc(32,7);
  const amount=9007199254740993n, now=Math.floor(Date.now()/1000);
  let boot,fixture,call,mode='missing',history='missing',height=100,hashTag=4;
  let signed,executed, sends=0,actualExecutions=0,preparationCalls=0,queries=0;
  try {
    await fs.mkdir(project); await fs.mkdir(path.join(directory,'key'),{mode:0o700});
    await fs.writeFile(path.join(project,'mesh.toml'),`[package]\nname="bounty-network-proof"\nversion="0.1.0"\n[dependencies]\nmobile={path=${JSON.stringify(path.join(product,'packages/mobile-core'))}}\n`);
    await fs.copyFile(path.join(product,'packages/wallet-core/tests/bounty-network.mpl.fixture'),path.join(project,'main.mpl'));
    const support=(await fs.readFile(path.join(product,'packages/mobile-core/tests/fork_filing_support.mpl'),'utf8'))
      .replace('from Tests.GroupConsistencySupport import signing_pair, wide','')
      .replace('from Tests.Support import repeated','');
    await fs.writeFile(path.join(project,'fixture.mpl'),support+`
fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do Err(_) -> Err("fixture_key_failed") Ok(value) -> Ok(value) end
end
fn wide(value :: Int) -> U64!String do U64.parse(Int.to_string(value)) end
fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do Err(_) -> Err("fixture_bytes_failed") Ok(value) -> Ok(value) end
end
`);
    const built=await run(process.env.MESHC||path.join(publicRoot,'target/debug/meshc'),['build',project,'--opt-level',process.env.BOUNTY_NETWORK_OPT_LEVEL||'2']);
    assert.equal(built.code,0,built.stdout+built.stderr);
    for(let index=0;index<3;index++) {
      const server=http.createServer(async(req,res)=>{
        let body=''; for await(const chunk of req) body+=chunk;
        const request=JSON.parse(body); res.setHeader('content-type','application/json'); res.setHeader('connection','close');
        const response=value=>res.end(JSON.stringify({jsonrpc:'2.0',id:request.id,result:value}));
        if(request.method==='getBlockHeight') {preparationCalls++; return response(height);}
        if(request.method==='getLatestBlockhash') {preparationCalls++; return response({context:{slot:100000},value:{blockhash:address(Buffer.alloc(32,hashTag)),lastValidBlockHeight:hashTag===4?123:223}});}
        if(request.method==='getMultipleAccounts') {
          preparationCalls++; assert.equal(request.params[1].commitment,'finalized');
          const values=request.params[0].map(key=>{
            let value=fixture.get(key)??null;
            if(key===boot.receipt&&mode==='missing') return null;
            if(key===boot.receipt&&mode==='elsewhere') {const data=Buffer.from(value.data[0],'base64');data.set(Buffer.alloc(32,99),72);value=account(value.owner,data);}
            if(key===address(mint)&&mode==='bad-mint') {const data=Buffer.from(value.data[0],'base64');data[44]=19;value=account(value.owner,data);}
            return value;
          });
          return response({context:{slot:100000},value:values});
        }
        if(request.method==='getTransaction') {
          queries++; assert.equal(request.id,63); assert.equal(request.params[0],kit.getBase58Decoder().decode(Buffer.from(signed.wire_hex,'hex').subarray(1,65)));
          assert.equal(request.params[1].commitment,'finalized');
          if(history==='missing'||(history==='disagree'&&index===2)) return response(null);
          const result=JSON.parse(executed.response).result;
          if(history==='disagree'&&index===1) result.meta.postTokenBalances.find(row=>row.owner===address(destination)).uiTokenAmount.amount='5';
          return response(result);
        }
        assert.equal(request.method,'sendTransaction'); assert.equal(request.id,64); sends++;
        const wire=Buffer.from(request.params[0],'base64'); assert.equal(wire.toString('hex'),signed.wire_hex);
        assert.deepEqual(request.params[1],{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:0,minContextSlot:100000});
        const saved=await call('local'); assert.equal(saved.status,2); assert.equal(saved.wire_hex,signed.wire_hex,'exactpacket must be durable in a fresh process before RPC');
        if(!executed) {
          executed=sync(oracle,{fixture:{version:'legacy',asset:0,payer:address(payer),source_owner:address(finder),mint:address(mint),source:boot.source,destination:boot.destination,deposit:address(destination),wire_hex:signed.wire_hex},token_source_amount:(amount+1n).toString(),block_time:now,replay_count:3});
          executed.response=executed.response.replace(/"data_hex":"([0-9a-f]*)"/g,(_all,hex)=>'"data":'+JSON.stringify(kit.getBase58Decoder().decode(Buffer.from(hex,'hex'))));
          assert.equal(executed.replay_rejections,3); actualExecutions++;
          req.socket.destroy(); return;
        }
        if(index===1) return res.end(JSON.stringify({jsonrpc:'2.0',id:65,result:kit.getBase58Decoder().decode(wire.subarray(1,65))}));
        return response(kit.getBase58Decoder().decode(Buffer.alloc(64,88)));
      });
      await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve)); servers.push(server);
    }
    const base={...process.env,BOUNTY_STORAGE:path.join(directory,'key'),BOUNTY_DATABASE:path.join(directory,'bounty.db'),BOUNTY_CONFIG:path.join(directory,'config.txt'),BOUNTY_ENDPOINTS:servers.map(s=>`http://127.0.0.1:${s.address().port}`).join(','),BOUNTY_PAYER:payer.toString('hex'),BOUNTY_FINDER:finder.toString('hex'),BOUNTY_DESTINATION:destination.toString('hex'),BOUNTY_NOW:String(now)};
    const invoke=async(action,extra={})=>{
      const result=await run(path.join(project,'bounty-network-proof'),[],{env:{...base,BOUNTY_ACTION:action,...extra}});
      assert.equal(result.code,0,result.stdout+result.stderr);return JSON.parse(result.stdout);
    };
    call=async(action,extra)=>{const result=await invoke(action,extra);assert.equal(result.error,undefined,JSON.stringify(result));return result;};
    boot=await call('bootstrap'); fixture=new Map();
    const log=Buffer.alloc(352);log.set(Buffer.from('4d4c4701','hex'));log[4]=2;log[5]=1;log[6]=boot.log_name.length;log.set(Buffer.from(boot.log_name),8);log.set(Buffer.from(boot.log_id_hex,'hex'),40);log.set(Buffer.from(boot.service_hex,'hex'),72);log.set(Buffer.alloc(32,20),104);log.set(Buffer.from(boot.ring_hex,'hex'),136);log.writeUInt16LE(10,210);log.set(Buffer.from('morse.test'),212);
    fixture.set(boot.log,account(boot.program,log));
    const economics=Buffer.alloc(192);economics.set(Buffer.from('4d454301','hex'));economics.set(Buffer.from(boot.log_id_hex,'hex'),4);economics.set(mint,36);economics.set(payer,68);economics.writeBigUInt64LE(1n,100);economics.writeBigUInt64LE(1n,108);economics[164]=3;fixture.set(boot.economics,account(boot.program,economics));
    const receipt=Buffer.alloc(288);receipt.set(Buffer.from('4d505201','hex'));receipt[4]=1;receipt.set(Buffer.from(boot.log_id_hex,'hex'),8);receipt.set(Buffer.from(boot.proof_hex,'hex'),40);receipt.set(finder,72);receipt.set(payer,104);receipt.set(mint,136);receipt.set(Buffer.from(boot.first_hex,'hex'),168);receipt.set(Buffer.from(boot.second_hex,'hex'),200);receipt.writeBigUInt64LE(BigInt(now),232);receipt.writeBigUInt64LE(amount*10n,240);receipt.writeBigUInt64LE(amount,248);receipt.writeBigUInt64LE(amount*10n,256);receipt.writeBigUInt64LE(3n,264);fixture.set(boot.receipt,account(boot.program,receipt));
    const mintData=Buffer.alloc(82);mintData.writeBigUInt64LE(amount+1n,36);mintData[44]=6;mintData[45]=1;fixture.set(address(mint),account(TOKEN,mintData));
    const holding=Buffer.alloc(165);holding.set(mint);holding.set(finder,32);holding.writeBigUInt64LE(amount+1n,64);holding[108]=1;fixture.set(boot.source,account(TOKEN,holding));
    assert.equal((await invoke('prepare')).error,'bounty_not_paid');assert.equal((await call('local')).status,0);
    mode='elsewhere';assert.equal((await invoke('prepare')).error,'bounty_paid_elsewhere');
    mode='bad-mint';assert.equal((await invoke('prepare')).error,'bounty_transfer_asset_unavailable');
    mode='good';let prepared=await call('prepare');assert.equal(prepared.status,1);
    const old=sync(bridge,{bounty_count:1,bounty_transfer_hex:prepared.intent_hex});
    height=124;hashTag=6;prepared=await call('prepare');assert.equal(Buffer.from(prepared.intent_hex,'hex').subarray(116,148).toString('hex'),Buffer.alloc(32,6).toString('hex'));
    assert.ok((await invoke('commit',{BOUNTY_WIRE:old.wire_hex})).error,'stale nativeprompt rejected');
    signed=sync(bridge,{bounty_count:1,bounty_transfer_hex:prepared.intent_hex});
    assert.ok((await invoke('commit',{BOUNTY_WIRE:signed.wire_hex,BOUNTY_NOW:String(now+1000)})).error,'expired nativeprompt rejected');
    const racers=await Promise.all(Array.from({length:4},()=>invoke('commit',{BOUNTY_WIRE:signed.wire_hex})));
    assert.ok(racers.some(value=>value.status===2));for(const value of racers)if(value.error)assert.equal(value.error,'local_state_changed');
    const committed=await call('local');assert.equal(committed.status,2);assert.equal(committed.wire_hex,signed.wire_hex);
    const beforePrepare=preparationCalls;assert.deepEqual(await call('prepare'),committed);assert.equal(preparationCalls,beforePrepare);
    assert.equal((await invoke('submit',{BOUNTY_FENCE:'1'})).error,'bounty_transfer_context_changed');assert.equal(sends,0);
    const unknown=await call('submit');assert.equal(unknown.status,2);assert.equal(actualExecutions,1);assert.equal(sends,3);
    assert.equal((await call('recover')).status,2,'two null histories do not reopen signing');
    assert.equal((await call('submit')).status,2);assert.equal(sends,6);
    assert.equal((await call('submit',{BOUNTY_NOW:String(now+1000)})).status,2);assert.equal(sends,6,'no expired first send');
    history='disagree';assert.equal((await invoke('recover')).error,'bounty_transfer_rpc_disagree');assert.equal((await call('local')).status,2);
    history='complete';const final=await call('recover');assert.equal(final.status,4);assert.equal(final.signature_hex,committed.signature_hex);assert.equal(final.finalized_slot,'100000');
    const beforeTerminal={queries,sends,preparationCalls};assert.deepEqual(await call('prepare'),final);assert.deepEqual(await call('submit'),final);assert.deepEqual(await call('recover'),final);assert.deepEqual({queries,sends,preparationCalls},beforeTerminal);
    await call('erase');assert.ok((await invoke('commit',{BOUNTY_WIRE:signed.wire_hex})).error);assert.equal((await call('local')).status,0);
    const report={schema_version:1,passed:true,local_only:true,opt_level:Number(process.env.BOUNTY_NETWORK_OPT_LEVEL||2),real_spl_ata_execution:actualExecutions,svm_duplicate_rejections:3,exact_packet_send_attempts:sends,journal_before_send:true,hard_process_restarts:true,above_2pow53:true,finalized_two_provider_agreement:true,missing_history_never_resigns:true,bad_token_delta_rejected:true,wrong_paid_finder_rejected:true,unpaid_receipt_rejected:true,concurrent_committers:4,expired_broadcasts:0,stale_prompt_rejected:true,native_context_fence:true,account_erase_fence:true};
    if(process.env.BOUNTY_NETWORK_REPORT)await fs.writeFile(process.env.BOUNTY_NETWORK_REPORT,JSON.stringify(report,null,2)+'\n');
    console.log('BOUNTY_NETWORK_JSON='+JSON.stringify(report));
  } finally {
    for(const server of servers)await new Promise(resolve=>server.close(resolve));
    await fs.rm(directory,{recursive:true,force:true});
  }
});
