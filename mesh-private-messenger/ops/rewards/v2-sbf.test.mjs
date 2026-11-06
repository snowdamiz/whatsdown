import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressEncoder, getCompiledTransactionMessageDecoder,
  getTransactionDecoder, getSignatureFromTransaction } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';

const run=promisify(execFile),genesis='11111111111111111111111111111111';
const required=name=>{assert.ok(process.env[name],`Missing ${name}; run scripts/prove-rewards-v2.sh`);return process.env[name];};
const binary=required('MORSE_REWARDS_V2_OPERATOR_BIN'),bridgeBinary=required('MORSE_REWARDS_V2_SBF_BRIDGE');
const cli=fileURLToPath(new URL('./cli.mjs',import.meta.url));
class Bridge{
  constructor(){
    this.child=spawn(bridgeBinary,[],{stdio:['pipe','pipe','pipe'],env:process.env});
    this.errors='';this.child.stderr.on('data',b=>this.errors+=b);this.child.on('error',e=>this.errors+=e.stack);
    this.exit=once(this.child,'exit');this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();
    this.queue=Promise.resolve();
  }
  ask(request){
    const result=this.queue.then(async()=>{
      this.child.stdin.write(JSON.stringify(request)+'\n');let timer;
      try{
        const line=await Promise.race([this.lines.next(),new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error(`Bridge timeout ${this.errors}`)),30000))]);
        assert.equal(line.done,false,this.errors);const value=JSON.parse(line.value);
        if(value.ok===false&&!value.signature)throw new Error(JSON.stringify(value));return value;
      }finally{clearTimeout(timer);}
    });this.queue=result.catch(()=>{});return result;
  }
  async close(){if(this.child.exitCode===null)this.child.kill('SIGKILL');await this.exit;}
}
const rpcAccount=a=>a===null?null:{...a,lamports:BigInt(a.lamports),space:BigInt(a.space),rentEpoch:0n};

// Three HTTP origins share one disposable bank. Only transport/history visibility
// is controlled here; execution, balances, fees, rent and signatures are real SBF.
async function oracle(bridge){
  const servers=[],urls=[],errors=[],sent=[],records=new Map();
  const control={mode:'normal',hideHistory:false,historyCovered:true};
  async function execute(wire){
    const tx=getTransactionDecoder().decode(Buffer.from(wire,'base64'));
    const signature=getSignatureFromTransaction(tx);
    if(!records.has(signature))records.set(signature,(async()=>{
      const keys=[...getCompiledTransactionMessageDecoder().decode(tx.messageBytes).staticAccounts];
      const before=await bridge.ask({method:'accounts',addresses:keys});
      const receipt=await bridge.ask({method:'execute',wire});
      assert.equal(receipt.ok,true,JSON.stringify(receipt));
      const after=await bridge.ask({method:'accounts',addresses:keys});
      const balances=values=>values.map(a=>a===null?0n:BigInt(a.lamports));
      return {slot:BigInt(receipt.context.slot),version:0n,transaction:[wire,'base64'],meta:{err:null,
        fee:BigInt(receipt.fee_lamports),preBalances:balances(before.value),postBalances:balances(after.value),
        loadedAddresses:{writable:[],readonly:[]}}};
    })());
    await records.get(signature);return signature;
  }
  for(let index=0;index<3;index++){
    const server=createServer(async(req,res)=>{
      try{
        let body='';for await(const chunk of req){body+=chunk;assert.ok(body.length<=32768);}
        const call=parseJsonWithBigInts(body),args=call.params??[];
        const context=await bridge.ask({method:'context'}),slot=BigInt(context.slot);
        let result;
        switch(call.method){
          case 'getGenesisHash':result=genesis;break;
          case 'getLatestBlockhash':
            assert.equal(args[0].commitment,'finalized');assert.ok(args[0].minContextSlot<=slot);
            result={context:{slot},value:{blockhash:context.blockhash,lastValidBlockHeight:BigInt(context.last_valid_block_height)}};break;
          case 'getFeeForMessage':{
            const fee=await bridge.ask({method:'fee'});result={context:{slot},value:BigInt(fee.single_signer_fee_lamports)};break;
          }
          case 'getMinimumBalanceForRentExemption':{
            const rent=await bridge.ask({method:'rent',space:Number(args[0])});result=BigInt(rent.lamports);break;
          }
          case 'getMultipleAccounts':case 'getAccountInfo':{
            const options=args[1];assert.equal(options.commitment,'finalized');assert.ok(options.minContextSlot<=slot);
            const slice=options.dataSlice?{offset:Number(options.dataSlice.offset),length:Number(options.dataSlice.length)}:{};
            const found=await bridge.ask(call.method==='getMultipleAccounts'?{method:'accounts',addresses:args[0],...slice}:{method:'account',address:args[0],...slice});
            result={context:{slot:BigInt(found.context.slot)},value:Array.isArray(found.value)?found.value.map(rpcAccount):rpcAccount(found.value)};break;
          }
          case 'sendTransaction':{
            const wire=args[0];sent.push(wire);assert.equal(args[1].skipPreflight,false);
            if(control.mode==='drop'){res.writeHead(503).end();return;}
            result=await execute(wire);
            if(control.mode==='lost-ack'){res.writeHead(503).end();return;}
            break;
          }
          case 'getSignatureStatuses':{
            assert.equal(args[1].searchTransactionHistory,true);
            const record=control.hideHistory?null:await records.get(args[0][0]);
            result={context:{slot},value:[record?{slot:record.slot,err:null,confirmations:null,confirmationStatus:'finalized'}:null]};break;
          }
          case 'getTransaction':result=control.hideHistory?null:(await records.get(args[0]))??null;break;
          case 'getBlockHeight':assert.equal(args[0].commitment,'finalized');result=BigInt(context.block_height);break;
          case 'getSlot':assert.equal(args[0].commitment,'finalized');result=slot;break;
          case 'getFirstAvailableBlock':result=control.historyCovered?0n:slot+1n;break;
          default:throw new Error(`Unexpected RPC ${call.method}`);
        }
        res.setHeader('content-type','application/json');res.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:call.id,result}));
      }catch(error){errors.push(error.stack);res.writeHead(500).end();}
    });
    server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);urls.push(`http://127.0.0.1:${server.address().port}`);
  }
  return {urls,errors,sent,records,control,async close(){for(const s of servers){s.closeAllConnections();await new Promise(resolve=>s.close(resolve));}}};
}
function rows(path){
  const db=new DatabaseSync(path,{readOnly:true});
  try{return db.prepare('SELECT * FROM rewards_transactions ORDER BY id').all().map(r=>({...r,plan:JSON.parse(r.plan),signed:r.signed?JSON.parse(r.signed):null}));}
  finally{db.close();}
}
async function harness(){
  const directory=await mkdtemp(join(tmpdir(),'rewards-v2-sbf-')),bridge=new Bridge();
  let rpc;
  try{
    const seed=new Uint8Array(32).fill(203),payer=await createKeyPairSignerFromPrivateKeyBytes(seed);
    const fixture=await bridge.ask({method:'initialize',payer:payer.address});
    assert.equal(fixture.execution,'local-sbf');assert.equal(fixture.signature_verification,true);
    rpc=await oracle(bridge);
    const securityConfig=JSON.stringify({...fixture.pins,schema_version:2,endpoints:rpc.urls,allow_loopback:true});
    const pins={version:2,program:fixture.program,judge:fixture.judge,token:fixture.token,log:fixture.addresses.log,
      mint:fixture.usdc_mint,morse:fixture.addresses.morse,payer:payer.address,
      configuration_hash:createHash('sha256').update(securityConfig).digest('hex')};
    const request={schema_version:2,action:'settle',program:pins.program,mint:pins.mint,log:fixture.log_name,payer:payer.address,epoch:fixture.epoch};
    const securityConfigPath=join(directory,'pins.json'),wallet=join(directory,'payer.json');
    await writeFile(securityConfigPath,securityConfig,{mode:0o600});
    await writeFile(wallet,JSON.stringify([...seed,...getAddressEncoder().encode(payer.address)]),{mode:0o600});
    async function intent(name,value){
      const requestPath=join(directory,`${name}-request.json`),journalPath=join(directory,`${name}.sqlite`),configPath=join(directory,`${name}.json`);
      await writeFile(requestPath,JSON.stringify(value),{mode:0o600});
      const config={binary,securityConfigPath,logVersion:fixture.log_version,requestPath,walletPaths:[wallet],journalPath,pins,
        rpc:{urls:rpc.urls,genesisHash:genesis,allowLoopback:true},policy:{maxLamports:'1000000000',maxTransactions:128}};
      await writeFile(configPath,JSON.stringify(config),{mode:0o600});
      return {journalPath,async cycle(){
        let result;try{result=await run(process.execPath,[cli,'--config',configPath],{timeout:60000,maxBuffer:65536});}
        catch(e){throw new Error(`CLI: ${e.stderr||e.message}; RPC: ${rpc.errors.join('\n')}`);}
        assert.deepEqual(rpc.errors,[]);return JSON.parse(result.stdout.trim());
      }};
    }
    async function data(key){const value=await bridge.ask({method:'account',address:key});return value.value?Buffer.from(value.value.data[0],'base64'):null;}
    return {bridge,rpc,fixture,request,intent,data,async close(){await rpc.close();await bridge.close();await rm(directory,{recursive:true,force:true});}};
  }catch(e){if(rpc)await rpc.close();await bridge.close();await rm(directory,{recursive:true,force:true});throw e;}
}

test('CLI processes restart through dropped packet expiry, pruned lost-ack effects, append31, finalize26 and exact asset claims', {timeout:300000},async()=>{
  const h=await harness();
  try{
    const {bridge,rpc,fixture}=h,settle=await h.intent('settle',h.request);
    rpc.control.mode='drop';assert.equal((await settle.cycle()).state,'unacknowledged');
    const first=rows(settle.journalPath)[0];assert.equal(first.plan.action,'open');assert.equal(first.phase,'signed');
    await settle.cycle();assert.deepEqual(rows(settle.journalPath)[0].signed,first.signed);
    await bridge.ask({method:'expire_blockhash'});rpc.control.historyCovered=false;rpc.control.hideHistory=true;
    await settle.cycle();assert.equal(rows(settle.journalPath)[0].phase,'signed','pruned absence retains reservation');
    assert.equal(rows(settle.journalPath).length,1);
    rpc.control.historyCovered=true;assert.equal((await settle.cycle()).state,'expired');
    assert.equal(rows(settle.journalPath)[0].phase,'expired');
    rpc.control.mode='lost-ack';assert.equal((await settle.cycle()).state,'unacknowledged');
    const second=rows(settle.journalPath)[1];assert.notEqual(second.signed.signature,first.signed.signature);
    assert.ok(await h.data(fixture.addresses.epoch));
    await bridge.ask({method:'expire_blockhash'});rpc.control.historyCovered=false;rpc.control.mode='normal';
    assert.equal((await settle.cycle()).state,'effect','authenticated open effect resolves pruned history');
    assert.equal(rows(settle.journalPath).length,2);
    rpc.control.hideHistory=false;rpc.control.historyCovered=true;
    let complete=false;
    for(let pass=0;pass<80;pass++){
      const value=await settle.cycle();
      if(value.state==='complete'){complete=true;break;}
      assert.ok(['broadcast','finalized'].includes(value.state),JSON.stringify(value));
    }
    assert.equal(complete,true);
    const all=rows(settle.journalPath),actions=all.map(r=>r.plan.action);
    assert.ok(actions.includes('begin'));assert.ok(actions.includes('finalize'));
    assert.ok(all.some(r=>r.plan.action==='append'&&r.plan.instructions.at(-1).accountCount===31));
    assert.ok(all.some(r=>r.plan.action==='finalize'&&r.plan.instructions.at(-1).accountCount===26));
    const ledger=await h.data(fixture.addresses.epoch),tokenEpoch=await h.data(fixture.addresses.token_epoch);
    assert.equal(ledger[52],2);assert.equal(ledger[53],64);
    for(const asset of [0,1]){
      const row=17,claim=await h.intent(`claim-${asset}`,{...h.request,action:'claim',row,asset});
      const witness=fixture.witnesses[row],destination=asset?witness.payout_morse_ata:witness.payout_usdc_ata;
      const previous=await h.data(destination),before=previous?previous.readBigUInt64LE(64):0n;
      const earned=asset?tokenEpoch.readBigUInt64LE(264+row*16):ledger.readBigUInt64LE(224+row*128+120);
      assert.ok(earned>0n);
      rpc.control.mode='lost-ack';assert.equal((await claim.cycle()).state,'unacknowledged');
      const packet=rows(claim.journalPath)[0].signed;
      rpc.control.mode='normal';assert.equal((await claim.cycle()).state,'finalized');
      assert.deepEqual(rows(claim.journalPath)[0].signed,packet);
      assert.equal((await h.data(destination)).readBigUInt64LE(64)-before,earned);
      assert.equal((await claim.cycle()).state,'complete');
      assert.equal((await claim.cycle()).state,'complete');assert.equal(rows(claim.journalPath).length,1);
    }
    console.log(JSON.stringify({proof:'v2-cli-kit-journal-sbf',signedAttempts:all.length+2,bankExecutions:rpc.records.size,appendPackets:actions.filter(a=>a==='append').length,
      claims:2,processRestartEveryCycle:true,fixtureReused:fixture.provenance.fixture_reused,fixtureSha256:fixture.provenance.fixture_sha256,programs:fixture.provenance.programs}));
  }finally{await h.close();}
});

test('restarted explicit settlement cancels an expired stage through the real program', {timeout:90000},async()=>{
  const h=await harness();
  try{
    const intent=await h.intent('expiry',h.request);
    for(const action of ['open','begin']){
      assert.equal((await intent.cycle()).state,'broadcast');
      assert.equal(rows(intent.journalPath).at(-1).plan.action,action);
      assert.equal((await intent.cycle()).state,'finalized');
    }
    await h.bridge.ask({method:'advance_clock',seconds:3600});
    assert.equal((await intent.cycle()).state,'broadcast');
    assert.equal(rows(intent.journalPath).at(-1).plan.action,'cancel');
    assert.equal((await intent.cycle()).state,'finalized');
    assert.equal((await h.data(h.fixture.addresses.epoch))[52],0);
  }finally{await h.close();}
});

test('lost append fees remain charged when cancellation erases its effect and transaction history has a hole', {timeout:90000},async()=>{
  const h=await harness();
  try{
    const intent=await h.intent('append-hole',h.request);
    for(const action of ['open','begin']){
      assert.equal((await intent.cycle()).state,'broadcast');
      assert.equal(rows(intent.journalPath).at(-1).plan.action,action);
      assert.equal((await intent.cycle()).state,'finalized');
    }
    h.rpc.control.mode='lost-ack';
    const sent=await intent.cycle();assert.equal(sent.state,'unacknowledged');
    const packet=rows(intent.journalPath).at(-1);assert.equal(packet.plan.action,'append');
    const landed=await h.rpc.records.get(packet.signed.signature);assert.equal(landed.meta.fee,5000n);
    await h.bridge.ask({method:'advance_clock',seconds:3600});
    h.rpc.control.mode='normal';
    const canceller=await h.intent('other-keeper',h.request);
    assert.equal((await canceller.cycle()).state,'broadcast');
    assert.equal(rows(canceller.journalPath).at(-1).plan.action,'cancel');
    assert.equal((await canceller.cycle()).state,'finalized');
    h.rpc.control.hideHistory=true;h.rpc.control.historyCovered=true;
    const result=await intent.cycle();assert.equal(result.state,'expired');
    assert.equal(BigInt(result.spentLamports)-BigInt(sent.spentLamports),BigInt(JSON.parse(packet.quote).maxDebitLamports),
      'oldest available block is not complete history; absent mutable effect cannot erase spent fees');
  }finally{await h.close();}
});
