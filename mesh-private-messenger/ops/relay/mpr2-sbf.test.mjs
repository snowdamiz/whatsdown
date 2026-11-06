import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressDecoder, getAddressEncoder, getProgramDerivedAddress,
  getBase58Encoder, getSignatureFromTransaction, getTransactionDecoder, getCompiledTransactionMessageDecoder } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { RelayJournal } from './journal.mjs';
import { connectRelayRpc } from './rpc.mjs';
import { createRelayScheduler } from './scheduler.mjs';
import { createRelayVerifier } from './verifier.mjs';
import { createRelayService } from './service.mjs';

const required=name=>{assert.ok(process.env[name],`Missing ${name}; run scripts/prove-mpr2-relay.sh`);return process.env[name];};
const run=promisify(execFile),hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const originalBytes=await readFile(required('MORSE_TOKEN_CUSTODY_FIXTURES_PATH'));
assert.equal(hash(originalBytes),'448e6668036e6dd2184bc7a4fd60e2740545b1270ba070c59858c9bb7eb196b5');
const original=JSON.parse(originalBytes),vectorBytes=await readFile(required('MORSE_MPR2_RELAY_VECTORS_PATH'));
assert.equal(hash(vectorBytes),'6c34a4b1979a3d6518d165f26e1467a1251b48446db5d9e988d1cf7d91c7aa97');
const vectors=JSON.parse(vectorBytes).cases;
const binary=process.env.MORSE_MPR2_RELAY_BINARY,bridgeBinary=required('MORSE_MPR2_RELAY_SBF_BRIDGE');
const output=required('MORSE_MPR2_RELAY_PROOF_OUTPUT');await mkdir(output,{recursive:true});
const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(203));
const decoder=getAddressDecoder(),encoder=getAddressEncoder();
const TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',ATA='ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const addr=bytes=>decoder.decode(bytes),raw=value=>Buffer.from(value.data_hex,'hex');
const pda=async(programAddress,seeds)=>(await getProgramDerivedAddress({programAddress,seeds}))[0];
const associated=(owner,mint)=>pda(ATA,[encoder.encode(owner),encoder.encode(TOKEN),encoder.encode(mint)]);
const privateKey=seed=>createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,seed)]),format:'der',type:'pkcs8'});
function currentEvidence(previous,now){
  const wire=Buffer.from(previous),checkpoints=[];
  for(const [index,offset] of [69,258].entries()){
    const cp=wire.subarray(offset,offset+188);cp.writeBigUInt64BE(BigInt(now)*1000n-BigInt(1000-index*1000),84);
    const version=Buffer.alloc(2);version.writeUInt16BE(cp[0]);
    const statement=Buffer.concat([Buffer.from('mesh-key-transparency-v1'),version,cp.subarray(4,124)]);
    const signature=sign(null,statement,privateKey(11));signature.copy(cp,124);
    checkpoints.push(Buffer.from(hash(Buffer.concat([Buffer.from('mesh-msg/v1/transparency-checkpoint'),statement,signature])),'hex'));
  }
  const count=wire[446];let cursor=447;
  for(let index=0;index<count;index++){
    const length=wire[cursor++],id=wire.subarray(cursor,cursor+length);cursor+=length;
    const cp=checkpoints[index<count/2?0:1];cp.copy(wire,cursor);cursor+=32;
    if(wire[0]===3){assert.equal(wire[cursor++],0);}
    const name=id.toString(),seed=name==='outside'?12:name==='token-outside'?15:40+Number(name.slice('additional-'.length));
    assert.ok(Number.isSafeInteger(seed));sign(null,Buffer.concat([Buffer.from('mesh-msg/v1/transparency-witness'),id,cp]),privateKey(seed)).copy(wire,cursor);cursor+=64;
  }
  assert.equal(cursor,wire.length);return wire;
}

class Bridge{
  constructor(){
    this.child=spawn(bridgeBinary,[],{stdio:['pipe','pipe','pipe'],env:process.env});this.errors='';
    this.child.stderr.on('data',data=>this.errors+=data);this.child.on('error',error=>this.errors+=error.stack);
    this.exit=once(this.child,'exit');this.lines=createInterface({input:this.child.stdout})[Symbol.asyncIterator]();this.queue=Promise.resolve();
  }
  ask(request){
    const result=this.queue.then(async()=>{
      this.child.stdin.write(JSON.stringify(request)+'\n');let timer;
      try{
        const line=await Promise.race([this.lines.next(),new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error('SBF bridge timeout '+this.errors)),30000))]);
        assert.equal(line.done,false,this.errors);return JSON.parse(line.value);
      }finally{clearTimeout(timer);}
    });this.queue=result.catch(()=>{});return result;
  }
  async close(){if(this.child.exitCode===null)this.child.kill('SIGKILL');await this.exit;}
}

// Snapshots supply initialized custody only. The receipt, stage and four payout
// accounts are absent in the fresh bank; execution cannot pass via seeded effects.
async function fixture(count=2,{settled=false}={}){
  const snapshot=structuredClone(original.snapshots.find(row=>row.name===`mixed-proof-${settled?'settled':'prepared'}`));
  const row=vectors.find(row=>row.tag===41&&row.success&&row.anchor_generation===null&&row.keys.length===count&&row.clock_time===snapshot.now);
  assert.ok(row,`missing ${count}-target before-state vector`);
  const accounts=snapshot.accounts,known=new Set(Object.values(accounts).map(value=>value.address));
  for(const [address,value] of Object.entries(row.accounts)){
    if(known.has(address)||value.missing||value.executable||value.owner==='BPFLoaderUpgradeab1e11111111111111111111111')continue;
    accounts[address]={...value,address};
  }
  if(count===16){
    // The maximum bank also contains later top-ups and pending balances. Keep
    // all custody roles coherent with its exact pre-prepare aggregate.
    for(const [role,value] of Object.entries(accounts)){
      const before=row.accounts[value.address];
      if(before&&!before.missing&&!before.executable&&!['judge_data','token_data','rewards_data','proof'].includes(role))accounts[role]={...before,address:value.address};
    }
  }
  if(!settled)snapshot.now=String(Math.floor(Date.now()/1000));
  const wire=settled?Buffer.from(row.wire_hex,'hex'):currentEvidence(Buffer.from(row.wire_hex,'hex'),snapshot.now);
  const proofHash=hash(Buffer.concat([wire.subarray(0,5),wire.subarray(37)]));
  const receipt=await pda(snapshot.program,[Buffer.from('proof'),Buffer.from(snapshot.log_id,'hex'),Buffer.from(proofHash,'hex')]);
  const stage=await pda(snapshot.program,[Buffer.from('stage'),encoder.encode(signer.address),Buffer.from(hash(wire),'hex')]);
  const locked=await pda(snapshot.program,[Buffer.from('locked'),Buffer.from(snapshot.log_id,'hex')]);
  const finder=addr(wire.subarray(5,37)),mints=[accounts.usdc.address,accounts.morse.address];
  const destinations=await Promise.all([finder,locked].flatMap(owner=>mints.map(mint=>associated(owner,mint))));
  const excluded=new Set([stage,...destinations,...(!settled?[receipt]:[])]);
  for(const [role,value] of Object.entries(accounts)){
    if(excluded.has(value.address)||(!settled&&role==='proof')||raw(value.missing?{data_hex:''}:value).subarray(0,4).equals(Buffer.from('MST\x01')))delete accounts[role];
  }
  const log=raw(accounts.log),oracle=raw(accounts.oracle),pool=raw(accounts.pool);
  const configuration={schema_version:1,judge:snapshot.program,token:snapshot.token_program,rewards:snapshot.rewards_program,
    log_name:snapshot.log_name,usdc_mint:mints[0],morse_mint:mints[1],submitter:signer.address,fee_payer:signer.address,
    governance:row.governance,
    token_governance:addr(raw(accounts.token_config).subarray(4,36)),service_public_key:log.subarray(72,104).toString('hex'),log_version:log[4],
    network_started:pool.readBigUInt64LE(164).toString(),judge_slot:raw(accounts.judge_data).readBigUInt64LE(4).toString(),
    token_slot:raw(accounts.token_data).readBigUInt64LE(4).toString(),rewards_slot:raw(accounts.rewards_data).readBigUInt64LE(4).toString(),
    source_program:addr(oracle.subarray(68,100)),source:addr(oracle.subarray(100,132)),feed:oracle.subarray(132,164).toString('hex'),
    source_revision:oracle.readBigUInt64LE(292).toString(),witnesses:row.keys};
  return {snapshot,row,wire,proofHash,receipt,stage,finder,locked,mints,destinations,configuration};
}

function rpcAccount(value,config={}){
  if(!value||value.lamports==='0')return null;
  const data=raw(value),slice=config.dataSlice;
  return {owner:value.owner,lamports:BigInt(value.lamports),executable:value.executable,rentEpoch:0n,space:BigInt(data.length),
    data:[(slice?data.subarray(Number(slice.offset),Number(slice.offset)+Number(slice.length)):data).toString('base64'),'base64']};
}

async function oracle(bridge,f){
  const servers=[],endpoints=[],errors=[],calls=[],records=new Map(),packets=[];
  const control={mode:'normal',hideHistory:false,blockHeight:0n,firstAvailableBlock:0n,phaseModes:{prepare:'drop',settle:'drop'}},genesis='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
  // One in-flight execution per signature across concurrent RPC transports.
  async function execute(wire){
    const transaction=getTransactionDecoder().decode(Buffer.from(wire,'base64')),signature=getSignatureFromTransaction(transaction);
    if(!records.has(signature))records.set(signature,(async()=>{
      const context=await bridge.ask({method:'read_context'}),execution=await bridge.ask({method:'send',wire});
      if(!execution.ok){
        const message=getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
        const keys=[...message.staticAccounts,...execution.loaded_addresses.writable,...execution.loaded_addresses.readonly];
        const accounts=await Promise.all(keys.map(async address=>({address,...await bridge.ask({method:'account',address})})));
        await writeFile(join(output,`bank-failure-${f.row.keys.length}.json`),JSON.stringify({wire,execution,message,accounts},(_,v)=>typeof v==='bigint'?String(v):v,2)+'\n');
      }
      assert.equal(execution.ok,true,JSON.stringify(execution));packets.push({wire,execution});
      return {slot:BigInt(context.slot),version:0n,transaction:[wire,'base64'],meta:{err:null,fee:BigInt(execution.fee),
        preBalances:execution.pre_balances.map(BigInt),postBalances:execution.post_balances.map(BigInt),loadedAddresses:execution.loaded_addresses}};
    })());
    await records.get(signature);return signature;
  }
  for(let origin=0;origin<3;origin++){
    const server=createServer(async(req,res)=>{
      try{
        const parts=[];for await(const part of req)parts.push(part);
        const call=parseJsonWithBigInts(Buffer.concat(parts).toString()),args=call.params??[];
        const state=await bridge.ask({method:'read_context'}),slot=BigInt(state.slot);let result;
        calls.push({origin,method:call.method});
        switch(call.method){
          case 'getGenesisHash':result=genesis;break;
          case 'getLatestBlockhash':result={context:{slot},value:{blockhash:state.blockhash,lastValidBlockHeight:BigInt(state.lastValidBlockHeight)}};break;
          case 'getFeeForMessage':result={context:{slot},value:25000n};break;
          case 'getMinimumBalanceForRentExemption':result=BigInt((await bridge.ask({method:'rent',space:Number(args[0])})).lamports);break;
          case 'getAccountInfo':case 'getMultipleAccounts':{
            const options=args[1];assert.equal(options.commitment,'finalized');assert.ok(options.minContextSlot<=slot);
            const keys=call.method==='getAccountInfo'?[args[0]]:args[0];
            const values=await Promise.all(keys.map(async address=>rpcAccount(await bridge.ask({method:'account',address}),options)));
            result={context:{slot},value:call.method==='getAccountInfo'?values[0]:values};break;
          }
          case 'getProgramAccounts':{
            const options=args[1];assert.equal(args[0],f.snapshot.program);assert.equal(options.commitment,'finalized');
            const value=[];
            for(const source of Object.values(f.snapshot.accounts)){
              const current=await bridge.ask({method:'account',address:source.address});if(!current||current.owner!==args[0])continue;
              const bytes=raw(current);
              if((options.filters??[]).some(filter=>filter.dataSize!==undefined?Number(filter.dataSize)!==bytes.length:
                !bytes.subarray(Number(filter.memcmp.offset),Number(filter.memcmp.offset)+getBase58Encoder().encode(filter.memcmp.bytes).length)
                  .equals(Buffer.from(getBase58Encoder().encode(filter.memcmp.bytes)))))continue;
              value.push({pubkey:source.address,account:rpcAccount(current,options)});
            }
            result={context:{slot},value};break;
          }
          case 'sendTransaction':{
            const tx=getTransactionDecoder().decode(Buffer.from(args[0],'base64'));
            const message=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
            const judge=message.instructions.filter(ix=>message.staticAccounts[ix.programAddressIndex]===f.snapshot.program);
            const tag=judge.at(-1)?.data?.[0],phase=tag===44?'settle':[41,42,43].includes(tag)?'prepare':null;
            const mode=phase?control.phaseModes[phase]:control.mode;
            if(mode==='drop'){res.writeHead(503).end();return;}
            result=await execute(args[0]);
            if(mode==='lost-ack'){res.writeHead(503).end();return;}break;
          }
          case 'getSignatureStatuses':{
            const value=control.hideHistory?null:await records.get(args[0][0]);
            result={context:{slot},value:[value?{slot:value.slot,confirmations:null,confirmationStatus:'finalized',err:null}:null]};break;
          }
          case 'getTransaction':result=control.hideHistory?null:(await records.get(args[0]))??null;break;
          case 'getBlockHeight':result=control.blockHeight;break;
          case 'getSlot':result=slot;break;
          case 'getFirstAvailableBlock':result=control.firstAvailableBlock;break;
          default:throw new Error(`Unexpected local RPC ${call.method}`);
        }
        res.writeHead(200,{'content-type':'application/json'});res.end(stringifyJsonWithBigInts({jsonrpc:'2.0',id:call.id,result}));
      }catch(error){errors.push(error.stack);res.writeHead(500).end('local bank failure');}
    });
    server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);endpoints.push(`http://127.0.0.1:${server.address().port}`);
  }
  return {endpoints,errors,calls,packets,control,genesis,async close(){await Promise.all(servers.map(server=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();})));}};
}

async function harness(count=2,options={}){
  const f=await fixture(count,options),directory=await mkdtemp(join(tmpdir(),'mpr2-relay-sbf-')),bridge=new Bridge();let server;
  try{
    const initialized=await bridge.ask({method:'initialize',fixture:f.snapshot,payer:signer.address});
    assert.equal(initialized.signature_verification,true);server=await oracle(bridge,f);
    f.configuration.endpoints=server.endpoints;
    await writeFile(join(output,`bank-input-${count}${options.settled?'-settled':''}.json`),JSON.stringify({fixture:f.snapshot,configuration:f.configuration,wire_hex:f.wire.toString('hex'),proof_hash:f.proofHash,receipt:f.receipt},null,2)+'\n');
    const capturedPins=join(output,`pins-${count}.json`),capturedWire=join(output,`evidence-${count}.frk`),capturedRequest=join(output,`request-${count}.json`);
    await writeFile(capturedPins,JSON.stringify(f.configuration));await writeFile(capturedWire,f.wire);
    await writeFile(capturedRequest,JSON.stringify({schema_version:2,method:'admit',min_context_slot:'0'}));
    const pins={version:2,program:f.snapshot.program,log:f.snapshot.accounts.log.address,mint:f.mints[0],submitter:signer.address,usdcMint:f.mints[0],morseMint:f.mints[1]};
    const plannerConfig=JSON.stringify(f.configuration),tempRoot=join(directory,'native');
    const nativeVerifier=binary?await createRelayVerifier({binary,tempRoot,securityConfig:'owned local fixture',plannerConfig,logVersion:f.configuration.log_version,pins}):null;
    const verifier=nativeVerifier?Object.fromEntries(Object.entries(nativeVerifier).map(([method,read])=>[method,async(...args)=>{
      try{return await read(...args);}catch(error){
        const [value,second,third]=args,request={schema_version:2,method,min_context_slot:method==='admit'?(second??'0'):method==='effect'?(third??'0'):(second??'0')};
        if(method==='effect')request.effect=second.meshEffect??second;
        if(value?.lookup)request.lookup={creation_slot:value.lookup.recent_slot,addresses:value.lookup.addresses};
        if(method==='lookup'&&third?.closing)request.method='lookup-close';
        const path=join(output,`refused-${count}-${method}.json`);await writeFile(path,JSON.stringify(request));
        let detail;try{detail=(await run(binary,['--pins',capturedPins,'--input',capturedWire,'--request',path],{timeout:30000,env:{PATH:'/usr/bin:/bin'}})).stdout;}
        catch(native){detail=String(native.stdout??'')+String(native.stderr??'');}
        await writeFile(join(output,`refused-${count}-${method}.txt`),detail);
        throw new Error(`${method}: ${error.message}; native=${detail.slice(0,2000)}; RPC=${JSON.stringify(server.errors)}`,{cause:error});
      }
    }])):null;
    const journalOptions={path:join(directory,'relay.sqlite'),identity:'local:mpr2-sbf',pins,
      policy:{perJobLamports:'1000000000',windowLamports:'1000000000',maxJobs:1}};
    let journal=new RelayJournal(journalOptions),clock=1000,ordinal=0;
    const transport=await connectRelayRpc({urls:server.endpoints,allowLoopback:true,genesisHash:server.genesis});
    const rpc={...transport,async quote(step,view){await bridge.ask({method:'context'});return transport.quote(step,view);}};
    let scheduler=verifier?createRelayScheduler({journal,verifier,rpc,signer,now:()=>clock++,owner:`worker-${ordinal}`}):null;
    async function restart(){
      const pending=journal.pending();journal.close();journal=new RelayJournal(journalOptions);clock+=30001;
      if(pending)assert.deepEqual(journal.pending().signed,pending.signed,'restart preserves exact signed packet');
      scheduler=createRelayScheduler({journal,verifier,rpc,signer,now:()=>clock++,owner:`worker-${++ordinal}`});
    }
    return {f,bridge,server,initialized,verifier,directory,pins,plannerConfig,
      get journal(){return journal;},get scheduler(){return scheduler;},restart,
      async submit(wire=f.wire){
        const service=createRelayService({journal,verifier,scheduler,now:()=>clock++});
        try{const request=service.submit(wire);await service.cycle();return await request;}finally{await service.close();}
      },
      async tick(){clock+=1001;const value=await scheduler.tick();await writeFile(join(output,`progress-${count}.json`),JSON.stringify({value,plan:journal.jobs()[0]?.plan,pending:journal.pending()},null,2));assert.deepEqual(server.errors,[]);return value;},
      async balance(address){const value=await bridge.ask({method:'account',address});return value&&value.lamports!=='0'?raw(value).readBigUInt64LE(64):0n;},
      async retainJournal(){
        await run('python3',['-c','import sqlite3,sys; source=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True); target=sqlite3.connect(sys.argv[2]); source.backup(target); target.close(); source.close()',
          journalOptions.path,join(output,`journal-${count}.sqlite`)]);
      },
      async admit(wire=f.wire){
        try{const value=await verifier.admit(wire);assert.deepEqual(server.errors,[]);return value;}
        catch(error){
          let diagnosis;
          try{diagnosis=(await run(binary,['--pins',capturedPins,'--input',capturedWire,'--request',capturedRequest],{timeout:30000,env:{PATH:'/usr/bin:/bin'}})).stdout;}
          catch(native){diagnosis=String(native.stdout??'')+String(native.stderr??'');}
          throw new Error(`${error.message}; native=${diagnosis}; RPC=${JSON.stringify(server.errors)}`,{cause:error});
        }
      },
      async close(){await server.close();await bridge.close();journal.close();await rm(directory,{recursive:true,force:true});}};
  }catch(error){await server?.close();await bridge.close();await rm(directory,{recursive:true,force:true});throw error;}
}

test('current compiled relay must authenticate an MPR2 receipt', {skip:!process.env.MORSE_MPR2_BASELINE_BINARY},async()=>{
  const h=await harness(2,{settled:true});
  try{
    const request=join(h.directory,'baseline.json');
    await writeFile(request,JSON.stringify({configuration:{program:h.f.snapshot.program,log_name:h.f.snapshot.log_name,
      service_key:h.f.configuration.service_public_key,version:h.f.configuration.log_version,mint:h.f.mints[0],submitter:signer.address,endpoints:h.server.endpoints},
      mode:'receipt',minimum_slot:'0',proof_hex:h.f.wire.toString('hex')}));
    const result=await run(process.env.MORSE_MPR2_BASELINE_BINARY,[request],{timeout:30000,env:{PATH:'/usr/bin:/bin'}});
    assert.equal(JSON.parse(result.stdout).status,'settled');
  }finally{await h.close();}
});

for(const count of [2,16])test(`fresh ${count}-target relay prepares and settles both assets through Mesh, Kit, SQLite and SBF`, {skip:!binary,timeout:600000},async t=>{
  const h=await harness(count),restarts=[],states=[],faults=new Map(),pruned=[];let pruning=null;
  try{
    assert.equal(await h.bridge.ask({method:'account',address:h.f.receipt}),null,'fresh bank has no prepared or paid proof');
    const sourceAccounts=Object.values(h.f.snapshot.accounts).filter(value=>!value.missing&&value.owner===TOKEN&&raw(value).length===165&&raw(value).readBigUInt64LE(64)>0n);
    const sources=new Map(await Promise.all(sourceAccounts.map(async value=>[value.address,await h.balance(value.address)])));
    const initial=await h.admit();assert.equal(initial.schema_version,2);assert.equal(initial.status,'ready');
    assert.equal(initial.proof_hash,h.f.proofHash);assert.equal(initial.finder,h.f.finder);
    const tables=new Set([initial.lookup?.address].filter(Boolean));
    const accepted=await h.submit();assert.equal(accepted.status,'queued');assert.equal(accepted.proof_hash,h.f.proofHash);
    let prepared=false,complete=false,preparedPlan;
    for(let turn=0;turn<240;turn++){
      const result=await h.tick();states.push(result);
      if(pruning){
        assert.equal(result.state,'effect','expired signed settlement resolves via authenticated Mesh effect with history pruned');
        assert.equal(h.server.packets.length,pruning.packets,'pruned recovery never resends or pays again');
        assert.equal(h.journal.pending(),null,'authenticated effect releases the signed transaction fence');
        const transaction=h.journal.transaction(pruning.pending.id);assert.equal(transaction.phase,'observed');
        assert.equal(transaction.debitLamports,pruning.pending.maxDebitLamports,'unknown historical fee charges the full reservation');
        assert.equal(BigInt(h.journal.budget(900000).chargedLamports),BigInt(pruning.charged)+BigInt(pruning.pending.maxDebitLamports));
        pruned.push({step:'settle',signature:pruning.pending.signed.signature,reserved_lamports:pruning.pending.maxDebitLamports,
          charged_lamports:transaction.debitLamports,block_height:String(h.server.control.blockHeight),
          first_available_block:String(h.server.control.firstAvailableBlock),slot:transaction.observation.slot});
        faults.get('settle').state='reconciled';pruning=null;
        h.server.control.blockHeight=0n;h.server.control.firstAvailableBlock=0n;h.server.control.hideHistory=false;
      }
      const table=h.journal.job(h.f.proofHash).plan.lookup?.address;if(table)tables.add(table);
      if(result.state==='waiting')await h.bridge.ask({method:result.reason==='cooldown'?'retire_lookup_history':'advance'});
      const receipt=await h.bridge.ask({method:'account',address:h.f.receipt});
      if(receipt&&raw(receipt)[7]===0){
        prepared=true;preparedPlan=h.journal.job(h.f.proofHash).plan;
        assert.equal(h.journal.job(h.f.proofHash).receipt,null,'prepared proof is not paid');
        assert.equal((await h.verifier.receipt(preparedPlan)).status,'prepared');
        for(const [address,balance] of sources)assert.equal(await h.balance(address),balance,'preparation transfers no token units');
      }
      const signed=h.journal.pending();
      if(signed&&['prepare','settle'].includes(signed.stepId)){
        const phase=signed.stepId,fault=faults.get(phase);
        if(!fault){
          assert.ok(signed.signed);faults.set(phase,{state:'before',packet:signed.signed});
          restarts.push(`${phase}/before`);await h.restart();h.server.control.phaseModes[phase]='lost-ack';h.server.control.hideHistory=true;
        }else if(fault.state==='before'){
          assert.deepEqual(signed.signed,fault.packet);assert.equal(result.state,'unacknowledged');
          fault.state='after';restarts.push(`${phase}/after`);await h.restart();h.server.control.phaseModes[phase]='normal';
          if(count===2&&phase==='settle'){
            pruning={pending:signed,packets:h.server.packets.length,charged:h.journal.budget(900000).chargedLamports};
            h.server.control.blockHeight=BigInt(signed.signed.lastValidBlockHeight)+1n;
            h.server.control.firstAvailableBlock=BigInt(signed.signed.minContextSlot)+1n;
          }
        }else if(fault.state==='after'){
          assert.deepEqual(signed.signed,fault.packet);fault.state='resent';h.server.control.hideHistory=false;
        }
      }
      if(result.state==='complete'){complete=true;break;}
    }
    assert.equal(complete,true,JSON.stringify(states.slice(-12)));assert.equal(prepared,true);
    assert.deepEqual(restarts.sort(),['prepare/after','prepare/before','settle/after','settle/before']);
    assert.equal(pruned.length,count===2?1:0);
    const job=h.journal.job(h.f.proofHash),receipt=await h.verifier.receipt(job.plan);
    assert.equal(receipt.status,'settled');assert.equal(receipt.receipt.finder,h.f.finder);
    assert.ok(BigInt(receipt.receipt.usdc_slashed_units)>0n);assert.ok(BigInt(receipt.receipt.morse_slashed_units)>0n);
    const [finderUsdc,finderMorse,lockedUsdc,lockedMorse]=await Promise.all(h.f.destinations.map(address=>h.balance(address)));
    assert.equal(finderUsdc,BigInt(receipt.receipt.usdc_finder_units));assert.equal(finderMorse,BigInt(receipt.receipt.morse_finder_units));
    assert.equal(finderUsdc+lockedUsdc,BigInt(receipt.receipt.usdc_slashed_units));assert.equal(finderMorse+lockedMorse,BigInt(receipt.receipt.morse_slashed_units));
    assert.equal(h.journal.pending(),null);assert.deepEqual(h.journal.resources(h.f.proofHash),[]);
    assert.equal(h.journal.budget(900000).reservedLamports,'0');
    const stage=await h.bridge.ask({method:'account',address:h.f.stage});assert.ok(!stage||stage.lamports==='0');
    for(const address of tables){const table=await h.bridge.ask({method:'account',address});assert.ok(!table||table.lamports==='0','actual ALT account rent reclaimed');}
    const lookupAddresses=[...new Set(h.server.packets.flatMap(({execution})=>execution.loaded_addresses.writable.concat(execution.loaded_addresses.readonly)))];
    if(count===16)assert.ok(lookupAddresses.length>0,'maximum proof uses actual lookup-loaded transaction keys');
    for(const {wire,execution} of h.server.packets){assert.ok(Buffer.from(wire,'base64').length<=1232);assert.ok(execution.units<=1400000);}
    const migrationPackets=h.server.packets.filter(({wire})=>{
      const tx=getTransactionDecoder().decode(Buffer.from(wire,'base64')),message=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
      return message.instructions.some(ix=>message.staticAccounts[ix.programAddressIndex]===h.f.snapshot.program&&ix.data?.[0]===33);
    });
    assert.equal(migrationPackets.length,count===2?1:0,'scheduler losslessly migrates the retained legacy USDC bond before settlement');
    const journaled=h.server.packets.map((_,index)=>h.journal.transaction(index+1));
    assert.deepEqual(journaled.map(row=>row.signed.wire),h.server.packets.map(packet=>packet.wire),'every actual SBF packet is journaled');
    for(const {wire} of migrationPackets)assert.ok(journaled.some(row=>row.stepId.startsWith('migrate/')&&row.signed.wire===wire));
    // A receipt remains authenticated without the live custody, oracle or stage.
    // These explicit local removals model source rotation/unbond/cleanup, not a
    // signed on-chain migration, and cannot create a receipt or token balance.
    await h.bridge.ask({method:'remove_accounts',addresses:Object.values(h.f.snapshot.accounts)
      .filter(value=>[h.f.snapshot.program,h.f.snapshot.token_program,h.f.snapshot.rewards_program].includes(value.owner)&&
        value.address!==h.f.snapshot.accounts.log.address&&value.address!==h.f.receipt)
      .map(value=>value.address)});
    assert.deepEqual((await h.verifier.receipt(job.plan)).receipt,receipt.receipt);
    const prior=h.server.packets.length,other=Buffer.from(h.f.wire);encoder.encode(signer.address).forEach((value,index)=>other[5+index]=value);
    const already=await h.admit(other);assert.equal(already.status,'settled');assert.equal(already.settled_receipt.finder,h.f.finder);assert.notEqual(h.f.finder,signer.address);
    assert.equal(h.server.packets.length,prior,'other finder replay spends nothing');
    await h.retainJournal();
    await writeFile(join(output,`case-${count}.json`),JSON.stringify({schema_version:1,targets:count,fixture_sha256:hash(originalBytes),vectors_sha256:hash(vectorBytes),
      reused_initialized_fixture:true,bank_reset:['receipt','stage','payouts'],fresh_signed_execution:true,programs:h.initialized.programs,
      receipt:receipt.receipt,balances:{finderUsdc:String(finderUsdc),finderMorse:String(finderMorse),lockedUsdc:String(lockedUsdc),lockedMorse:String(lockedMorse)},
      restarts,states,pruned_history_recovery:pruned,reclaimed_tables:[...tables],journaled_migrations:migrationPackets.map(packet=>hash(Buffer.from(packet.wire,'base64'))),
      packets:h.server.packets.map(({wire,execution})=>({wire_base64:wire,sha256:hash(Buffer.from(wire,'base64')),bytes:Buffer.from(wire,'base64').length,...execution})),
      rpc_calls:h.server.calls,limits:['Three loopback origins share one bank; no provider independence or validator finality.',
        'Initialized public custody fixture reused; new checkpoints, witness attestations and relay packets signed at current time.',
        'Pruned history and finalized height coverage are explicit local RPC fixture injections, not validator finality.',
        'Source removal is an explicit fixture injection, not signed source rotation or unbond.']},null,2)+'\n');
    t.diagnostic(`${count} targets; ${h.server.packets.length} fresh signed SBF packets; USDC ${finderUsdc+lockedUsdc}; MORSE ${finderMorse+lockedMorse}; prepare/settle restarts ${restarts.length}`);
  }finally{await h.close();}
});

test('actual permanent MPR1 receipts replay through the mixed relay without signing', {skip:!binary,timeout:60000},async()=>{
  const bytes=await readFile(required('MORSE_MPR2_LEGACY_FIXTURES_PATH')),source=JSON.parse(bytes)[3];
  assert.ok(source.receipt_hex.startsWith('4d505201'));
  const f=await fixture(2,{settled:true}),bridge=new Bridge();let server;
  const directory=await mkdtemp(join(tmpdir(),'mpr1-relay-replay-'));
  try{
    const accounts=Object.fromEntries(['judge','judge_data','token','token_data','rewards','rewards_data'].map(role=>[role,f.snapshot.accounts[role]]));
    for(const value of source.accounts)accounts[value.address]=value;
    accounts.log=source.accounts.find(value=>value.data_hex.startsWith('4d4c4701'));
    accounts.proof={address:source.receipt_address,owner:source.program,data_hex:source.receipt_hex,
      executable:false,lamports:'10000000',space:String(source.receipt_hex.length/2)};
    f.snapshot={...f.snapshot,program:source.program,log_id:source.log_id,log_name:source.log_name,accounts};
    f.wire=Buffer.from(source.wire_hex,'hex');f.proofHash=hash(Buffer.concat([f.wire.subarray(0,5),f.wire.subarray(37)]));
    await bridge.ask({method:'initialize',fixture:f.snapshot,payer:signer.address});server=await oracle(bridge,f);
    const log=raw(accounts.log),configuration={...f.configuration,judge:source.program,log_name:source.log_name,usdc_mint:source.mint,
      service_public_key:source.service_key,log_version:log[4],endpoints:server.endpoints};
    const pins={program:source.program,log:accounts.log.address,mint:source.mint,usdcMint:source.mint,morseMint:f.mints[1],submitter:signer.address};
    const verifier=await createRelayVerifier({binary,tempRoot:join(directory,'native'),securityConfig:'owned MPR1 receipt bank',
      plannerConfig:JSON.stringify(configuration),logVersion:log[4],pins});
    const before=await bridge.ask({method:'account',address:source.receipt_address});
    assert.equal(before.data_hex,source.receipt_hex);
    const admitted=await verifier.admit(f.wire);assert.equal(admitted.status,'settled');
    assert.equal(admitted.settled_receipt.schema_version,1);assert.equal(admitted.settled_receipt.proof_hash,f.proofHash);
    assert.equal(admitted.settled_receipt.finder,source.finder);
    const readback=await verifier.receipt(admitted);assert.equal(readback.status,'settled');assert.deepEqual(readback.receipt,admitted.settled_receipt);
    assert.deepEqual(await bridge.ask({method:'account',address:source.receipt_address}),before);assert.equal(server.packets.length,0);assert.deepEqual(server.errors,[]);
    await writeFile(join(output,'legacy-replay.json'),JSON.stringify({schema_version:1,source_sha256:hash(bytes),source_case:3,receipt:readback.receipt,signed_packets:0},null,2)+'\n');
  }finally{await server?.close();await bridge.close();await rm(directory,{recursive:true,force:true});}
});
