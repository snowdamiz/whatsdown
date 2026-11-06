import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getAddressDecoder, getProgramDerivedAddress } from '@solana/kit';
import { createRewardsPlanner } from './planner.mjs';
import { prepareRewardsTransaction } from './transactions.mjs';

const root=JSON.parse(await readFile(process.env.MORSE_TOKEN_CUSTODY_FIXTURES_PATH,'utf8'));
const binary=process.env.MORSE_REWARDS_V2_OPERATOR_BIN;
const address=bytes=>getAddressDecoder().decode(bytes);
function configuration(f,endpoints){
  const bytes=name=>Buffer.from(f.accounts[name].data_hex,'hex');
  const pool=bytes('pool'),log=bytes('log'),token=bytes('token_config'),oracle=bytes('oracle');
  return {schema_version:2,program:f.rewards_program,judge:f.program,token:f.token_program,
    log_name:f.log_name,usdc_mint:f.accounts.usdc.address,governance:address(pool.subarray(4,36)),
    token_governance:address(token.subarray(4,36)),service_key:log.subarray(72,104).toString('hex'),
    log_version:log[4],network_started:pool.readBigUInt64LE(164).toString(),token_slot:'0',judge_slot:'0',rewards_slot:'0',
    source_program:address(oracle.subarray(68,100)),source:address(oracle.subarray(100,132)),
    feed:oracle.subarray(132,164).toString('hex'),source_revision:oracle.readBigUInt64LE(292).toString(),
    endpoints,allow_loopback:true};
}

async function configurationGate(endpoints,allow_loopback){
  const directory=await mkdtemp(join(tmpdir(),'rewards-v2-host-config-'));
  try{
    const f=root.snapshots.find(f=>f.name==='token-rewards-collecting');
    const config={...configuration(f,endpoints),allow_loopback};
    return await promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:JSON.stringify(config)},timeout:5000});
  }finally{await rm(directory,{recursive:true,force:true});}
}

for(const allowLoopback of [false,true]){
  for(const [name,endpoints] of [
    ['localhost root dot',['https://localhost:444/a','https://localhost.:444/b','https://other.example/rpc']],
    ['canonical mapped IPv6',['https://192.0.2.1/rpc','https://[::ffff:c000:201]/rpc','https://other.example/rpc']],
  ]){
    test(`v2 host config refuses ${name} before input or HTTP with allow_loopback=${allowLoopback}`,async()=>{
      await assert.rejects(configurationGate(endpoints,allowLoopback),
        error=>/invalid_anchor_sources/.test(error.stderr)&&!/No such file/.test(error.stderr));
    });
  }
}

test('v2 host config preserves ordinary IPv6 and the explicit loopback port control',async()=>{
  const inputGate=error=>!/invalid_anchor_sources/.test(error.stderr)&&/No such file or directory/.test(error.stderr);
  for(const allowLoopback of [false,true]){
    await assert.rejects(configurationGate([
      'https://[::fffe:c000:201]/rpc','https://[::c000:201]/rpc','https://192.0.2.1/rpc',
    ],allowLoopback),inputGate);
  }
  for(const host of ['localhost','127.0.0.1','[::1]']){
    const endpoints=[444,445,446].map(port=>`https://${host}:${port}/rpc`);
    await assert.rejects(configurationGate(endpoints,false),error=>/invalid_anchor_sources/.test(error.stderr));
    await assert.rejects(configurationGate(endpoints,true),inputGate);
  }
});

test('production v2 executable authenticates snapshots, plans explicit intent and reconciles immutable claims', {timeout:120000},async()=>{
  let selected=root.snapshots.find(f=>f.name==='token-rewards-collecting');
  const initial=selected, errors=[], requests=[];
  let advanceGroups=false;const groupRequests=[0,0,0];
  const [judgeConfig]=await getProgramDerivedAddress({programAddress:initial.program,seeds:[Buffer.from('config')]});
  const governance=Buffer.from(initial.accounts.pool.data_hex,'hex').subarray(4,36);
  const configData=Buffer.concat([Buffer.from('MCF\x01'),governance,Buffer.alloc(4)]);

  const servers=[],endpoints=[];
  const directory=await mkdtemp(join(tmpdir(),'rewards-v2-native-'));
  try{
    for(let index=0;index<3;index++){
      const server=createServer(async(req,res)=>{
        try{
          let body='';for await(const chunk of req)body+=chunk;
          const call=JSON.parse(body);requests.push(call);
          assert.equal(call.method,'getMultipleAccounts');
          assert.equal(call.params[1].commitment,'finalized');
          const group=advanceGroups&&call.params[0][0]===judgeConfig;
          const ordinal=group?++groupRequests[index]:0;
          const slot=Number(selected.context_slot)+ordinal*10;
          assert.ok(call.params[1].minContextSlot<=slot);
          if(group)assert.ok(call.params[1].minContextSlot>=Number(selected.context_slot)+(ordinal-1)*10,'later groups must retain the previous finalized context');
          const accounts=Object.values(selected.accounts);
          const value=call.params[0].map(key=>{
            const a=accounts.find(a=>a.address===key)??(key===judgeConfig?{owner:initial.program,executable:false,lamports:'1000000',space:'40',data_hex:configData.toString('hex')}:null);
            if(!a||a.missing)return null;
            const slice=call.params[1].dataSlice;
            // The stored fixture truncates program data at 8416 bytes. Its
            // omitted tail is zero-extended only in this local replay adapter.
            const raw=Buffer.concat([Buffer.from(a.data_hex,'hex'),Buffer.alloc(Math.max(0,Math.min(Number(a.space),slice.offset+slice.length)-a.data_hex.length/2))]);
            if(group&&key===selected.accounts.clock.address)raw.writeBigUInt64LE(BigInt(slot),0);
            return {owner:a.owner,executable:a.executable,lamports:Number(a.lamports),rentEpoch:0,
              space:Number(a.space),data:[raw.subarray(slice.offset,slice.offset+slice.length).toString('base64'),'base64']};
          });
          res.end(JSON.stringify({jsonrpc:'2.0',id:call.id,result:{context:{slot},value}}));
        }catch(e){errors.push(e);res.writeHead(500).end();}
      });
      server.listen(0,'127.0.0.1');await once(server,'listening');servers.push(server);
      endpoints.push(`http://127.0.0.1:${server.address().port}`);
    }
    const securityConfig=JSON.stringify(configuration(initial,endpoints));
    const pins={version:2,program:initial.rewards_program,judge:initial.program,token:initial.token_program,
      log:initial.accounts.log.address,mint:initial.accounts.usdc.address,morse:initial.accounts.morse.address,
      payer:initial.payer,configuration_hash:createHash('sha256').update(securityConfig).digest('hex')};
    const planner=await createRewardsPlanner({binary,tempRoot:join(directory,'planner'),securityConfig,logVersion:1,pins});
    const request={schema_version:2,program:pins.program,mint:pins.mint,log:initial.log_name,payer:pins.payer,epoch:initial.epoch,action:'settle'};
    // Clear the recorded timer while preserving the authenticated live price.
    // The unassessed below-threshold bond must be assessed during collection.
    selected=structuredClone(initial);
    const unassessed=Buffer.from(selected.accounts.bond1.data_hex,'hex');
    unassessed.writeBigUInt64LE(0n,200);selected.accounts.bond1.data_hex=unassessed.toString('hex');
    const assess=await planner.plan(request);
    assert.equal(assess.action,'assess');
    assert.equal(Buffer.from(assess.instructions.at(-1).dataBase64,'base64')[0],45);
    const report=assess.instructions.at(-1);
    assert.deepEqual(report.signerKeys,[]);assert.equal(report.accountCount,15);
    assert.ok(!report.writableKeys.includes(report.accountKeys[4]),'pending remains readonly');
    for(const change of [
      p=>{const ix=p.instructions.at(-1);ix.dataBase64=Buffer.from([36,1]).toString('base64');},
      p=>p.instructions.at(-1).writableKeys.push(report.accountKeys[4]),
      p=>p.instructions.at(-1).signerKeys.push(report.accountKeys[3]),
      p=>p.rent_allocations.push({address:p.payer,space:96})
    ]){const invalid=structuredClone(assess);change(invalid);assert.throws(()=>prepareRewardsTransaction(invalid,pins));}

    assert.equal((await planner.effect(request,assess,initial.context_slot)).state,'absent');
    selected=initial;
    assert.equal((await planner.effect(request,assess,initial.context_slot)).state,'present');
    selected=structuredClone(initial);
    const lifetime=Buffer.from(selected.accounts.bond1.data_hex,'hex');
    lifetime.writeBigUInt64LE(lifetime.readBigUInt64LE(176)-1n,176);selected.accounts.bond1.data_hex=lifetime.toString('hex');
    assert.equal((await planner.effect(request,assess,initial.context_slot)).state,'absent','another bond lifetime cannot reconcile the old packet');

    // Exact 80%, first crossing, partial recovery and exact full recovery use
    // the recorded lifetime target, which can differ from current policy.
    for(const [price,since,action] of [
      [1200000,0n,'append'],[1199999,0n,'assess'],
      [1400000,BigInt(initial.now),'append'],[1500000,BigInt(initial.now),'assess']
    ]){
      selected=structuredClone(initial);
      const bond=Buffer.from(selected.accounts.bond1.data_hex,'hex');bond.writeBigUInt64LE(since,200);selected.accounts.bond1.data_hex=bond.toString('hex');
      const pending=Buffer.from(selected.accounts.pending1.data_hex,'hex');pending.writeBigUInt64LE(200000001n,84);selected.accounts.pending1.data_hex=pending.toString('hex');
      const oracle=Buffer.from(selected.accounts.oracle.data_hex,'hex'),end=Number(oracle.readBigUInt64LE(164)/3600n);
      oracle.writeBigUInt64LE(BigInt(price),172);
      for(let hour=end-168;hour<end;hour++){
        const at=320+(hour%169)*32;
        oracle.writeBigUInt64LE(BigInt(price)*3600n,at+8);oracle.writeBigUInt64LE(0n,at+16);
      }
      selected.accounts.oracle.data_hex=oracle.toString('hex');
      assert.equal((await planner.plan(request)).action,action,`price=${price} since=${since}`);
    }
    selected=initial;
    const append=await planner.plan(request);
    assert.equal(append.action,'append');assert.equal(append.instructions.at(-1).accountCount,31);
    advanceGroups=true;
    const advancedContext=await planner.plan(request);
    advanceGroups=false;
    assert.equal(advancedContext.context_slot,(BigInt(initial.context_slot)+50n).toString());
    assert.deepEqual(groupRequests,[5,5,0]);

    assert.equal((await planner.effect(request,append,initial.context_slot)).state,'absent');
    selected=root.snapshots.find(f=>f.name==='token-rewards-ready');
    assert.equal((await planner.effect(request,append,initial.context_slot)).state,'present');
    const finalize=await planner.plan(request);assert.equal(finalize.action,'finalize');
    selected=root.snapshots.find(f=>f.name==='token-rewards-finalized');
    assert.equal((await planner.effect(request,finalize,initial.context_slot)).state,'present');
    assert.equal((await planner.plan(request)).status,'complete');
    const range={...request,action:'settle',epoch_count:'2',cursor:request.epoch};
    const completed=await planner.plan(range);
    assert.equal(completed.status,'complete');assert.equal(completed.next_epoch,(BigInt(request.epoch)+1n).toString());
    assert.notEqual(completed.intent_hash,finalize.intent_hash);
    for(const invalid of [
      {...range,epoch_count:2}, {...range,assessment_cursor:'65'}, {...range,assessment_cursor:'01'}, {...range,assessment_cursor:1}, {...range,action:'claim',row:0,asset:0}, {...range,epoch_count:'0'}, {...range,epoch_count:'257'}, {...range,epoch_count:'02'},
      {...range,epoch:'18446744073709551615'}, {...range,cursor:(BigInt(request.epoch)-1n).toString()},
      {...range,cursor:(BigInt(request.epoch)+2n).toString()}
    ])await assert.rejects(planner.plan(invalid));
    await assert.rejects(planner.effect(range,finalize,initial.context_slot),'range is bound separately from explicit settlement');
    const one=await planner.plan({...range,epoch_count:'1'});
    assert.equal(one.next_epoch,null);
    for(const [name,action] of [['floor-unfunded','waiting:token_reserve_cap'],['stale-floor-unfunded','waiting:token_reserve_unavailable'],['expired','cancel']]){
      selected=root.snapshots.find(f=>f.name===`token-rewards-${name}`);
      assert.equal((await planner.plan(range)).action,action);
    }
    selected=structuredClone(root.snapshots.find(f=>f.name==='token-rewards-floor-unfunded'));
    const waitingBond=Buffer.from(selected.accounts.bond1.data_hex,'hex');
    waitingBond.writeBigUInt64LE(0n,200);selected.accounts.bond1.data_hex=waitingBond.toString('hex');
    assert.equal((await planner.plan(range)).action,'assess','reserve waits must continue grace maintenance during collection');
    selected=structuredClone(root.snapshots.find(f=>f.name==='token-rewards-open'));
    const unsealed=Buffer.from(selected.accounts.attendance_epoch.data_hex,'hex');
    unsealed[62]=0;unsealed.writeBigUInt64LE(BigInt(selected.context_slot),52);
    selected.accounts.attendance_epoch.data_hex=unsealed.toString('hex');
    const beforeBegin=Buffer.from(selected.accounts.bond1.data_hex,'hex');
    beforeBegin.writeBigUInt64LE(0n,200);selected.accounts.bond1.data_hex=beforeBegin.toString('hex');
    assert.equal((await planner.plan(range)).action,'assess','cosign waits must continue grace maintenance before collection');
    const pausedConfig=JSON.stringify({...JSON.parse(securityConfig),rewards_slot:'1'});
    const paused=await createRewardsPlanner({binary,tempRoot:join(directory,'paused'),securityConfig:pausedConfig,logVersion:1,
      pins:{...pins,configuration_hash:createHash('sha256').update(pausedConfig).digest('hex')}});
    assert.equal((await paused.plan(range)).action,'waiting:code-pins');
    selected=root.snapshots.find(f=>f.name==='token-rewards-finalized');
    for(const asset of [0,1]){
      const claim={...request,action:'claim',row:17,asset};
      const plan=await planner.plan(claim);assert.equal(plan.action,asset?'claim-morse':'claim-usdc');
      assert.equal((await planner.effect(claim,plan,initial.context_slot)).state,'absent');
      await assert.rejects(planner.effect({...claim,row:1},plan,initial.context_slot));
      selected=root.snapshots.find(f=>f.name==='token-rewards-claimed');
      assert.equal((await planner.effect(claim,plan,initial.context_slot)).state,'present');
      assert.equal((await planner.plan(claim)).status,'complete');
      selected=root.snapshots.find(f=>f.name==='token-rewards-finalized');
    }
    await assert.rejects(planner.plan({...request,action:'fund'}));
    await assert.rejects(planner.plan({...request,epoch:'02828'}));
    const aliased=JSON.stringify({...JSON.parse(securityConfig),endpoints:[`${endpoints[0]}/a`,`${endpoints[0]}/b`,`${endpoints[0]}/c`]});
    const aliasPlanner=await createRewardsPlanner({binary,tempRoot:join(directory,'aliases'),securityConfig:aliased,logVersion:1,
      pins:{...pins,configuration_hash:createHash('sha256').update(aliased).digest('hex')}});
    await assert.rejects(aliasPlanner.plan(request),'three paths on one origin are not three providers');
    const oneHost=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://same.example:444','https://same.example:445','https://same.example:446']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:oneHost},timeout:5000}),
      error=>/invalid_anchor_sources/.test(error.stderr),'hostname aliases must fail before request reads or network access');
    const dotted=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://rpc.example:444/rpc','https://rpc.example.:444/rpc','https://other.example:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:dotted},timeout:5000}),
      error=>/invalid_anchor_sources/.test(error.stderr)&&!/No such file/.test(error.stderr),
      'a trailing DNS dot is the same host and must fail before request reads or network access');
    const distinct=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://a.example:444/rpc','https://b.example.:445/rpc','https://[2001:db8::1]:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:distinct},timeout:5000}),
      error=>!/invalid_anchor_sources/.test(error.stderr)&&/No such file or directory/.test(error.stderr),
      'distinct hosts, including one trailing dot and an IPv6 literal, pass the host check before network access');
    const mixedCase=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://RPC.Example:444/rpc','https://b.example:444/rpc','https://c.example:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:mixedCase},timeout:5000}),
      error=>/invalid_anchor_sources/.test(error.stderr)&&!/No such file/.test(error.stderr),
      'noncanonical host spelling stays rejected before network access');
    const strictLoopback=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://127.0.0.1:444/rpc','https://127.0.0.1:445/rpc','https://127.0.0.1:446/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:strictLoopback},timeout:5000}),
      error=>/invalid_anchor_sources/.test(error.stderr)&&!/No such file/.test(error.stderr),
      'TLS loopback ports cannot count separately when the explicit fixture option is off');
    assert.ok(requests.some(r=>r.params[0].length===26));
    assert.ok(requests.some(r=>r.params[0].length===3));
    assert.deepEqual(errors,[]);
  }finally{
    for(const server of servers){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
    await rm(directory,{recursive:true,force:true});
  }
});
