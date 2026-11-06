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
import { getAddressDecoder } from '@solana/kit';
import { createRewardsPlanner } from './planner.mjs';

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

test('production v2 executable authenticates snapshots, plans explicit intent and reconciles immutable claims', {timeout:120000},async()=>{
  let selected=root.snapshots.find(f=>f.name==='token-rewards-collecting');
  const initial=selected, errors=[], requests=[];
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
          assert.ok(call.params[1].minContextSlot<=Number(selected.context_slot));
          const accounts=Object.values(selected.accounts);
          const value=call.params[0].map(key=>{
            const a=accounts.find(a=>a.address===key);
            if(!a||a.missing)return null;
            const slice=call.params[1].dataSlice;
            return {owner:a.owner,executable:a.executable,lamports:Number(a.lamports),rentEpoch:0,
              space:Number(a.space),data:[Buffer.from(a.data_hex,'hex').subarray(slice.offset,slice.offset+slice.length).toString('base64'),'base64']};
          });
          res.end(JSON.stringify({jsonrpc:'2.0',id:call.id,result:{context:{slot:Number(selected.context_slot)},value}}));
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
    const append=await planner.plan(request);
    assert.equal(append.action,'append');assert.equal(append.instructions.at(-1).accountCount,31);
    assert.equal((await planner.effect(request,append,initial.context_slot)).state,'absent');
    selected=root.snapshots.find(f=>f.name==='token-rewards-ready');
    assert.equal((await planner.effect(request,append,initial.context_slot)).state,'present');
    const finalize=await planner.plan(request);assert.equal(finalize.action,'finalize');
    selected=root.snapshots.find(f=>f.name==='token-rewards-finalized');
    assert.equal((await planner.effect(request,finalize,initial.context_slot)).state,'present');
    assert.equal((await planner.plan(request)).status,'complete');
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
      error=>/rewards_v2_source_hosts/.test(error.stderr),'hostname aliases must fail before request reads or network access');
    const dotted=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://rpc.example:444/rpc','https://rpc.example.:444/rpc','https://other.example:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:dotted},timeout:5000}),
      error=>/rewards_v2_source_hosts/.test(error.stderr)&&!/No such file/.test(error.stderr),
      'a trailing DNS dot is the same host and must fail before request reads or network access');
    const distinct=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://a.example:444/rpc','https://b.example.:445/rpc','https://[2001:db8::1]:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:distinct},timeout:5000}),
      error=>!/rewards_v2_source_hosts/.test(error.stderr)&&/No such file or directory/.test(error.stderr),
      'distinct hosts, including one trailing dot and an IPv6 literal, pass the host check before network access');
    const mixedCase=JSON.stringify({...JSON.parse(securityConfig),allow_loopback:false,
      endpoints:['https://RPC.Example:444/rpc','https://b.example:444/rpc','https://c.example:444/rpc']});
    await assert.rejects(promisify(execFile)(binary,['--input',join(directory,'missing.json')],
      {env:{MORSE_REWARDS_V2_CONFIG:mixedCase},timeout:5000}),
      error=>/invalid_anchor_sources/.test(error.stderr)&&!/No such file/.test(error.stderr),
      'noncanonical host spelling stays rejected before network access');
    assert.ok(requests.some(r=>r.params[0].length===26));
    assert.ok(requests.some(r=>r.params[0].length===3));
    assert.deepEqual(errors,[]);
  }finally{
    for(const server of servers){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
    await rm(directory,{recursive:true,force:true});
  }
});
