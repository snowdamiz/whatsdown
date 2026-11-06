import assert from 'node:assert/strict';
import test from 'node:test';
import configure from '../plugins/network-counter-config.cjs';
import {createHash} from 'node:crypto';
const key='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const config=()=>({schema_version:1,mode:'v2',minimum_context_slot:'18446744073709551615',judge_slot:'0',log_version:1,token_program:key,token_slot:'0',token_governance:key,usdc_mint:key,morse_mint:key,rewards_program:key,rewards_slot:'0',rewards_governance:key,network_started:'1700000000'});
const env=x=>({MESSENGER_ANCHOR_LOG_NAME:'morse-main',MESSENGER_NETWORK_COUNTER_CONFIG:JSON.stringify(x)});
test('counter is default off and release frame is bound to exact security bytes without RPC/identity override fields',()=>{
 assert.equal(configure({},''),'');assert.throws(()=>configure({MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH:'/unused'},''));const f=configure(env(config()),'release-pins');const p=f.split('\n');assert.equal(p.length,17);assert.equal(p[1],createHash('sha256').update('release-pins').digest('hex'));assert.equal(p[3],'18446744073709551615');assert.equal(p[16],'1');
 for(const x of [{...config(),rpc_urls:['https://evil.example']},{...config(),witnesses:[]},{...config(),schema_version:2},{...config(),minimum_context_slot:1},{...config(),judge_slot:'01'},{...config(),token_program:'1'.repeat(32)},{...config(),mode:'unknown'}])assert.throws(()=>configure(env(x),'release-pins'));
 assert.throws(()=>configure({...env(config()),MESSENGER_ANCHOR_LOG_NAME:'morse-canary'},'release-pins'));
 assert.throws(()=>configure(env(config()),''));
 const legacy={schema_version:1,mode:'legacy-v1',minimum_context_slot:'1',judge_slot:'2',log_version:1,governance:key,anchor_authority:key,mint:key};assert.equal(configure(env(legacy),'pins').split('\n').length,17);
});


test('counter companion binds every byte of a floor envelope without gaining new authority', () => {
  const old = 'existing-security-profile';
  const wrapped = `6\n2\n${old}`;
  const previous = configure(env(config()), old).split('\n');
  const next = configure(env(config()), wrapped).split('\n');
  assert.equal(next[1], createHash('sha256').update(wrapped).digest('hex'));
  assert.notEqual(next[1], previous[1]);
  assert.deepEqual(next.slice(2), previous.slice(2));
});
