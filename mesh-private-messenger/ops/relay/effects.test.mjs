import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { prepareRelayTransactions } from './transactions.mjs';
import { createRelayEffectReader } from './effects.mjs';

const path=process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH;
if(!path)throw new Error('Run scripts/prove-relay-writer.sh for fresh plans');
const plans=(await readFile(path,'utf8')).trim().split('\n').map(JSON.parse);
const floor='9007199254740993';

test('every prepared effect is resolved from the correct Mesh reader with the expiry context floor',async()=>{
  let total=0;
  for(const plan of plans){
    const prepared=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex}),job={proofHash:plan.proof_hash,plan};
    let calls=[],stage={status:'missing',received_bytes:0,sealed:false,verified:[]},destinations={finder:{status:'missing'},locked:{status:'missing'}},lookup={status:'missing',addresses:[]},receipt={status:'missing'};
    const reader=(kind,result)=>async(p,minimum,options)=>{assert.equal(p.proof_hash,plan.proof_hash);assert.equal(minimum,floor);calls.push({kind,options});return {...result(),context_slot:floor,contextSlot:floor};};
    const verifier={stage:reader('stage',()=>stage),destinations:reader('destinations',()=>destinations),lookup:reader('lookup',()=>lookup),receipt:reader('receipt',()=>receipt)};
    const read=createRelayEffectReader(verifier);
    const check=async(step,present,kind)=>{
      const result=await read(job,step,{minContextSlot:floor});
      assert.deepEqual(result,{state:present?'present':'absent',slot:floor});const call=calls.pop();assert.equal(call.kind,kind);
      if(kind==='lookup')assert.equal(call.options.closing,['deactivate-table','close-table'].includes(step.kind));total++;
    };
    for(const step of prepared.preparation){
      if(step.kind==='initialize'){
        await check(step,false,'stage');stage.status='uploading';await check(step,true,'stage');
      }else if(step.kind==='append'){
        const chunk=Buffer.from(plan.stage.append_hex[Number(step.id.split('/')[1])],'hex'),end=chunk.readUInt16LE(1)+chunk.length-3;
        stage.received_bytes=end-1;await check(step,false,'stage');stage.received_bytes=end;await check(step,true,'stage');
      }else if(step.kind==='seal'){
        await check(step,false,'stage');stage.sealed=true;stage.status='sealed';await check(step,true,'stage');
      }else if(step.kind==='verify'){
        stage.verified=[];await check(step,false,'stage');
        stage.verified=plan.stage.signatures.map(value=>({ordinal:value.ordinal,public_key:value.ed25519_hex.slice(32,96)}));
        await check(step,true,'stage');
        stage.verified=stage.verified.map(value=>({...value,public_key:'00'.repeat(32)}));
        await assert.rejects(read(job,step,{minContextSlot:floor}),/key/i);
      }else{
        const key=step.id==='setup/0'?'finder':'locked';await check(step,false,'destinations');destinations[key].status='ready';await check(step,true,'destinations');
      }
    }
    await check(prepared.settlement,false,'receipt');receipt.status='settled';await check(prepared.settlement,true,'receipt');
    stage.status='sealed';await check(prepared.cleanup[0],false,'stage');stage.status='missing';await check(prepared.cleanup[0],true,'stage');
    if(prepared.needsLookup){
      await check(prepared.lookup[0],false,'lookup');lookup.status='extending';await check(prepared.lookup[0],true,'lookup');
      let end=0;
      for(const [index,step] of prepared.lookup.slice(1).entries()){
        const ix=Buffer.from(plan.lookup.extend[index].dataBase64,'base64');end+=Number(ix.readBigUInt64LE(4));
        lookup.addresses=plan.lookup.addresses.slice(0,end-1);await check(step,false,'lookup');lookup.addresses=plan.lookup.addresses.slice(0,end);await check(step,true,'lookup');
      }
      lookup.status='ready';await check(prepared.cleanup[1],false,'lookup');
      for(const state of ['cooling','closable','missing']){lookup.status=state;await check(prepared.cleanup[1],true,'lookup');}
      lookup.status='closable';await check(prepared.cleanup[2],false,'lookup');lookup.status='missing';await check(prepared.cleanup[2],true,'lookup');
    }
    await assert.rejects(read({...job,plan:{...plan,receipt:plan.program}},prepared.settlement,{minContextSlot:floor}),/plan/i);
    await assert.rejects(read(job,{...prepared.settlement},{minContextSlot:floor}),/prepared/i);
    const stale=createRelayEffectReader({...verifier,receipt:async()=>({status:'missing',context_slot:'0'})});
    await assert.rejects(stale(job,prepared.settlement,{minContextSlot:floor}),/context/i);
    const offline=createRelayEffectReader({...verifier,receipt:async()=>{throw new Error('unavailable');}});
    await assert.rejects(offline(job,prepared.settlement,{minContextSlot:floor}),/unavailable/);
  }
  assert.ok(total>400);
});
