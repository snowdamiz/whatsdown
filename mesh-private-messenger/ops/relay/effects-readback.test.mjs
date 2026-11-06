import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { prepareRelayTransactions } from './transactions.mjs';
import { createRelayEffectReader } from './effects.mjs';

for(const name of ['MORSE_RELAY_SETTLEMENT_PLANS_PATH','MORSE_RELAY_EFFECT_REPORTS_PATH']){
  if(!process.env[name])throw new Error(`Missing ${name}; run scripts/prove-relay-writer.sh`);
}
const plans=(await readFile(process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH,'utf8')).trim().split('\n').map(JSON.parse);
const reports=(await readFile(process.env.MORSE_RELAY_EFFECT_REPORTS_PATH,'utf8')).trim().split('\n').map(JSON.parse);

test('phase effect selection dogfoods actual Mesh-authenticated SBF Stage, lookup, destination and receipt reports',async()=>{
  const counts={stage:0,lookup:0,settlement:0};let decisions=0;
  for(const report of reports){
    const plan=plans.find(value=>value.proof_hex===report.proof_hex&&value.log===report.log);assert.ok(plan);
    const prepared=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex}),job={proofHash:plan.proof_hash,plan};
    const all=[...prepared.preparation,...prepared.lookup,prepared.settlement,...prepared.cleanup];
    const view=report[report.type==='settlement'?'receipt':report.type];
    const floor=view.context_slot??view.contextSlot;
    const verifier=Object.fromEntries(['stage','lookup','receipt','destinations'].map(kind=>[kind,async(value,minimum)=>{
      assert.equal(value.proof_hex,plan.proof_hex);assert.equal(minimum,floor);assert.ok(report[kind],`unexpected ${kind} reader`);return report[kind];
    }]));
    const read=createRelayEffectReader(verifier);
    async function check(id,present){
      const step=all.find(value=>value.id===id);assert.ok(step,id);
      assert.deepEqual(await read(job,step,{minContextSlot:floor}),{state:present?'present':'absent',slot:floor},`${report.type} ${plan.proof_hash} ${id}`);decisions++;
    }
    if(report.type==='stage')await check(report.step_id,true);
    else if(report.type==='lookup')await check(report.step_id==='before-create'?'create-table':report.step_id,report.step_id!=='before-create');
    else if(report.type==='settlement'){
      await check('setup/0',report.step_id!=='before-setup');
      await check('setup/1',['setup/1','settle'].includes(report.step_id));
      await check('settle',report.step_id==='settle');
    }else assert.fail(`unknown report ${report.type}`);
    counts[report.type]++;
  }
  assert.deepEqual(counts,{stage:190,lookup:42,settlement:76});
  assert.equal(decisions,460);
});
