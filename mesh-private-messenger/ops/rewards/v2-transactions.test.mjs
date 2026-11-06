import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { prepareRewardsTransaction, rewardsMessage } from './transactions.mjs';

// Reused Rust/SBF vectors, not fresh bank execution. The executable proof also
// exercises these reports from freshly authenticated local-bank reads.
const root = JSON.parse(readFileSync(process.env.MORSE_TOKEN_CUSTODY_FIXTURES_PATH));
const v = root.write_vectors;
const pins = {version:2, program:v.program, judge:v.judge, token:v.token,
  log:v.begin.accountKeys[4], mint:v.mint, morse:v.begin.accountKeys[12], payer:v.payer,
  configuration_hash:'12'.repeat(32)};
function plan(action) {
  const ix = action === 'append' ? v.append[1] : action === 'claim-morse' ? v.claim[0] :
    action === 'claim-usdc' ? v.claim_usdc[0] : v[action];
  const setup = action === 'claim-morse' ? [v.claim_setup] : action === 'claim-usdc' ? [v.claim_usdc_setup] : [];
  const rents = action === 'open' ? [{address:ix.accountKeys[3],space:8416},{address:ix.accountKeys[4],space:1280}] :
    action === 'finalize' ? [{address:ix.accountKeys[22],space:256}] :
    setup.length ? [{address:setup[0].accountKeys[1],space:165}] : [];
  return {...pins,schema_version:2,status:'ready',action,epoch:v.epoch,context_slot:'100000',
    intent_hash:'ab'.repeat(32),signer_keys:[pins.payer],instructions:[...setup,ix],rent_allocations:rents};
}
test('v2 Kit admits exact Rust open, append31, finalize26 and both fixed-payout claims',()=>{
  for (const action of ['open','begin','append','finalize','cancel','claim-usdc','claim-morse']) {
    const p=plan(action), step=prepareRewardsTransaction(p,pins);
    const message=rewardsMessage(step,{blockhash:'11111111111111111111111111111111',lastValidBlockHeight:100n});
    assert.equal(message.minContextSlot,'100000');
    assert.deepEqual(message.rentAllocations,p.rent_allocations);
  }
});
test('v2 cannot cross a v1 scope or broaden pinned assets, privileges, rent and instruction shape',()=>{
  for(const mutate of [p=>p.schema_version=1,p=>p.token=p.judge,p=>p.morse=p.mint,
    p=>p.configuration_hash='cd'.repeat(32),p=>p.instructions[0].writableKeys.push(p.token),
    p=>p.instructions[0].signerKeys.push(p.payer),p=>p.instructions[0].accountKeys.pop(),
    p=>p.instructions[0].dataBase64='Bw==',p=>p.rent_allocations.push({address:p.payer,space:256})]) {
    const p=structuredClone(plan('append')); mutate(p); assert.throws(()=>prepareRewardsTransaction(p,pins));
  }
  assert.throws(()=>prepareRewardsTransaction(plan('append'),{...pins,version:1}));
});
