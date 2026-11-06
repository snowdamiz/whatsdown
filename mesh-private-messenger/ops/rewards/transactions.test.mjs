import assert from 'node:assert/strict';
import test from 'node:test';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { prepareRewardsTransaction, rewardsMessage, signRewardsTransaction, verifyRewardsSigned } from './transactions.mjs';

const payer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const funder = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(12));
const other = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(13));
const system = '11111111111111111111111111111111';
const token = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const keys = (await Promise.all([21,22,23,24,25,26,27,28].map(n => createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(n))))).map(s => s.address);
const pins = {program:keys[0],judge:keys[1],log:keys[2],mint:keys[3],payer:payer.address};
const lifetime = {blockhash:system,lastValidBlockHeight:100n};
function funding() {
  const data=Buffer.alloc(42);data[0]=12;data[1]=1;data.writeBigUInt64LE(500000n,2);data.fill(77,10);
  const accounts=[funder.address,payer.address,keys[4],keys[5],keys[6],keys[7],pins.mint,token,other.address,system];
  return {...pins,schema_version:1,status:'ready',epoch:'99',context_slot:'10',action:'fund',intent_hash:'ab'.repeat(32),
    signer_keys:[payer.address,funder.address],rent_allocations:[{address:other.address,space:192}],
    instructions:[{schemaVersion:1,programId:pins.program,accountCount:10,accountKeys:accounts,
      signerKeys:[funder.address,payer.address],writableKeys:[payer.address,keys[4],keys[5],keys[6],keys[7],other.address],dataBase64:data.toString('base64'),dataBytes:data.length}]};
}

test('rewards signing binds both payer and funding authority to the exact Mesh message',async()=>{
  const plan=funding(),step=prepareRewardsTransaction(plan,pins);
  const info=rewardsMessage(step,lifetime);
  const signed=await signRewardsTransaction(step,[payer,funder],lifetime);
  assert.ok(Buffer.from(signed.wire,'base64').length<=1232);
  await verifyRewardsSigned(signed,info.messageHash,plan.signer_keys);
  await assert.rejects(signRewardsTransaction(step,[payer],lifetime),/signer/i);
  await assert.rejects(signRewardsTransaction(step,[payer,other],lifetime),/signer/i);
  await assert.rejects(signRewardsTransaction({...step},[payer,funder],lifetime),/prepared/i);
  await assert.rejects(verifyRewardsSigned(signed,'00'.repeat(32),plan.signer_keys),/reservation/i);
  await assert.rejects(verifyRewardsSigned({...signed,wire:signed.wire+'AAAA'},info.messageHash,plan.signer_keys),/bytes|reservation/i);
  plan.instructions[0].dataBase64='AA==';
  assert.equal(rewardsMessage(step,lifetime).messageHash,info.messageHash,'prepared recipes cannot be mutated');
});

test('writer rejects legacy funding, unpinned programs, unexpected signers and hidden rent recipients',()=>{
  for(const mutate of [
    p=>p.program=other.address,
    p=>p.instructions[0].programId=other.address,
    p=>{const d=Buffer.from(p.instructions[0].dataBase64,'base64');d[0]=2;p.instructions[0].dataBase64=d.toString('base64');},
    p=>p.instructions[0].signerKeys.push(other.address),
    p=>p.instructions[0].writableKeys.push(system),
    p=>p.rent_allocations[0].address=system,
    p=>p.rent_allocations[0].space=8416,
    p=>p.instructions.push(p.instructions[0]),
    p=>p.context_slot=10,
  ]){
    const plan=funding();mutate(plan);assert.throws(()=>prepareRewardsTransaction(plan,pins));
  }
});
