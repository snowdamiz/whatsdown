import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { createKeyPairSignerFromPrivateKeyBytes, getTransactionDecoder, getCompiledTransactionMessageDecoder } from '@solana/kit';
import { prepareRelayTransactions, signRelayStep, relayStepMessage, relayStepEffect } from './transactions.mjs';

const addresses=await Promise.all(Array.from({length:24},async(_,index)=>(await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(index+1))).address));
const [payer,program,log,usdc,morse,stage,receipt]=addresses;
const SYSTEM='11111111111111111111111111111111',TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const pins={program,log,mint:usdc,usdcMint:usdc,morseMint:morse,submitter:payer};
const wire=Buffer.alloc(452,7),fullHash=createHash('sha256').update(wire).digest('hex');
const ix=(keys,data,signers=[],writable=[])=>({schemaVersion:1,programId:program,accountCount:keys.length,accountKeys:keys,signerKeys:signers,writableKeys:writable,dataBase64:data.toString('base64'),dataBytes:data.length});
function plan(reason,instructions,rent=[]){return {schema_version:2,status:'ready',program,log,submitter:payer,usdc_mint:usdc,morse_mint:morse,proof_hex:wire.toString('hex'),proof_hash:'ab'.repeat(32),finder:payer,receipt,context_slot:'400',stage:{address:stage,full_hash:fullHash},operation:{reason,instructions,rent_allocations:rent}};}
function initial(){const data=Buffer.alloc(35);data[0]=10;data.writeUInt16LE(wire.length,1);Buffer.from(fullHash,'hex').copy(data,3);return plan('initialize_proof_stage',[ix([payer,log,stage,SYSTEM],data,[payer],[payer,stage])],[{address:stage,space:10000}]);}
const admit=p=>prepareRelayTransactions(p,{...pins,proofHex:p.proof_hex});

test('existing relay Kit admission executes a versioned Mesh MPR2 operation with one pinned fee payer',async()=>{
  const p=initial(),prepared=admit(p);assert.equal(prepared.settlement,null);assert.equal(prepared.preparation.length,1);
  const step=prepared.preparation[0],signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));
  const signed=await signRelayStep(step,signer,{blockhash:SYSTEM,lastValidBlockHeight:500n});
  const tx=getTransactionDecoder().decode(Buffer.from(signed.wire,'base64'));
  assert.deepEqual(Object.keys(tx.signatures),[payer]);
  assert.equal(getCompiledTransactionMessageDecoder().decode(tx.messageBytes).instructions[0].data[0],10);
  assert.deepEqual(relayStepMessage(step,{blockhash:SYSTEM,lastValidBlockHeight:500n}).rentAllocations,[{address:stage,space:10000}]);
  assert.equal(relayStepEffect(step,p).reason,'initialize_proof_stage');
});

test('MPR2 settle admits canonical tag44 thirteen fixed accounts plus three per witness',async()=>{
  const keys=[log,addresses[7],addresses[8],receipt,addresses[9],addresses[10],usdc,addresses[11],addresses[12],morse,addresses[13],addresses[14],TOKEN,...addresses.slice(15,18)];
  const writable=keys.filter((_,i)=>![2,6,9,12].includes(i));
  const p=plan('settle_mixed_assets',[ix(keys,Buffer.from([44]),[],writable)]);
  const prepared=admit(p);assert.equal(prepared.preparation.length,0);assert.equal(prepared.settlement.kind,'settle');
  const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));
  const signed=await signRelayStep(prepared.settlement,signer,{blockhash:SYSTEM,lastValidBlockHeight:500n});
  assert.ok(Buffer.from(signed.wire,'base64').length<=1232);
  for(const mutate of [x=>x.operation.instructions[0].accountKeys.splice(13,1),x=>x.operation.instructions[0].accountKeys[6]=morse,x=>x.operation.instructions[0].signerKeys.push(payer),x=>x.operation.instructions[0].dataBase64=Buffer.from([22]).toString('base64')]){
    const bad=structuredClone(p);mutate(bad);assert.throws(()=>admit(bad));
  }
});

test('versioned admission refuses changed mints, proof bytes, payer roles and unauthenticated allocation targets',()=>{
  for(const mutate of [p=>p.usdc_mint=morse,p=>p.morse_mint=usdc,p=>p.stage.full_hash='ff'.repeat(32),p=>p.operation.instructions[0].signerKeys=[program],p=>p.operation.instructions[0].writableKeys=[stage],p=>p.operation.rent_allocations[0].address=receipt,p=>p.operation.reason='settle_mixed_assets']){
    const p=initial();mutate(p);assert.throws(()=>admit(p));
  }
});

test('legacy USDC migration is a permissionless journaled Mesh operation with no token transfer or rent',async()=>{
  const keys=[log,addresses[7],addresses[8],addresses[9],addresses[10]];
  const p=plan('migrate_legacy_bond',[ix(keys,Buffer.from([33,1]),[],[keys[1],keys[3]])]);
  p.operation.effect={schema_version:1,full_hash:p.stage.full_hash,reason:'migrate_legacy_bond',bond:keys[3]};
  const prepared=admit(p),step=prepared.preparation[0];
  assert.equal(step.kind,'migrate');assert.equal(step.id,`migrate/${keys[3]}`);
  assert.deepEqual(relayStepEffect(step,p).meshEffect,p.operation.effect);
  const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));
  const signed=await signRelayStep(step,signer,{blockhash:SYSTEM,lastValidBlockHeight:500n});
  const tx=getTransactionDecoder().decode(Buffer.from(signed.wire,'base64'));
  assert.deepEqual(Object.keys(tx.signatures),[payer]);
  assert.deepEqual(relayStepMessage(step,{blockhash:SYSTEM,lastValidBlockHeight:500n}).rentAllocations,[]);
});

test('prepared winner payout setup preserves the requested finder and pays the authenticated winner in both pinned assets',()=>{
  const winner=addresses[19],locked=addresses[20],destinations=addresses.slice(7,11);
  const setup=destinations.map((destination,index)=>({...ix([payer,destination,index%2?locked:winner,index<2?usdc:morse,SYSTEM,TOKEN],Buffer.from([1]),[payer],[payer,destination]),programId:'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'}));
  const p=plan('payout_accounts',setup,destinations.map(address=>({address,space:165})));p.payout_finder=winner;
  const prepared=admit(p);assert.equal(prepared.preparation[0].kind,'setup');assert.equal(p.finder,payer);assert.notEqual(p.finder,p.payout_finder);
  const wrong=structuredClone(p);wrong.operation.instructions[2].accountKeys[2]=payer;assert.throws(()=>admit(wrong),/payout|account shape/);
  const mint=structuredClone(p);mint.operation.instructions[2].accountKeys[3]=usdc;assert.throws(()=>admit(mint),/account shape/);
});
