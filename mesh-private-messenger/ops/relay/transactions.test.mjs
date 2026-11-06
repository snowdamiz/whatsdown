import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createKeyPairSignerFromPrivateKeyBytes, getTransactionDecoder,
  getCompiledTransactionMessageDecoder } from '@solana/kit';
import { prepareRelayTransactions, relayStepMessageHash, signRelayStep, verifyRelaySignedTransaction } from './transactions.mjs';

const path = process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH;
if (!path) throw new Error('Set MORSE_RELAY_SETTLEMENT_PLANS_PATH to fresh plans from prove-relay-admission.sh');
const plans = (await readFile(path,'utf8')).trim().split('\n').map(JSON.parse);
assert.equal(plans.length,19);
const signer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const lifetime = {blockhash:'11111111111111111111111111111111',lastValidBlockHeight:100n};
const pins = plan => ({program:plan.program,log:plan.log,mint:plan.mint,submitter:signer.address,proofHex:plan.proof_hex});
const view = plan => ({schema_version:1,status:'ready',address:plan.lookup.address,authority:signer.address,addresses:plan.lookup.addresses,
  creationSlot:plan.lookup.recent_slot,
  contextSlot:(BigInt(plan.lookup.recent_slot)+1n).toString(),lastExtendedSlot:plan.lookup.recent_slot,
  deactivationSlot:'18446744073709551615'});
const closeView = plan => ({...view(plan),status:'closable',remainingBlocks:0,
  deactivationSlot:(BigInt(plan.lookup.recent_slot)+1n).toString(),contextSlot:(BigInt(plan.lookup.recent_slot)+515n).toString()});

test('Kit signs every Mesh relay step, patches actual precompile positions, and fits maximum lookup settlements',async () => {
  let maximum = 0;
  for(const plan of plans){
    const prepared=prepareRelayTransactions(plan,pins(plan));
    assert.equal(prepared.proofHash,plan.proof_hash);
    assert.equal(prepared.finder,plan.finder);
    const steps=[...prepared.preparation,...(prepared.needsLookup?prepared.lookup:[]),prepared.settlement,...prepared.cleanup];
    for(const step of steps){
      const lookup=step.kind==='close-table'?closeView(plan):prepared.needsLookup?view(plan):undefined;
      const signed=await signRelayStep(step,signer,lifetime,lookup);
      const raw=Buffer.from(signed.wire,'base64'); assert.ok(raw.length<=1232);
      const tx=getTransactionDecoder().decode(raw);
      await verifyRelaySignedTransaction(signed,relayStepMessageHash(step,lifetime,lookup),signer.address);
      assert.deepEqual(Object.keys(tx.signatures),[signer.address]);
      assert.equal(await crypto.subtle.verify('Ed25519',signer.keyPair.publicKey,tx.signatures[signer.address],tx.messageBytes),true);
      const message=getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
      if(step.kind==='verify'){
        for(let n=0;n<message.instructions.length;n+=2){
          const judge=Buffer.from(message.instructions[n+1].data);
          assert.equal(judge[0],13); assert.equal(judge.readUInt16LE(2),n);
        }
      }
      if(step.kind==='settle'){
        assert.equal(message.instructions.length,2);
        assert.equal(Buffer.from(message.instructions[1].data).toString('base64'),plan.settlement.dataBase64);
        if(prepared.needsLookup) assert.equal(message.addressTableLookups.length,1);
      }
    }
    if(prepared.needsLookup){
      maximum++;
      await assert.rejects(signRelayStep(prepared.settlement,signer,lifetime),/lookup/i);
      for(const bad of [{...view(plan),authority:plan.program},{...view(plan),addresses:[...plan.lookup.addresses].reverse()},
        {...view(plan),contextSlot:plan.lookup.recent_slot},{...view(plan),deactivationSlot:'1'},{...view(plan),status:'extending'}]){
        await assert.rejects(signRelayStep(prepared.settlement,signer,lifetime,bad),/lookup/i);
      }
    }
  }
  assert.ok(maximum>=4);
});

test('lookup closure requires a locally authenticated cooldown decision before hashing or signing',async () => {
  const plan=plans.find(value=>prepareRelayTransactions(value,pins(value)).needsLookup);
  const step=prepareRelayTransactions(plan,pins(plan)).cleanup.find(value=>value.kind==='close-table');
  const good=closeView(plan);
  const signed=await signRelayStep(step,signer,lifetime,good);
  assert.equal(signed.minContextSlot,good.contextSlot,'broadcast preserves the closure observation floor');
  for(const change of [null,{status:'cooling'},{status:'ready'},{status:'missing'},{remainingBlocks:1},
    {remainingBlocks:'0'},{authority:plan.program},{address:plan.program},{creationSlot:'0'},
    {addresses:[...good.addresses].reverse()},{addresses:[...good.addresses,plan.program]},
    {deactivationSlot:'18446744073709551615'},{deactivationSlot:good.contextSlot},
    {lastExtendedSlot:good.contextSlot},{contextSlot:plan.context_slot}]){
    const bad=change===null?undefined:{...good,...change};
    assert.throws(()=>relayStepMessageHash(step,lifetime,bad),/lookup/i);
    await assert.rejects(signRelayStep(step,signer,lifetime,bad),/lookup/i);
  }
  // Interrupted extension can leave any valid prefix, including an empty table.
  for(const addresses of [[],good.addresses.slice(0,1),good.addresses.slice(0,19)]){
    await signRelayStep(step,signer,lifetime,{...good,addresses,lastExtendedSlot:addresses.length?good.lastExtendedSlot:'0'});
  }
  const settle=prepareRelayTransactions(plan,pins(plan)).settlement;
  assert.equal((await signRelayStep(settle,signer,lifetime,view(plan))).minContextSlot,view(plan).contextSlot);
});

test('the signer accepts only locally prepared steps and binds wallet, proof and operator pins',async () => {
  const plan=plans[0];
  for(const field of ['program','log','mint','submitter','proofHex']){
    assert.throws(()=>prepareRelayTransactions(plan,{...pins(plan),[field]:'invalid'}),/pin|proof|address/i);
  }
  const prepared=prepareRelayTransactions(plan,pins(plan));
  await assert.rejects(signRelayStep({...prepared.settlement},signer,lifetime),/prepared/i);
  const wrong=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(99));
  await assert.rejects(signRelayStep(prepared.settlement,wrong,lifetime),/payer/i);
  const modified=structuredClone(plan); modified.setup[0].signerKeys.push(plan.program);
  assert.throws(()=>prepareRelayTransactions(modified,pins(plan)),/signer/i);
  const long=plans.find(value=>value.stage.append_hex.length>1);
  const reordered=structuredClone(long); reordered.stage.append_hex.reverse();
  assert.throws(()=>prepareRelayTransactions(reordered,pins(long)),/upload/i);
});

test('journal authentication rejects wrong messages, forged signatures and noncanonical transaction bytes',async () => {
  const plan=plans[0],prepared=prepareRelayTransactions(plan,pins(plan)),step=prepared.preparation[0];
  const signed=await signRelayStep(step,signer,lifetime),hash=relayStepMessageHash(step,lifetime);
  const other=await signRelayStep(prepared.preparation[1],signer,lifetime);
  await assert.rejects(verifyRelaySignedTransaction({...other,stepId:step.id},hash,signer.address),/reservation/i);
  const otherHash=relayStepMessageHash(step,{...lifetime,blockhash:plan.program});
  await assert.rejects(verifyRelaySignedTransaction(signed,otherHash,signer.address),/reservation/i);
  await assert.rejects(verifyRelaySignedTransaction({...signed,wire:signed.wire+'\n'},hash,signer.address),/bytes/i);
  const trailing=Buffer.concat([Buffer.from(signed.wire,'base64'),Buffer.from([0])]);
  await assert.rejects(verifyRelaySignedTransaction({...signed,wire:trailing.toString('base64')},hash,signer.address),/reservation/i);
});
