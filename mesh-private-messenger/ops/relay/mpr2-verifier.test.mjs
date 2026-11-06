import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRelayVerifier } from './verifier.mjs';
import { prepareRelayTransactions, relayStepEffect } from './transactions.mjs';
import { pins, plan } from './mpr2-journal-fixture.mjs';

async function fixture(t,mode='valid'){
  const root=await mkdtemp(join(tmpdir(),'mpr2-verifier-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const value=plan();value.operation.effect={schema_version:1,full_hash:value.stage.full_hash,reason:value.operation.reason};
  const configuration={judge:pins.program,usdc_mint:pins.usdcMint,morse_mint:pins.morseMint,
    submitter:pins.submitter,fee_payer:pins.submitter,testPlan:value,mode};
  const binary=join(root,'native verifier');
  await writeFile(binary,`#!${process.execPath}
const fs=require('node:fs'),args=process.argv.slice(2);
if(args.length!==6||args[0]!=='--pins'||args[2]!=='--input'||args[4]!=='--request')process.exit(7);
for(const path of [args[1],args[3],args[5]])if((fs.statSync(path).mode&511)!==384)process.exit(8);
if(process.env.MPR2_TEST_SECRET||process.env.NODE_OPTIONS)process.exit(9);
const config=JSON.parse(fs.readFileSync(args[1])),request=JSON.parse(fs.readFileSync(args[5])),p=config.testPlan;
if(fs.readFileSync(args[3]).toString('hex')!==p.proof_hex)process.exit(10);
if(request.schema_version!==2||request.min_context_slot!==process.env.MORSE_RELAY_MIN_CONTEXT_SLOT)process.exit(11);
p.context_slot=request.min_context_slot;
if(request.method==='admit')console.log(JSON.stringify(p));
else if(request.method==='effect'){
 if(JSON.stringify(request.effect)!==JSON.stringify(p.operation.effect))process.exit(12);
 console.log(JSON.stringify({schema_version:2,state:'present',slot:request.min_context_slot}));
}else if(request.method==='receipt'){
 const receipt={schema_version:2,status:config.mode==='settled'?'settled':'prepared',proof_hash:p.proof_hash,finder:p.finder,usdc_mint:p.usdc_mint,morse_mint:config.mode==='wrong-mint'?p.usdc_mint:p.morse_mint,context_slot:request.min_context_slot};
 console.log(JSON.stringify({schema_version:2,status:receipt.status,address:p.receipt,proof_hash:p.proof_hash,context_slot:request.min_context_slot,receipt}));
}else process.exit(13);
`,{mode:0o700});
  return {value,tempRoot:join(root,'temporary'),binary,configuration};
}
async function open(f){return createRelayVerifier({binary:f.binary,tempRoot:f.tempRoot,securityConfig:'operator-owned security pins',plannerConfig:JSON.stringify(f.configuration),logVersion:2,pins});}

test('MPR2 wrapper privately binds raw evidence, operator pins, full-width context and opaque Mesh effect',async t=>{
  const f=await fixture(t),verifier=await open(f),floor='9007199254740993';
  process.env.MPR2_TEST_SECRET='excluded';t.after(()=>delete process.env.MPR2_TEST_SECRET);
  const p=await verifier.admit(Buffer.from(f.value.proof_hex,'hex'),floor);
  const step=prepareRelayTransactions(p,{...pins,proofHex:p.proof_hex}).preparation[0];
  assert.deepEqual(await verifier.effect(p,relayStepEffect(step,p),floor),{schema_version:2,state:'present',slot:floor});
  assert.equal((await verifier.receipt(p,floor)).status,'prepared');
  assert.deepEqual(await readdir(f.tempRoot),[]);
});

test('MPR2 wrapper keeps prepared and settled typed and rejects a different mint',async t=>{
  for(const mode of ['valid','settled','wrong-mint']){
    const f=await fixture(t,mode),verifier=await open(f);
    if(mode==='wrong-mint')await assert.rejects(verifier.receipt(f.value),/receipt assets/);
    else assert.equal((await verifier.receipt(f.value)).status,mode==='settled'?'settled':'prepared');
  }
});
