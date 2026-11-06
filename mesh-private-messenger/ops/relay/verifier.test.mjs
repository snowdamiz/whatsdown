import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, readdir, readFile, stat, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRelayVerifier } from './verifier.mjs';

const path=process.env.MORSE_RELAY_SETTLEMENT_PLANS_PATH;
if(!path)throw new Error('Run scripts/prove-relay-writer.sh for fresh Mesh plans');
const plans=(await readFile(path,'utf8')).trim().split('\n').map(JSON.parse),plan=plans[0];
const pins=Object.fromEntries(['program','log','mint','submitter'].map(key=>[key,plan[key]]));
async function fixture(t,body){
  const root=await mkdtemp(join(tmpdir(),'morse-verifier-wrapper-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const binary=join(root,'native verifier');
  await writeFile(binary,`#!${process.execPath}\n${body}\n`,{mode:0o700});
  const temporary=join(root,'work');
  return {root,binary,tempRoot:temporary,securityConfig:JSON.stringify(plan),logVersion:2,pins};
}

test('the subprocess wrapper binds local configuration, stages private bounded bytes, and removes them after success',async t=>{
  const config=await fixture(t,`
    const fs=require('node:fs');const args=process.argv.slice(2),plan=JSON.parse(process.env.MESSENGER_SECURITY_CONFIG);
    if(process.env.RELAY_TEST_SECRET||process.env.NODE_OPTIONS)process.exit(9);
    if(process.env.MORSE_RELAY_LOG_VERSION!=='2'||process.env.MORSE_RELAY_MIN_CONTEXT_SLOT!=='9007199254740993')process.exit(10);
    if(args[0]!=='--input'||args[2]!=='--submitter'||args[3]!==plan.submitter||args[4]!=='--mint'||args[5]!==plan.mint)process.exit(11);
    if(fs.statSync(args[1]).mode%512!==384||fs.readFileSync(args[1]).toString('hex')!==plan.proof_hex)process.exit(12);
    plan.context_slot=process.env.MORSE_RELAY_MIN_CONTEXT_SLOT;console.log(JSON.stringify(plan));`);
  process.env.RELAY_TEST_SECRET='must not reach subprocess';
  t.after(()=>delete process.env.RELAY_TEST_SECRET);
  const verifier=await createRelayVerifier(config);
  const result=await verifier.admit(Buffer.from(plan.proof_hex,'hex'),'9007199254740993');
  assert.equal(result.proof_hash,plan.proof_hash);
  assert.equal(result.context_slot,'9007199254740993');
  assert.equal((await stat(config.tempRoot)).mode&0o777,0o700);
  assert.deepEqual(await readdir(config.tempRoot),[]);
  await assert.rejects(verifier.admit(Buffer.alloc(8193)),/evidence/i);
  await assert.rejects(verifier.admit(Buffer.alloc(1),'01'),/context/i);
});

test('only one bounded native process runs, cancellation waits for termination, and errors never expose configuration',async t=>{
  const config=await fixture(t,`process.stderr.write(process.env.MESSENGER_SECURITY_CONFIG.slice(0,100));setInterval(()=>{},1000);`);
  const verifier=await createRelayVerifier({...config,timeoutMs:100});
  const pending=verifier.admit(Buffer.from(plan.proof_hex,'hex'));
  await assert.rejects(verifier.admit(Buffer.from(plan.proof_hex,'hex')),/busy/i);
  await assert.rejects(pending,error=>/timed out/i.test(error.message)&&!error.message.includes(plan.proof_hex));
  assert.deepEqual(await readdir(config.tempRoot),[]);
  const controller=new AbortController();
  const aborted=verifier.admit(Buffer.from(plan.proof_hex,'hex'),'0',{signal:controller.signal});controller.abort();
  await assert.rejects(aborted,/cancelled/i);
  assert.deepEqual(await readdir(config.tempRoot),[]);
});

test('oversized, malformed, substituted and unsuccessful native reports never enter the writer',async t=>{
  for(const code of [
    `process.stdout.write('x'.repeat(262145))`,
    `process.stderr.write('secret'.repeat(2000))`,
    `console.log('{}\\n{}')`,
    `console.log(JSON.stringify({...JSON.parse(process.env.MESSENGER_SECURITY_CONFIG),proof_hex:'00'}))`,
    `console.log(process.env.MESSENGER_SECURITY_CONFIG);process.exit(1)`,
    `console.log(JSON.stringify({...JSON.parse(process.env.MESSENGER_SECURITY_CONFIG),context_slot:'0'}))`,
  ]){
    const config=await fixture(t,code),verifier=await createRelayVerifier(config);
    await assert.rejects(verifier.admit(Buffer.from(plan.proof_hex,'hex'),'1'));
    assert.deepEqual(await readdir(config.tempRoot),[]);
  }
});

test('Stage and lookup recovery use fixed arguments, bound identities and full-width minimum slots',async t=>{
  const config=await fixture(t,`
    const fs=require('node:fs'),args=process.argv.slice(2),p=JSON.parse(process.env.MESSENGER_SECURITY_CONFIG),floor=process.env.MORSE_RELAY_MIN_CONTEXT_SLOT;
    if(args[0]==='--stage-state'){
      if(args[1]!=='--input'||args[3]!=='--submitter'||args[4]!==p.submitter||fs.readFileSync(args[2]).toString('hex')!==p.proof_hex)process.exit(4);
      console.log(JSON.stringify({schema_version:1,status:'missing',address:p.stage.address,context_slot:floor,total_bytes:p.proof_hex.length/2,received_bytes:0,sealed:false,verified:[]}));
    }else{
      if(!['--lookup-state','--lookup-close-state'].includes(args[0])||args[1]!=='--submitter'||args[2]!==p.submitter||args[3]!=='--slot'||args[4]!==p.lookup.recent_slot||args[5]!=='--addresses'||args[6]!==p.lookup.addresses.join(','))process.exit(5);
      console.log(JSON.stringify({schema_version:1,status:args[0]==='--lookup-state'?'ready':'closable',address:p.lookup.address,authority:p.submitter,creationSlot:p.lookup.recent_slot,contextSlot:floor,addresses:p.lookup.addresses,lastExtendedSlot:p.lookup.recent_slot,deactivationSlot:'1',remainingBlocks:0}));
    }`);
  const verifier=await createRelayVerifier(config),floor='9007199254740993';
  assert.equal((await verifier.stage(plan,floor)).address,plan.stage.address);
  assert.equal((await verifier.lookup(plan,floor)).status,'ready');
  assert.equal((await verifier.lookup(plan,floor,{closing:true})).status,'closable');
  assert.deepEqual(await readdir(config.tempRoot),[]);
  const wrong={...plan,submitter:plan.program};
  await assert.rejects(verifier.stage(wrong),/pin/i);
});

test('receipt and destination state reports preserve explicit absence, context and original job identity',async t=>{
  const config=await fixture(t,`
    const fs=require('node:fs'),args=process.argv.slice(2),p=JSON.parse(process.env.MESSENGER_SECURITY_CONFIG),floor=process.env.MORSE_RELAY_MIN_CONTEXT_SLOT;
    if(args[1]!=='--input'||args[3]!=='--submitter'||args[4]!==p.submitter||args[5]!=='--mint'||args[6]!==p.mint||fs.readFileSync(args[2]).toString('hex')!==p.proof_hex)process.exit(2);
    if(args[0]==='--receipt-state')console.log(JSON.stringify({schema_version:1,status:'missing',address:p.receipt,proof_hash:p.proof_hash,context_slot:floor,receipt:null}));
    else if(args[0]==='--destinations-state')console.log(JSON.stringify({schema_version:1,proof_hash:p.proof_hash,mint:p.mint,context_slot:floor,
      finder:{address:p.setup[0].accountKeys[1],owner:p.setup[0].accountKeys[2],status:'ready'},
      locked:{address:p.setup[1].accountKeys[1],owner:p.setup[1].accountKeys[2],status:'missing'}}));
    else process.exit(3);`);
  const verifier=await createRelayVerifier(config),floor='9007199254740993';
  const receipt=await verifier.receipt(plan,floor);assert.equal(receipt.receipt,null);assert.equal(receipt.status,'missing');
  const destinations=await verifier.destinations(plan,floor);assert.equal(destinations.finder.status,'ready');assert.equal(destinations.locked.status,'missing');
  assert.deepEqual(await readdir(config.tempRoot),[]);
  for(const change of [{address:plan.program},{proof_hash:'12'.repeat(32)},{context_slot:'0'},{status:'settled'},
    {status:'settled',receipt:{schema_version:1,proof_hash:plan.proof_hash,mint:plan.program,context_slot:floor}}]){
    const report={schema_version:1,status:'missing',address:plan.receipt,proof_hash:plan.proof_hash,context_slot:floor,receipt:null,...change};
    const broken=await createRelayVerifier(await fixture(t,`console.log(${JSON.stringify(JSON.stringify(report))});`));
    await assert.rejects(broken.receipt(plan,floor));
  }
});

test('migrated legacy jobs read version-aware permanent receipts after collateral conversion',async t=>{
  const mixedPins={...pins,usdcMint:pins.mint,morseMint:plan.program};
  const config=await fixture(t,`
    const fs=require('node:fs'),args=process.argv.slice(2),p=JSON.parse(process.env.MESSENGER_SECURITY_CONFIG);
    const request=JSON.parse(fs.readFileSync(args[5]));
    if(request.method!=='receipt')process.exit(19);
    console.log(JSON.stringify({schema_version:2,status:'settled',address:p.receipt,proof_hash:p.proof_hash,context_slot:request.min_context_slot,
      receipt:{schema_version:2,status:'settled',proof_hash:p.proof_hash,finder:p.finder,usdc_mint:p.mint,morse_mint:p.program,context_slot:request.min_context_slot}}));`);
  const plannerConfig=JSON.stringify({judge:pins.program,usdc_mint:pins.mint,morse_mint:plan.program,submitter:pins.submitter,fee_payer:pins.submitter});
  const verifier=await createRelayVerifier({...config,pins:mixedPins,plannerConfig});
  const receipt=await verifier.receipt(plan,plan.context_slot);
  assert.equal(receipt.status,'settled');assert.equal(receipt.receipt.schema_version,2);
  assert.equal(receipt.receipt.proof_hash,plan.proof_hash);
});
