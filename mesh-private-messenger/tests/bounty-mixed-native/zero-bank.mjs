// Genuine zero-finder receipts from the frozen signed SBF bank; no build step.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn, execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const directory=path.dirname(fileURLToPath(import.meta.url));
const workspace=path.resolve(directory,'../../..');
const cases=['usdc-zero','morse-zero','both-zero'];
const option=name=>process.argv.find(value=>value.startsWith(`--${name}=`))?.slice(name.length+3);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

async function checkCapture(root,name,wallet){
  assert.ok(cases.includes(name),'explicit zero-finder case required');
  const captures={};
  for(const phase of ['prepared','settled']){
    const manifest=JSON.parse(await readFile(path.join(root,`phone-${phase}.json`),'utf8'));
    const bank=JSON.parse(await readFile(path.join(root,`phone-${phase}.bank.json`),'utf8'));
    const response=JSON.parse(await readFile(path.join(root,`phone-${phase}.raw.response.json`),'utf8'));
    for(const [file,hash] of Object.entries(manifest.artifacts))assert.equal(sha(await readFile(file)),hash,file);
    const receipt=Buffer.from(bank.accounts[3].data_hex,'hex');
    assert.deepEqual(receipt,Buffer.from(response.result.value[3].data[0],'base64'));
    assert.equal(receipt.subarray(0,4).toString('hex'),'4d505202');
    assert.equal(receipt[7],phase==='prepared'?0:1);
    if(wallet)assert.equal(receipt.subarray(72,104).toString('hex'),wallet.bounties[3].address_hex);
    assert.ok(manifest.boundary.signed_packet_count>0);
    const amounts={usdcSlashed:receipt.readBigUInt64LE(272),usdcFinder:receipt.readBigUInt64LE(280),
      morseSlashed:receipt.readBigUInt64LE(296),morseFinder:receipt.readBigUInt64LE(304)};
    if(phase==='prepared')assert.deepEqual(Object.values(amounts),[0n,0n,0n,0n]);
    captures[phase]={manifest,amounts,receipt_sha256:sha(receipt)};
  }
  const amounts=captures.settled.amounts;
  assert.ok(amounts.usdcSlashed>0n&&amounts.morseSlashed>0n,'both assets actually slashed');
  assert.equal(amounts.usdcFinder===0n,name!=='morse-zero','USDC finder zero classification');
  assert.equal(amounts.morseFinder===0n,name!=='usdc-zero','MORSE finder zero classification');
  assert.ok(captures.settled.manifest.boundary.signed_packet_count>captures.prepared.manifest.boundary.signed_packet_count);
  return {case:name,status:'PASS',amounts,...Object.fromEntries(Object.entries(captures).map(([phase,value])=>[phase,{
    receipt_sha256:value.receipt_sha256,receipt_address:value.manifest.receipt_address,
    signed_packet_count:value.manifest.boundary.signed_packet_count,
    manifest:path.join(root,`phone-${phase}.json`)}]))};
}

if(option('check')){
  console.log(JSON.stringify(await checkCapture(path.resolve(option('check')),option('case')),(_,v)=>typeof v==='bigint'?String(v):v,2));
  process.exit(0);
}

// Inject only initialized custody, before bridge initialize. The retained helper
// removes receipt/stage/destinations, then signs and executes their creation.
async function adjustZeroCustody(f){
  const zeroUsdc=process.env.BOUNTY_ZERO_CASE!=='morse-zero';
  const zeroMorse=process.env.BOUNTY_ZERO_CASE!=='usdc-zero';
  const accounts=f.snapshot.accounts,values=Object.values(accounts),changes=[];
  const totals=()=>f.mints.map(mint=>values.reduce((sum,value)=>{
    if(value.missing||value.owner!==TOKEN)return sum;
    const bytes=raw(value);return bytes.length===165&&addr(bytes.subarray(0,32))===mint?sum+bytes.readBigUInt64LE(64):sum;
  },0n));
  const initialTotals=totals();
  function edit(value,offset,amount){
    const bytes=raw(value),before=bytes.readBigUInt64LE(offset);
    bytes.writeBigUInt64LE(amount,offset);value.data_hex=bytes.toString('hex');
    if(before!==amount)changes.push({address:value.address,offset,before:String(before),after:String(amount)});
  }
  const bonds=values.filter(value=>!value.missing&&raw(value).subarray(0,3).toString()==='MBD');
  assert.equal(bonds.length,3,'exact retained two-witness plus directory custody');
  const operator=raw(accounts.economics).subarray(68,100);
  for(const bond of bonds){
    const bytes=raw(bond),asset=bytes[6];
    if(!(asset===0?zeroUsdc:zeroMorse))continue;
    const vault=values.find(value=>value.address===addr(bytes.subarray(136,168)));
    assert.equal(vault.owner,TOKEN);assert.equal(raw(vault).length,165);
    const operatorSource=values.find(value=>!value.missing&&value.owner===TOKEN&&raw(value).length===165
      &&raw(value).subarray(0,32).equals(raw(vault).subarray(0,32))&&raw(value).subarray(32,64).equals(operator));
    assert.ok(operatorSource,'same-mint operator source retains removed fixture tokens');
    const balance=raw(vault).readBigUInt64LE(64);
    assert.ok(balance>=9n);
    edit(operatorSource,64,raw(operatorSource).readBigUInt64LE(64)+balance-9n);
    edit(vault,64,9n);
    const pending=values.find(value=>!value.missing&&raw(value).subarray(0,4).toString('hex')==='4d425002'
      &&raw(value).subarray(4,36).equals(encoder.encode(bond.address)));
    const pendingAmount=pending?raw(pending).readBigUInt64LE(68):0n;
    assert.ok(pendingAmount<9n);
    edit(bond,168,9n-pendingAmount);
    if(asset===1){assert.ok(pending);edit(pending,84,1n);}
  }
  // Lower disposable initial policy targets consistently. MORSE lifetime targets
  // stay recorded in pending companions; each retained principal covers its own.
  if(zeroUsdc){edit(accounts.economics,100,1n);edit(accounts.economics,108,1n);}
  if(zeroMorse)edit(accounts.economics,100,1n);
  for(const asset of [0,1]){
    const witnessSum=bonds.reduce((sum,bond)=>{const d=raw(bond);return sum+(d[5]===1&&d[6]===asset?d.readBigUInt64LE(168):0n);},0n);
    const directorySum=bonds.reduce((sum,bond)=>{const d=raw(bond);return sum+(d[5]===0&&d[6]===asset?d.readBigUInt64LE(168):0n);},0n);
    edit(accounts.economics,asset===0?148:176,witnessSum);
    edit(accounts.economics,asset===0?156:184,directorySum);
  }
  assert.deepEqual(totals(),initialTotals,'initialized token totals conserved by mint');
  const economics=raw(accounts.economics);
  assert.ok(economics.readBigUInt64LE(100)>0n&&economics.readBigUInt64LE(108)>=economics.readBigUInt64LE(100));
  for(const bond of bonds){
    const d=raw(bond),vault=values.find(value=>value.address===addr(d.subarray(136,168)));
    assert.ok(d.readBigUInt64LE(168)>0n&&d.readBigUInt64LE(168)<=raw(vault).readBigUInt64LE(64));
  }
  for(const value of values)if(!value.missing){
    assert.notEqual(raw(value).subarray(0,3).toString(),'MPR','no seeded receipt');
    assert.notEqual(raw(value).subarray(0,3).toString(),'MST','no seeded stage');
    assert.ok(!f.destinations.includes(value.address),'no seeded payout destination');
  }
  await writeFile(join(output,'custody-adjustments.json'),JSON.stringify({case:process.env.BOUNTY_ZERO_CASE,
    boundary:'Disposable initial custody only; no receipt/stage/payout is initialized. Removed vault tokens stay in the same-mint operator source.',
    token_totals_before:initialTotals.map(String),token_totals_after:totals().map(String),changes},null,2)+'\n');
}

const output=path.resolve(option('out')??path.join(workspace,'.morse/bounty-mixed/proof-zero'));
assert.ok(output.startsWith(path.join(workspace,'.morse/bounty-mixed/proof-zero')),'owned proof-zero output required');
await mkdir(output,{recursive:true});
const retained='/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-824a9ee0';
const sbf='/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-63282176/.morse/grace-assessment/sbf';
const sdk=path.join(workspace,'.morse/bounty-mixed/proof-wallet-sdk');
const wallet=JSON.parse(execFileSync(sdk,[],{input:'{"bounty_count":4}',encoding:'utf8',timeout:30000}));
assert.equal(wallet.bounties[3].index,3);
const helperPath=path.join(directory,'bank.mjs'),helper=await readFile(helperPath,'utf8');
const initializeHook="    const initialized=await bridge.ask({method:'initialize',fixture:f.snapshot,payer:signer.address});";
const writeHook='await writeFile(generated,source);';
assert.equal(helper.split(writeHook).length,2);
const results=[];
for(const name of option('case')?[option('case')]:cases){
  assert.ok(cases.includes(name));
  const root=path.join(output,name);await mkdir(root,{recursive:true});
  const initialization=`await (${adjustZeroCustody.toString()})(f);\n${initializeHook}`;
  const bootstrap=helper.replace(writeHook,`if(source.split(${JSON.stringify(initializeHook)}).length!==2)throw new Error('retained initialization shape changed');\nsource=source.replace(${JSON.stringify(initializeHook)},${JSON.stringify(initialization)});\n${writeHook}`);
  const bootstrapPath=path.join(root,'bank-bootstrap.mjs');await writeFile(bootstrapPath,bootstrap);
  const env={...process.env,BOUNTY_RELAY_TEST_SOURCE:path.join(retained,'mesh-private-messenger/ops/relay/mpr2-sbf.test.mjs'),
    MORSE_MPR2_RELAY_PROOF_OUTPUT:root,
    MORSE_TOKEN_CUSTODY_FIXTURES_PATH:'/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/token-custody-fixtures.json',
    MORSE_MPR2_RELAY_VECTORS_PATH:'/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/collateral-v2-operator/sdk-vector-subset-final3.json',
    MORSE_MPR2_RELAY_BINARY:path.join(retained,'.morse/mpr2-phone-snapshots/final-6a061ec/relay-mpr2'),
    MORSE_MPR2_RELAY_SBF_BRIDGE:path.join(retained,'.morse/mpr2-phone-snapshots/mpr2_relay_bridge'),
    MORSE_JUDGE_SBF_PATH:path.join(sbf,'morse_judge.so'),MORSE_TOKEN_SBF_PATH:path.join(sbf,'morse_token.so'),
    MORSE_REWARDS_SBF_PATH:path.join(sbf,'morse_rewards.so'),BOUNTY_FIXTURE_FINDER:wallet.bounties[3].address_hex,
    BOUNTY_FIXTURE_WALLET:JSON.stringify(wallet),BOUNTY_ZERO_CASE:name};
  await writeFile(path.join(root,'inputs.json'),JSON.stringify({case:name,fixture_seed_tag:1,finder_sdk_index:3,
    artifacts:{[fileURLToPath(import.meta.url)]:sha(await readFile(fileURLToPath(import.meta.url))),
      [helperPath]:sha(Buffer.from(helper)),[sdk]:sha(await readFile(sdk)),[bootstrapPath]:sha(Buffer.from(bootstrap))},
    sbf_sources:'Retained unchanged ELFs; no build performed. Exact path/hash recorded by bridge initialization.'},null,2)+'\n');
  const child=spawn(process.execPath,[bootstrapPath],{env,stdio:['pipe','pipe','pipe']});
  const exited=once(child,'exit'),reader=createInterface({input:child.stdout})[Symbol.asyncIterator]();
  let stderr='';child.stderr.on('data',data=>stderr+=data);
  async function line(){
    let timer;
    try{const next=await Promise.race([reader.next(),new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error(`bank response timeout: ${stderr}`)),60000))]);
      assert.equal(next.done,false,stderr);return JSON.parse(next.value);
    }finally{clearTimeout(timer);}
  }
  const command=async request=>{child.stdin.write(JSON.stringify(request)+'\n');return line();};
  try{
    const ready=await line();assert.equal(ready.ready,true);
    await writeFile(path.join(root,'ready.json'),JSON.stringify(ready,null,2)+'\n');
    assert.deepEqual(await command({method:'settle'}),{settled:true});
    const report=await command({method:'report'});
    await writeFile(path.join(root,'signed-packets.json'),JSON.stringify(report,null,2)+'\n');
    assert.deepEqual(report.errors,[]);
    for(const packet of report.packets)assert.equal(packet.execution.ok,true);
    const result=await checkCapture(root,name,wallet);
    result.packet_report_sha256=sha(await readFile(path.join(root,'signed-packets.json')));
    result.signature_verification=true;
    result.limits=['Disposable LiteSVM bank; local finalized RPC label, not live validator finality.',
      'Coherent custody/policy initialization changes only; receipts, stage and payouts created by freshly signed SBF packets.',
      'No external RPC, accounts, funding, toolchain copy or build.'];
    await writeFile(path.join(root,'result.json'),JSON.stringify(result,(_,v)=>typeof v==='bigint'?String(v):v,2)+'\n');
    results.push(result);console.log(JSON.stringify(result,(_,v)=>typeof v==='bigint'?String(v):v));
  }finally{
    if(child.exitCode===null)child.stdin.end('{"method":"stop"}\n');
    let timer;try{await Promise.race([exited,new Promise(resolve=>timer=setTimeout(()=>{child.kill('SIGKILL');resolve();},5000))]);}
    finally{clearTimeout(timer);await writeFile(path.join(root,'stderr.log'),stderr);}
  }
}
await writeFile(path.join(output,'results.json'),JSON.stringify(results,(_,v)=>typeof v==='bigint'?String(v):v,2)+'\n');
