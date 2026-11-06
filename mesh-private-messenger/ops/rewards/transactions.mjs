import { createHash } from 'node:crypto';
import {
  AccountRole, addSignersToTransactionMessage, appendTransactionMessageInstructions, assertIsAddress,
  assertIsSendableTransaction, compileTransaction, createTransactionMessage, getAddressEncoder,
  getBase64EncodedWireTransaction, getCompiledTransactionMessageDecoder, getSignatureFromTransaction,
  getTransactionDecoder, getTransactionEncoder, getTransactionSize, setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners,
} from '@solana/kit';

const SYSTEM='11111111111111111111111111111111';
const TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const ATA='ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const COMPUTE='ComputeBudget111111111111111111111111111111';
const MAX=18446744073709551615n;
const RECIPES=new WeakMap();
const fail=message=>{throw new Error(message);};
const key=value=>{assertIsAddress(value);return value;};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const unique=values=>[...new Set(values)].sort();
export function rewardsCoordinate(value){
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>MAX)fail('Invalid rewards coordinate');
  return BigInt(value);
}
function report(value,limit){
  if(!value||value.schemaVersion!==1||!Array.isArray(value.accountKeys)||value.accountKeys.length>limit||
    value.accountCount!==value.accountKeys.length||!Array.isArray(value.signerKeys)||!Array.isArray(value.writableKeys)||
    value.signerKeys.some(k=>!value.accountKeys.includes(k))||value.writableKeys.some(k=>!value.accountKeys.includes(k))||
    typeof value.dataBase64!=='string'||value.dataBase64.length>1024)fail('Invalid rewards instruction report');
  const data=Buffer.from(value.dataBase64,'base64');
  if(data.toString('base64')!==value.dataBase64||data.length!==value.dataBytes)fail('Invalid rewards instruction data');
  return {programAddress:key(value.programId),data,accounts:value.accountKeys.map(address=>({address:key(address),
    role:value.signerKeys.includes(address)?(value.writableKeys.includes(address)?AccountRole.WRITABLE_SIGNER:AccountRole.READONLY_SIGNER):
      value.writableKeys.includes(address)?AccountRole.WRITABLE:AccountRole.READONLY}))};
}
function roles(ix,signers,writable){
  const addresses=ix.accounts.map(a=>a.address);
  // Aliased payer/funder metas acquire the union of privileges on Solana.
  const s=new Set(signers.map(i=>addresses[i])),w=new Set(writable.map(i=>addresses[i]));
  for(const a of ix.accounts){
    const expected=s.has(a.address)?(w.has(a.address)?AccountRole.WRITABLE_SIGNER:AccountRole.READONLY_SIGNER):w.has(a.address)?AccountRole.WRITABLE:AccountRole.READONLY;
    if(a.role!==expected)fail('Unexpected rewards account privileges');
  }
}

// This is a packet/signing boundary. Only the local Mesh planner supplies these
// reports; RPC and HTTP callers cannot submit reports, instructions or signers.
// Mesh and the chain program own all eligibility, identity and reward policy.
export function prepareRewardsTransaction(plan,pins){
  const version=pins?.version??1;
  if(![1,2].includes(version)||!plan||plan.schema_version!==version||plan.status!=='ready')fail('Expected a ready Mesh rewards plan');
  for(const field of ['program','judge','log','mint','payer']){
    if(plan[field]!==pins?.[field])fail('Rewards operator pin mismatch');key(plan[field]);
  }
  if(version===2){
    for(const field of ['token','morse']){if(plan[field]!==pins[field])fail('Rewards v2 pin mismatch');key(plan[field]);}
    if(!/^[a-f0-9]{64}$/.test(plan.configuration_hash)||plan.configuration_hash!==pins.configuration_hash)fail('Rewards v2 configuration mismatch');
  }
  rewardsCoordinate(plan.epoch);rewardsCoordinate(plan.context_slot);
  if(typeof plan.intent_hash!=='string'||!/^[a-f0-9]{64}$/.test(plan.intent_hash))fail('Invalid rewards intent');
  if(!Array.isArray(plan.instructions)||plan.instructions.length<1||plan.instructions.length>3)fail('Invalid rewards instructions');
  const instructions=plan.instructions.map(value=>report(value,version===2?31:24)),work=[...instructions];
  if(work[0].programAddress===COMPUTE){
    const compute=work.shift();
    if(compute.accounts.length||compute.data.length!==5||compute.data[0]!==2||compute.data.readUInt32LE(1)!==1400000)fail('Invalid rewards compute budget');
  }
  let setup;
  if(work[0]?.programAddress===ATA)setup=work.shift();
  if(work.length!==1)fail('Expected one rewards operation');
  const ix=work[0],a=ix.accounts.map(value=>value.address),tag=ix.data[0];
  const tags=version===2?{open:14,begin:15,append:16,finalize:17,'claim-usdc':8,'claim-morse':18,cancel:19,assess:45,'attendance-open':28,seal:29}:
    {open:1,fund:12,begin:5,append:6,finalize:7,claim:8,cancel:11,'attendance-open':28,seal:29};
  if(tag!==tags[plan.action]||ix.programAddress!==(['seal','attendance-open','assess'].includes(plan.action)?plan.judge:plan.program))fail('Unexpected rewards program or operation');
  let rents=[],signers=[plan.payer];
  if(version===2&&!['attendance-open','seal'].includes(plan.action)){
    switch(plan.action){
      case 'assess':
        if(ix.data.length!==2||ix.data[1]>1||a.length!==14+ix.data[1]||a[0]!==plan.log||a[6]!==plan.token||a[9]!==plan.morse||a[11]!==plan.program)fail('Invalid v2 grace assessment');
        if(rewardsCoordinate(plan.assessment?.next_cursor)>64n)fail('Invalid v2 assessment cursor');
        roles(ix,[],[1,3,5]);break;
      case 'open':
        if(a.length!==6||ix.data.length!==9||a[0]!==plan.payer||a[5]!==SYSTEM||ix.data.readBigUInt64LE(1)!==BigInt(plan.epoch))fail('Invalid v2 rewards open');
        roles(ix,[0],[0,3,4]);rents=[{address:a[3],space:8416},{address:a[4],space:1280}];break;
      case 'begin':case 'append':case 'cancel':case 'finalize':{
        const final=plan.action==='finalize';
        if(ix.data.length!==1||a[4]!==plan.log||a[9]!==plan.token||a[12]!==plan.morse||a[14]!==plan.program||a[16]!==plan.judge||
          (plan.action==='append'?(a.length<23||a.length>31||(a.length-19)%4):a.length!==(final?26:19)))fail('Invalid v2 rewards settlement');
        if(final){
          if(a[23]!==plan.payer||a[24]!==TOKEN||a[25]!==SYSTEM)fail('Invalid v2 finalize payer or program');
          roles(ix,[23],[0,1,2,3,19,20,21,22,23]);rents=[{address:a[22],space:256}];
        }else roles(ix,[],[0,2,3]);
        break;
      }
      case 'claim-usdc':
        if(ix.data.length!==2||ix.data[1]>63||a.length!==6||a[4]!==plan.mint||a[5]!==TOKEN)fail('Invalid v2 USDC claim');
        roles(ix,[],[0,1,2,3]);break;
      case 'claim-morse':
        if(ix.data.length!==2||ix.data[1]>63||a.length!==8||a[6]!==plan.morse||a[7]!==TOKEN)fail('Invalid v2 MORSE claim');
        roles(ix,[],[1,3,4,5]);break;
      default:fail('Invalid v2 rewards operation');
    }
  }else{
  switch(plan.action){
    case 'open':
      if(a.length!==4||ix.data.length!==9||a[0]!==plan.payer||a[3]!==SYSTEM||ix.data.readBigUInt64LE(1)!==BigInt(plan.epoch))fail('Invalid rewards open');
      roles(ix,[0],[0,2]);rents=[{address:a[2],space:8416}];break;
    case 'fund':
      if(a.length!==10||ix.data.length!==42||ix.data[1]>1||ix.data.readBigUInt64LE(2)===0n||ix.data.subarray(10).every(n=>n===0)||
        a[1]!==plan.payer||a[6]!==plan.mint||a[7]!==TOKEN||a[9]!==SYSTEM)fail('Invalid idempotent rewards funding');
      roles(ix,[0,1],[1,2,3,4,5,8]);signers.push(a[0]);rents=[{address:a[8],space:192}];break;
    case 'begin':case 'finalize':case 'append':
      if(ix.data.length!==1||a[2]!==plan.log||(plan.action==='append'?(a.length<9||a.length>18||(a.length-6)%3):a.length!==6))fail('Invalid rewards settlement');
      roles(ix,[],[0,1]);break;
    case 'cancel':
      if(ix.data.length!==1||a.length!==3)fail('Invalid rewards cancellation');roles(ix,[],[0,1]);break;
    case 'claim':
      if(ix.data.length!==2||ix.data[1]>63||a.length!==6||a[4]!==plan.mint||a[5]!==TOKEN)fail('Invalid rewards claim');
      roles(ix,[],[0,1,2,3]);break;
    case 'attendance-open':
      if(ix.data.length!==9||a.length!==5||a[0]!==plan.payer||a[1]!==plan.log||a[4]!==SYSTEM||ix.data.readBigUInt64LE(1)!==BigInt(plan.epoch))fail('Invalid attendance open');
      roles(ix,[0],[0,3]);rents=[{address:a[3],space:2640}];break;
    case 'seal':
      if(ix.data.length!==1||a.length!==2||a[0]!==plan.log)fail('Invalid attendance seal');roles(ix,[],[1]);break;
  }
  }
  if(setup){
    const s=setup.accounts.map(value=>value.address);
    const claim=version===2?['claim-usdc','claim-morse'].includes(plan.action):plan.action==='claim';
    const morse=plan.action==='claim-morse';
    if(!claim||setup.data.toString('hex')!=='01'||s.length!==6||s[0]!==plan.payer||s[1]!==a[morse?5:3]||s[3]!==(morse?plan.morse:plan.mint)||s[4]!==SYSTEM||s[5]!==TOKEN)fail('Invalid rewards ATA setup');
    roles(setup,[0],[0,1]);rents=[{address:s[1],space:165}];
  }
  if(!same(plan.rent_allocations,rents)||!Array.isArray(plan.signer_keys)||!same(unique(plan.signer_keys),unique(signers))||plan.signer_keys.length!==unique(signers).length)fail('Invalid rewards rent or signers');
  const recipe={instructions,payer:plan.payer,signers:unique(signers),contextSlot:plan.context_slot,rent:rents,
    intent:hash(JSON.stringify({intent:plan.intent_hash,action:plan.action,payer:plan.payer,instructions,
      ...(version===2?{version,configuration:plan.configuration_hash,...(plan.action==='assess'?{assessment:plan.assessment}:{})}:{})}))};
  const step=Object.freeze({id:recipe.intent,kind:plan.action});RECIPES.set(step,recipe);
  rewardsMessage(step,{blockhash:SYSTEM,lastValidBlockHeight:1n});return step;
}
function message(step,lifetime){
  const recipe=RECIPES.get(step);if(!recipe)fail('Expected a locally prepared rewards step');
  key(lifetime?.blockhash);
  if(typeof lifetime.lastValidBlockHeight!=='bigint'||lifetime.lastValidBlockHeight<=0n||lifetime.lastValidBlockHeight>MAX)fail('Invalid rewards lifetime');
  let value=setTransactionMessageFeePayer(recipe.payer,createTransactionMessage({version:0}));
  value=setTransactionMessageLifetimeUsingBlockhash(lifetime,value);
  value=appendTransactionMessageInstructions(recipe.instructions,value);
  if(getTransactionSize(compileTransaction(value))>1232)fail('Rewards packet exceeds limit');
  return {value,recipe};
}
export function rewardsMessage(step,lifetime){
  const {value,recipe}=message(step,lifetime),bytes=Buffer.from(compileTransaction(value).messageBytes);
  const decoded=getCompiledTransactionMessageDecoder().decode(bytes);
  return {messageBase64:bytes.toString('base64'),messageHash:hash(bytes),minContextSlot:recipe.contextSlot,
    accountKeys:[...decoded.staticAccounts],loadedAddresses:{writable:[],readonly:[]},rentAllocations:structuredClone(recipe.rent),refundAccount:null};
}
export async function verifyRewardsSigned(signed,expectedMessageHash,signers){
  if(typeof signed?.wire!=='string'||signed.wire.length>1644)fail('Invalid rewards transaction bytes');
  const bytes=Buffer.from(signed.wire,'base64');
  if(!bytes.length||bytes.length>1232||bytes.toString('base64')!==signed.wire)fail('Invalid rewards transaction bytes');
  const tx=getTransactionDecoder().decode(bytes);
  if(!bytes.equals(Buffer.from(getTransactionEncoder().encode(tx)))||!same(unique(Object.keys(tx.signatures)),unique(signers))||
    hash(tx.messageBytes)!==expectedMessageHash||getSignatureFromTransaction(tx)!==signed.signature)fail('Rewards transaction differs from reservation');
  for(const signer of signers){
    const publicKey=await crypto.subtle.importKey('raw',getAddressEncoder().encode(key(signer)),'Ed25519',false,['verify']);
    if(!await crypto.subtle.verify('Ed25519',publicKey,tx.signatures[signer],tx.messageBytes))fail('Invalid rewards signature');
  }
}
export async function rewardsSignedStep(step,signed){
  const recipe=RECIPES.get(step);if(!recipe||signed.stepId!==step.id||signed.minContextSlot!==recipe.contextSlot)fail('Invalid signed rewards step');
  const raw=getTransactionDecoder().decode(Buffer.from(signed.wire,'base64'));
  const decoded=getCompiledTransactionMessageDecoder().decode(raw.messageBytes);
  const info=rewardsMessage(step,{blockhash:decoded.lifetimeToken,lastValidBlockHeight:rewardsCoordinate(signed.lastValidBlockHeight)});
  await verifyRewardsSigned(signed,info.messageHash,recipe.signers);return info;
}
export async function signRewardsTransaction(step,signers,lifetime){
  const {value,recipe}=message(step,lifetime);
  if(!Array.isArray(signers)||!same(unique(signers.map(s=>s.address)),recipe.signers)||signers.length!==recipe.signers.length)fail('Rewards signer mismatch');
  const transaction=await signTransactionMessageWithSigners(addSignersToTransactionMessage(signers,value));
  assertIsSendableTransaction(transaction);
  return {stepId:step.id,signature:getSignatureFromTransaction(transaction),wire:getBase64EncodedWireTransaction(transaction),
    lastValidBlockHeight:lifetime.lastValidBlockHeight.toString(),minContextSlot:recipe.contextSlot};
}
