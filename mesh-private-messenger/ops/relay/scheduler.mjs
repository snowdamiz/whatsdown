import { randomUUID } from 'node:crypto';
import { prepareRelayTransactions } from './transactions.mjs';
import { createRelayEffectReader } from './effects.mjs';
import { recoverRelayPending, submitRelayStep } from './writer.mjs';

const prepared=plan=>prepareRelayTransactions(plan,{...plan,mint:plan.mint??plan.usdc_mint,
  usdcMint:plan.usdc_mint,morseMint:plan.morse_mint,proofHex:plan.proof_hex});
const fence=context=>context.journal.renew(context.lease,context.now());
const floor=(context,proof)=>context.journal.progress(proof).minContextSlot;
async function receipt(context,job){
  if(job.receipt)return job;
  const view=await context.verifier.receipt(job.plan,floor(context,job.proofHash));fence(context);
  if(view.context_slot!==undefined&&!context.journal.pending())context.journal.observeContext(context.lease,job.proofHash,view.context_slot,context.now());
  if(view.status==='settled')context.journal.recordReceipt(context.lease,job.proofHash,view.receipt,context.now());
  return context.journal.job(job.proofHash);
}
function waiting(context,proof,reason,delay=1000){
  context.journal.deferJob(context.lease,proof,delay,context.now());
  return {state:'waiting',reason,proofHash:proof};
}

// One tick may authenticate several already present effects, but signs at most
// one transaction. Cache only views from this tick, and only while their agreed
// context satisfies the next read. No untrusted HTTP fields reach this adapter.
async function walk(context,job,steps,{retiring=false}={}){
  const cache=new Map();
  const verifier=Object.fromEntries(['stage','destinations','receipt','lookup'].map(kind=>[kind,async(plan,minimum,options)=>{
    const key=`${kind}:${Boolean(options?.closing)}`,cached=cache.get(key);
    if(cached&&BigInt(cached.context_slot??cached.contextSlot)>=BigInt(minimum))return cached;
    const value=await context.verifier[kind](plan,minimum,options);fence(context);cache.set(key,value);return value;
  }]));
  verifier.effect=async(...args)=>{const value=await context.verifier.effect(...args);fence(context);return value;};
  const read=createRelayEffectReader(verifier),proof=job.proofHash;
  for(const step of steps.filter(Boolean)){
    const result=await read(job,step,{minContextSlot:floor(context,proof)});fence(context);
    context.journal.observeContext(context.lease,proof,result.slot,context.now());
    if(result.state==='present'){
      context.journal.observeStep(context.lease,proof,step.id,{slot:result.slot},context.now());continue;
    }
    let lookupView;
    if(step.requiresLookup){
      lookupView=await verifier.lookup(job.plan,floor(context,proof),{closing:false});
      context.journal.observeContext(context.lease,proof,lookupView.contextSlot,context.now());
      if(lookupView.status!=='ready')return waiting(context,proof,'lookup-activation');
    }
    if(step.kind==='close-table'){
      lookupView=await verifier.lookup(job.plan,floor(context,proof),{closing:true});
      context.journal.observeContext(context.lease,proof,lookupView.contextSlot,context.now());
      if(lookupView.status!=='closable')return waiting(context,proof,'cooldown',1000);
    }
    if(step.id!=='settle')context.journal.invalidateStep(context.lease,proof,step.id,{slot:floor(context,proof)},context.now());
    return {...await submitRelayStep({...context,proofHash:proof,stepId:step.id,lookupView}),proofHash:proof,stepId:step.id};
  }
  if(retiring)return {state:'table-retired',proofHash:proof};
  if(job.receipt){context.journal.complete(context.lease,proof,context.now());return {state:'complete',proofHash:proof};}
  if(job.plan.schema_version===2)return {state:'operation-observed',proofHash:proof};
  // The receipt effect became visible during this tick. Persist its full report
  // on the next tick before attempting cleanup.
  return {state:'settlement-observed',proofHash:proof};
}

export async function advanceRelay(context){
  fence(context);
  const pending=context.journal.pending();
  if(pending){
    if(pending.phase==='signed')await receipt(context,context.journal.job(pending.proofHash));
    return {...await recoverRelayPending(context),proofHash:pending.proofHash};
  }
  context.journal.maintain(context.lease,context.now());
  let job=context.journal.nextJob(context.lease,context.now());
  if(!job)return {state:'idle'};
  job=await receipt(context,job);
  if(job.plan.schema_version===2){
    const admission=await context.verifier.admit(Buffer.from(job.plan.proof_hex,'hex'),floor(context,job.proofHash),{schemaVersion:2,lookup:job.plan.lookup});fence(context);
    if(admission.status==='settled'&&!job.receipt){
      // A receipt may settle between the first read and the fresh plan. Persist
      // only the authenticated permanent receipt before adopting cleanup.
      job=await receipt(context,job);
      if(!job.receipt)return waiting(context,job.proofHash,'settlement-receipt');
    }
    let lookupView;
    if(job.plan.lookup&&context.journal.resources(job.proofHash).includes(job.plan.lookup.address)){
      lookupView=await context.verifier.lookup(job.plan,admission.context_slot,{closing:true});fence(context);
    }
    const revision=context.journal.revisePlan(context.lease,job.proofHash,admission,context.now(),lookupView);
    if(revision.state==='resource-busy')return waiting(context,job.proofHash,'resource-ownership');
    if(revision.state==='retire-table')return walk(context,job,prepared(job.plan).cleanup.filter(step=>step.kind!=='close-stage'),{retiring:true});
    job=context.journal.job(job.proofHash);
    if(job.receipt&&context.journal.completeUnspent(context.lease,job.proofHash,context.now()))return {state:'complete',proofHash:job.proofHash};
    const plan=prepared(job.plan);
    return walk(context,job,job.receipt?plan.cleanup:[...(plan.needsLookup?plan.lookup:[]),...plan.preparation,plan.settlement]);
  }
  if(job.receipt){
    if(context.journal.completeUnspent(context.lease,job.proofHash,context.now()))return {state:'complete',proofHash:job.proofHash};
    if(!context.journal.claimResources(context.lease,job.proofHash,context.now()))return waiting(context,job.proofHash,'resource-ownership');
    return walk(context,job,prepared(job.plan).cleanup);
  }
  const admission=await context.verifier.admit(Buffer.from(job.plan.proof_hex,'hex'),floor(context,job.proofHash),{schemaVersion:1});fence(context);
  if(admission.status==='settled'){
    context.journal.recordReceipt(context.lease,job.proofHash,admission.receipt,context.now());
    return {state:'receipt-observed',proofHash:job.proofHash};
  }
  let lookupView;
  if(prepared(job.plan).needsLookup&&context.journal.resources(job.proofHash).includes(job.plan.lookup.address)){
    lookupView=await context.verifier.lookup(job.plan,admission.context_slot,{closing:true});fence(context);
  }
  const revision=context.journal.revisePlan(context.lease,job.proofHash,admission,context.now(),lookupView);
  if(revision.state==='resource-busy')return waiting(context,job.proofHash,'resource-ownership');
  if(revision.state==='retire-table')return walk(context,job,prepared(job.plan).cleanup.filter(step=>step.kind!=='close-stage'),{retiring:true});
  job=context.journal.job(job.proofHash);
  const plan=prepared(job.plan);
  return walk(context,job,[...plan.preparation,...(plan.needsLookup?plan.lookup:[]),plan.settlement]);
}

export function createRelayScheduler({journal,verifier,rpc,signer,now=Date.now,owner=randomUUID()}){
  let busy=false,lease=null;
  return Object.freeze({async tick(){
    if(busy)return {state:'busy'};
    busy=true;
    try{
      if(lease){
        try{journal.renew(lease,now());}catch(error){
          // A superseded worker may try again only by taking a new fenced lease.
          // Clock and storage errors are not evidence that its old lease is free.
          if(!/lease expired or superseded/i.test(error.message))throw error;
          lease=null;
        }
      }
      if(!lease)lease=journal.claim(owner,now());
      if(!lease)return {state:'lease-busy'};
      return await advanceRelay({journal,lease,verifier,rpc,signer,now});
    }finally{busy=false;}
  }});
}
