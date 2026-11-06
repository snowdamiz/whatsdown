import { prepareRelayTransactions, signRelayStep } from './transactions.mjs';
import { createRelayEffectReader } from './effects.mjs';

function prepared(job,id){
  const plan=job.plan,value=prepareRelayTransactions(plan,{...plan,proofHex:plan.proof_hex});
  const steps=[...value.preparation,...(value.needsLookup?value.lookup:[]),value.settlement,...value.cleanup];
  const step=steps.find(value=>value.id===id);
  if(!step)throw new Error('Unknown journaled relay step');
  return step;
}
function fence({journal,lease,now}){journal.renew(lease,now());}
async function broadcast(context,id){
  fence(context);
  const packet=context.journal.authorizeBroadcast(context.lease,id,context.now());
  if(packet===null)return {state:'pending'};
  try{await context.rpc.broadcast(packet);return {state:'broadcast'};}
  catch{return {state:'unacknowledged'};}
}

// Scheduling/admission chooses the step and supplies locally authenticated Mesh
// views. This execution boundary never accepts HTTP-provided plans or packets.
// All asynchronous quote, signing and observation work is fenced again before
// its result can mutate the journal or authorize a broadcast.
export async function submitRelayStep(context){
  fence(context);
  const {journal,lease,rpc,signer,proofHash,stepId,now}=context;
  const job=journal.job(proofHash),step=prepared(job,stepId);
  const view=context.lookupView===undefined?undefined:structuredClone(context.lookupView);
  const quote=await rpc.quote(step,view);
  fence(context);
  const row=journal.reserve(lease,proofHash,stepId,quote,now(),view);
  let signed;
  try{
    signed=await signRelayStep(step,signer,{blockhash:quote.blockhash,lastValidBlockHeight:BigInt(quote.lastValidBlockHeight)},view);
  }catch{throw new Error('Relay signing failed; unsigned reservation retained');}
  fence(context);
  await journal.recordSigned(lease,row.id,signed,now());
  return broadcast(context,row.id);
}

// Restart recovery needs no wallet. An unrecorded signature could never have
// passed authorizeBroadcast; abandoning only that unsigned reservation is safe.
// A persisted signature is reconciled and, when necessary, resent unchanged.
export async function recoverRelayPending(context){
  fence(context);
  const {journal,lease,rpc,now}=context,row=journal.pending();
  if(row===null)return {state:'idle'};
  if(row.phase==='reserved'){
    journal.abandonUnsigned(lease,row.id,now());return {state:'unsigned-abandoned'};
  }
  const job=journal.job(row.proofHash),step=prepared(job,row.stepId);
  const reader=context.readEffect??(context.verifier?createRelayEffectReader(context.verifier):undefined);
  const readEffect=reader?request=>reader(job,step,request):undefined;
  const observation=await rpc.observe(step,row.signed,readEffect);
  fence(context);
  switch(observation.state){
    case 'finalized':
      journal.finalize(lease,row.id,observation,now());
      return {state:observation.success?'finalized':'failed'};
    case 'expired':
      if(!readEffect)throw new Error('Relay expiry requires a Mesh effect reader');
      journal.expire(lease,row.id,observation,now());return {state:'expired'};
    case 'effect':
      if(!readEffect)throw new Error('Relay recovery requires a Mesh effect reader');
      journal.observeEffect(lease,row.id,observation,now());return {state:'effect'};
    case 'expiry-barrier':return {state:'expiry-barrier'};
    case 'pending':return broadcast(context,row.id);
    default:throw new Error('Unknown relay reconciliation result');
  }
}
