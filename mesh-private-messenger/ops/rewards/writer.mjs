import { prepareRewardsTransaction, signRewardsTransaction } from './transactions.mjs';

const fence=ctx=>ctx.journal.renew(ctx.lease,ctx.now());
async function broadcast(ctx){
  fence(ctx);const packet=ctx.journal.authorizeBroadcast(ctx.lease,ctx.now());
  if(packet===null)return {state:'pending'};
  let state='broadcast';
  try{await ctx.rpc.broadcast(packet);}catch{state='unacknowledged';}
  fence(ctx);return {state,signature:packet.signature};
}

// Every cycle either reconciles the one existing packet or obtains a fresh
// authenticated Mesh plan. Only the journal's stored bytes can be broadcast.
export async function runRewardsCycle(ctx){
  fence(ctx);
  const pending=ctx.journal.pending();
  if(pending){
    if(pending.phase==='reserved'){
      ctx.journal.abandonUnsigned(ctx.lease,ctx.now());return {state:'unsigned-abandoned'};
    }
    const step=prepareRewardsTransaction(pending.plan,ctx.pins);
    const observation=await ctx.rpc.observe(step,pending.signed,async({minContextSlot})=>{
      fence(ctx);
      const effect=await ctx.planner.effect(ctx.journal.planningRequest(),pending.plan,minContextSlot);
      fence(ctx);return effect;
    });
    fence(ctx);
    if(['finalized','expired','effect'].includes(observation.state)){
      ctx.journal.finish(ctx.lease,observation,ctx.now());
      return {state:observation.state==='finalized'&&!observation.success?'failed':observation.state};
    }
    if(observation.state==='expiry-barrier')return {state:'expiry-barrier'};
    if(observation.state!=='pending')throw new Error('Unknown rewards observation');
    return broadcast(ctx);
  }
  if(ctx.journal.progress().scheduleComplete)return {state:'complete',reason:'complete'};
  const plan=await ctx.planner.plan(ctx.journal.planningRequest(),ctx.journal.progress().contextSlot);
  fence(ctx);const accepted=ctx.journal.acceptPlan(ctx.lease,plan,ctx.now());
  if(plan.status==='complete'||plan.status==='waiting')return accepted;
  const step=prepareRewardsTransaction(plan,ctx.pins);
  const quote=await ctx.rpc.quote(step);fence(ctx);
  ctx.journal.reserve(ctx.lease,plan,quote,ctx.now());
  const signers=ctx.signers.filter(signer=>plan.signer_keys.includes(signer.address));
  const signed=await signRewardsTransaction(step,signers,{blockhash:quote.blockhash,lastValidBlockHeight:BigInt(quote.lastValidBlockHeight)});
  fence(ctx);await ctx.journal.recordSigned(ctx.lease,signed,ctx.now);
  return broadcast(ctx);
}
