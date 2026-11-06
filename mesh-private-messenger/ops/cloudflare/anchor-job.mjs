import { assertIsAddress } from '@solana/kit';
import { anchorWriterConfig } from './anchor-config.mjs';
import { connectAnchorRpc } from './anchor-rpc.mjs';
import { openAnchorAccounts } from './anchor-accounts.mjs';
import { createAnchorDirectory } from './anchor-directory.mjs';
import { signAnchorPost, signAnchorCosigns } from './anchor-transactions.mjs';
import { AnchorCycle } from './anchor-cycle.mjs';

function context(response, minimum) {
  if (typeof response?.context?.slot !== 'bigint' || response.context.slot < minimum || response.context.slot > 18446744073709551615n) throw new Error('Anchor RPC context unavailable');
  return response.value;
}

export async function runAnchorJob(ctx,env,{fetcher=globalThis.fetch,clock=Date.now} = {}) {
  const config=await anchorWriterConfig(env);
  if(!config)return {mode:'off',issues:[]};
  const cycle=new AnchorCycle(ctx.storage,config.scope);
  const chain=await connectAnchorRpc({url:config.rpcUrl,genesisHash:config.genesisHash},fetcher);
  const accounts=await openAnchorAccounts(chain.rpc,config);
  const directory=createAnchorDirectory(env,{...config,logId:accounts.logId});
  const signerAccounts={...accounts,feePayer:config.feePayer,anchorAuthority:config.anchorAuthority};
  const report=await cycle.run(config,{
    snapshot:options=>accounts.readRing(options),
    logState:()=>accounts.logState,
    balance:async()=> {
      const floor=accounts.contextSlot;
      return context(await chain.rpc.getBalance(config.feePayer.address,{commitment:'finalized',minContextSlot:floor}).send(),floor);
    },
    blockTime:slot=>chain.rpc.getBlockTime(slot).send(),
    lifetime:async()=> {
      const floor=accounts.contextSlot;
      const value=context(await chain.rpc.getLatestBlockhash({commitment:'finalized',minContextSlot:floor}).send(),floor);
      assertIsAddress(value.blockhash);
      if(typeof value.lastValidBlockHeight!=='bigint' || value.lastValidBlockHeight<=0n || value.lastValidBlockHeight>18446744073709551615n) throw new Error('Invalid anchor transaction lifetime');
      return value;
    },
    candidate:()=>directory.candidate(),
    witnessSet:generation=>accounts.witnessSet(generation),
    cosigns:(entry,set)=>directory.cosigns(entry,set),
    signPost:async(material,lifetime)=>signAnchorPost(material,{...signerAccounts,attendance:await accounts.attendanceForPost()},lifetime),
    signCosigns:async(pairs,set,entry,lifetime)=>signAnchorCosigns(pairs,{...signerAccounts,generation:set.address,attendance:await accounts.attendanceForCosign(entry)},lifetime),
    observe:row=>chain.observe(row,accounts.readback),
    broadcast:transaction=>chain.broadcast(transaction),
    record:(intent,confirmation)=>directory.record(intent,confirmation),
  },clock);
  return {...report,program:config.program,logName:config.logName,feePayer:config.feePayer.address};
}
