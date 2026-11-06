// Finalized quorum transport shared by locally prepared chain writers.
// All protocol selection and effect verification belong to the Mesh callers.
export async function connectChainWriterRpc(config,adapter,platform,fetcher=globalThis.fetch){
  const {urls,genesisHash,allowLoopback=false,timeoutMs=3000}=config;
  const {assertIsAddress,createJsonRpcApi,createRpc,parseJsonWithBigInts,stringifyJsonWithBigInts}=platform;
  if(typeof adapter?.message!=='function'||typeof adapter?.signedStep!=='function')throw new Error('Invalid chain writer adapter');
const MAX=18446744073709551615n;
const fail=message=>{throw new Error(message);};
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value!==null&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
const same=(a,b)=>stringifyJsonWithBigInts(canonical(a))===stringifyJsonWithBigInts(canonical(b));
function uint(value){if(typeof value!=='bigint'||value<0n||value>MAX)fail('Invalid relay RPC integer');return value;}
function decimal(value){if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value))fail('Invalid relay RPC coordinate');return uint(BigInt(value));}
function contextual(value,floor){if(!value||uint(value.context?.slot)<floor)fail('Relay RPC context regressed');return value;}
async function successes(promises){return (await Promise.allSettled(promises)).filter(value=>value.status==='fulfilled').map(value=>value.value);}
function pair(values,equal=same){
  for(let i=0;i<values.length;i++)for(let j=i+1;j<values.length;j++)if(equal(values[i],values[j]))return [values[i],values[j]];
  fail('Relay RPC quorum unavailable');
}
const minimum=(a,b)=>a<b?a:b;
const maximum=(a,b)=>a>b?a:b;
async function body(response,signal){
  const reader=response.body?.getReader();if(!reader)fail('Empty RPC response');
  const chunks=[];let size=0;
  const abort=()=>{void reader.cancel().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});
  try{
    if(signal.aborted)fail('RPC response timed out');
    for(;;){
      const {done,value}=await reader.read();
      if(signal.aborted)fail('RPC response timed out');
      if(done)break;
      size+=value.length;if(size>262144)fail('RPC response exceeded limit');chunks.push(value);
    }
    return Buffer.concat(chunks);
  }finally{signal.removeEventListener('abort',abort);void reader.cancel().catch(()=>{});}
}
function status(response,floor){
  contextual(response,floor);
  if(!Array.isArray(response.value)||response.value.length!==1)fail('Invalid relay RPC status');
  const value=response.value[0];
  if(value!==null){
    if(!value||!['processed','confirmed','finalized',null].includes(value.confirmationStatus)||
      !Object.hasOwn(value,'err')||!validError(value.err)||uint(value.slot)>response.context.slot||
      (value.confirmationStatus==='finalized'&&value.confirmations!==null))fail('Invalid relay RPC status');
  }
  return {slot:response.context.slot,value};
}
function validError(value){return value===null||typeof value==='string'||(typeof value==='object'&&!Array.isArray(value));}
function transaction(value,signed,info,expected){
  if(!value||value.version!==0n||uint(value.slot)<decimal(signed.minContextSlot)||
    (expected&&value.slot!==expected.slot)||!same(value.transaction,[signed.wire,'base64']))fail('Relay RPC transaction changed');
  const meta=value.meta;
  if(!meta||!Object.hasOwn(meta,'err')||!validError(meta.err)||(expected&&!same(meta.err,expected.err))||
    !same(meta.loadedAddresses,info.loadedAddresses)||!Array.isArray(meta.preBalances)||!Array.isArray(meta.postBalances)||
    meta.preBalances.length!==info.accountKeys.length||meta.postBalances.length!==info.accountKeys.length)fail('Invalid relay RPC metadata');
  const fee=uint(meta.fee);if(fee===0n)fail('Invalid relay RPC fee');
  const pre=meta.preBalances.map(uint),post=meta.postBalances.map(uint);
  const funding=new Set(info.rentAllocations.map(value=>value.address));
  let gross=fee,total=0n;
  for(let index=0;index<pre.length;index++){
    const change=post[index]-pre[index];total+=change;
    if(index===0)continue;
    if(meta.err!==null&&change!==0n)fail('Failed relay transaction changed an account');
    if(change>0n){
      if(!funding.has(info.accountKeys[index]))fail('Unexpected relay lamport recipient');
      gross+=change;
    }
    if(change<0n&&info.accountKeys[index]!==info.refundAccount)fail('Unexpected relay lamport refund');
  }
  if(total!==-fee)fail('Relay balance metadata does not conserve fees');
  return {state:'finalized',success:meta.err===null,debitLamports:uint(gross).toString(),slot:value.slot.toString()};
}

// Exactly three independently operated pinned endpoints, with at most one
// dishonest provider. A timeout, pruned history or isolated missing response
// never releases money. Protocol effects are read by the local Mesh verifier.
  assertIsAddress(genesisHash);
  if(!Array.isArray(urls)||urls.length!==3||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>10000)fail('Invalid relay RPC configuration');
  const sources=urls.map(value=>{
    const url=new URL(value),local=['localhost','127.0.0.1','[::1]'].includes(url.hostname);
    if((url.protocol!=='https:'&&!(allowLoopback&&local&&url.protocol==='http:'))||url.username||url.password||url.hash)fail('Invalid relay RPC origin');
    return url;
  });
  const hostKey=url=>{
    if(allowLoopback&&['localhost','127.0.0.1','[::1]'].includes(url.hostname))return url.origin;
    const host=url.hostname.toLowerCase();
    return host.startsWith('[')||!host.endsWith('.')?host:host.slice(0,-1);
  };
  if(new Set(sources.map(hostKey)).size!==3)fail('Relay RPC sources must be independent');
  const clients=sources.map(url=>{
    const rpc=createRpc({api:createJsonRpcApi({responseTransformer:value=>value.result}),transport:async({payload,signal})=>{
      const deadline=AbortSignal.timeout(timeoutMs),cancel=signal?AbortSignal.any([signal,deadline]):deadline;
      try{
        const response=await fetcher(url.href,{method:'POST',headers:{'Content-Type':'application/json'},body:stringifyJsonWithBigInts(payload),redirect:'error',signal:cancel});
        if(!response.ok)fail('RPC HTTP error');
        const value=parseJsonWithBigInts(new TextDecoder('utf-8',{fatal:true}).decode(await body(response,cancel)));
        if(!value||Array.isArray(value)||value.jsonrpc!=='2.0'||value.id!==payload.id||!Object.hasOwn(value,'result')||Object.hasOwn(value,'error'))fail('Invalid RPC response');
        return value;
      }catch{fail('Relay RPC transport or response unavailable');}
    }});
    const check=async()=>{if(await rpc.getGenesisHash().send()!==genesisHash)fail('Relay RPC cluster mismatch');return rpc;};
    return {rpc,check};
  });
  if((await successes(clients.map(value=>value.check()))).length<2)fail('Relay RPC cluster quorum unavailable');
  const all=fn=>successes(clients.map(async client=>fn(await client.check())));
  return Object.freeze({
    async quote(step,view){
      const template=adapter.message(step,{blockhash:'11111111111111111111111111111111',lastValidBlockHeight:1n},view);
      if(template.rentAllocations===null)fail('Mesh rent allocations are required for a quote');
      const floor=decimal(template.minContextSlot);
      const lives=await all(async rpc=>{
        const value=contextual(await rpc.getLatestBlockhash({commitment:'finalized',minContextSlot:floor}).send(),floor);
        assertIsAddress(value.value?.blockhash);if(uint(value.value.lastValidBlockHeight)===0n)fail('Invalid relay lifetime');
        return {slot:value.context.slot,life:{blockhash:value.value.blockhash,lastValidBlockHeight:value.value.lastValidBlockHeight}};
      });
      const agreed=pair(lives,(a,b)=>same(a.life,b.life));
      const lifetime=agreed[0].life,contextFloor=minimum(agreed[0].slot,agreed[1].slot),info=adapter.message(step,lifetime,view);
      const costs=await all(async rpc=>{
        const fee=contextual(await rpc.getFeeForMessage(info.messageBase64,{commitment:'finalized',minContextSlot:contextFloor}).send(),contextFloor);
        if(uint(fee.value)===0n)fail('Invalid relay fee quote');
        const rents=await Promise.all(info.rentAllocations.map(async allocation=>uint(await rpc.getMinimumBalanceForRentExemption(BigInt(allocation.space),{commitment:'finalized'}).send())));
        return {slot:fee.context.slot,fee:fee.value,rents};
      });
      const quotes=pair(costs,(a,b)=>a.fee===b.fee&&same(a.rents,b.rents)),cost=quotes[0];
      const debit=uint(cost.rents.reduce((sum,value)=>sum+value,cost.fee));
      return {blockhash:lifetime.blockhash,lastValidBlockHeight:lifetime.lastValidBlockHeight.toString(),maxDebitLamports:debit.toString(),
        messageHash:info.messageHash,minContextSlot:info.minContextSlot,contextSlot:minimum(quotes[0].slot,quotes[1].slot).toString()};
    },
    async broadcast(signed){
      const floor=decimal(signed.minContextSlot);
      if(typeof signed.wire!=='string'||signed.wire.length>1644||typeof signed.signature!=='string')fail('Invalid relay packet');
      const bytes=Buffer.from(signed.wire,'base64');
      if(!bytes.length||bytes.length>1232||bytes.toString('base64')!==signed.wire)fail('Invalid relay packet');
      const accepted=await all(async rpc=>{
        if(await rpc.sendTransaction(signed.wire,{encoding:'base64',skipPreflight:false,preflightCommitment:'finalized',maxRetries:0n,minContextSlot:floor}).send()!==signed.signature)fail('Unexpected relay signature');
        return true;
      });
      if(!accepted.length)fail('Relay broadcast unacknowledged');
      return {accepted:accepted.length};
    },
    async observe(step,signed,readEffect){
      const info=await adapter.signedStep(step,signed);
      if(info.rentAllocations===null)fail('Mesh rent allocations are required for reconciliation');
      const floor=decimal(signed.minContextSlot),lastHeight=decimal(signed.lastValidBlockHeight);
      const values=await all(async rpc=>{
        const fetchStatus=async minimum=>status(await rpc.getSignatureStatuses([signed.signature],{searchTransactionHistory:true}).send(),minimum);
        const fetchTransaction=()=>rpc.getTransaction(signed.signature,{commitment:'finalized',encoding:'base64',maxSupportedTransactionVersion:0n}).send();
        const settle=async value=>value.confirmationStatus==='finalized'?transaction(await fetchTransaction(),signed,info,value):{state:'pending'};
        const first=await fetchStatus(floor);
        if(first.value!==null)return settle(first.value);
        const height=uint(await rpc.getBlockHeight({commitment:'finalized',minContextSlot:first.slot}).send());
        if(height<=lastHeight)return {state:'pending'};
        const barrier=uint(await rpc.getSlot({commitment:'finalized',minContextSlot:first.slot}).send());
        if(barrier<first.slot)fail('Relay finalized context regressed');
        const second=await fetchStatus(barrier);
        if(second.value!==null)return settle(second.value);
        const found=await fetchTransaction();if(found!==null)return transaction(found,signed,info);
        let historyCovered=false;
        try{historyCovered=uint(await rpc.getFirstAvailableBlock().send())<=floor;}catch{ /* Only authenticated effects can resolve missing history. */ }
        return {state:'barrier',slot:barrier,blockHeight:height,historyCovered};
      });
      try{return pair(values.filter(value=>value.state==='finalized'))[0];}catch{ /* Keep reservations until two providers agree. */ }
      let barriers;
      const available=values.filter(value=>value.state==='barrier');
      const covered=available.filter(value=>value.historyCovered);
      try{barriers=pair(covered.length>=2?covered:available,()=>true);}catch{return {state:'pending'};}
      const minimumSlot=maximum(barriers[0].slot,barriers[1].slot).toString();
      const blockHeight=minimum(barriers[0].blockHeight,barriers[1].blockHeight).toString();
      if(!readEffect)return {state:'expiry-barrier',slot:minimumSlot,blockHeight};
      const effect=await readEffect({minContextSlot:minimumSlot});
      if(!effect||!['present','absent'].includes(effect.state)||decimal(effect.slot)<decimal(minimumSlot))fail('Invalid Mesh effect or context');
      if(effect.state==='present')return {state:'effect',slot:effect.slot,blockHeight};
      if(!barriers.every(value=>value.historyCovered))return {state:'pending'};
      return {state:'expired',slot:effect.slot,blockHeight};
    },
  });
}
