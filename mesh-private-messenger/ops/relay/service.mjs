import { setTimeout as sleep } from 'node:timers/promises';

// Public requests supply bytes only. All plans and receipts originate in the
// operator-owned Mesh verifier. The service serializes admission with recovery
// so the native process and durable writer cannot be raced by HTTP traffic.
export function createRelayService({journal,verifier,scheduler,now=Date.now,maxQueued=16}) {
  if (!Number.isSafeInteger(maxQueued)||maxQueued<1||maxQueued>64) throw new Error('Invalid relay queue limit');
  const entries=new Set();let active=null,closed=false;
  function finish(entry,error,result) {
    entries.delete(entry);entry.signal?.removeEventListener('abort',entry.abort);
    if(error)entry.reject(error);else entry.resolve(result);
  }
  const service={
    async submit(wire,{signal}={}) {
      if(closed)throw new Error('Relay service closed');
      if(!(wire instanceof Uint8Array)||!wire.length||wire.length>8192)throw new Error('Invalid relay evidence size');
      if(signal?.aborted)throw new Error('Relay admission cancelled');
      if(entries.size>=maxQueued)throw new Error('Relay service busy');
      const bytes=Buffer.from(wire);
      return new Promise((resolve,reject)=>{
        const entry={bytes,resolve,reject,signal,controller:new AbortController(),started:false};
        entry.abort=()=>{entry.controller.abort();finish(entry,new Error('Relay admission cancelled'));};
        entries.add(entry);signal?.addEventListener('abort',entry.abort,{once:true});
        if(signal?.aborted)entry.abort();
      });
    },
    async cycle() {
      if(closed)return {scheduler:{state:'closed'}};
      if(active)return {scheduler:{state:'busy'}};
      active=(async()=>{
        let state;
        try{state=await scheduler.tick();}catch{state={state:'unavailable'};}
        if(closed)return {scheduler:state};
        const entry=[...entries].find(value=>!value.started);
        if(!entry)return {scheduler:state};
        entry.started=true;
        try{
          const admission=await verifier.admit(entry.bytes,journal.retention().minContextSlot,{signal:entry.controller.signal});
          if(closed||entry.controller.signal.aborted)throw new Error('cancelled');
          if(admission.status==='settled') {
            const {proof_hash,finder}=admission.receipt;
            finish(entry,null,{schema_version:1,status:'settled',proof_hash,finder});
          }else if(admission.status==='ready') {
            const accepted=journal.accept(admission,now());
            finish(entry,null,{schema_version:1,status:'queued',proof_hash:accepted.proofHash,finder:accepted.finder,duplicate:accepted.duplicate});
          }else throw new Error('Invalid admission result');
        }catch{
          finish(entry,new Error(closed?'Relay service closed':entry.controller.signal.aborted?'Relay admission cancelled':'Relay admission unavailable'));
        }
        return {scheduler:state};
      })();
      try{return await active;}finally{active=null;}
    },
    async close() {
      closed=true;
      for(const entry of entries){entry.controller.abort();finish(entry,new Error('Relay service closed'));}
      await active;
    },
  };
  return Object.freeze(service);
}


export async function runRelayLoop(service,{signal,intervalMs=250,onCycle=()=>{}}) {
  if(!signal||!Number.isSafeInteger(intervalMs)||intervalMs<1||intervalMs>60000)throw new Error('Invalid relay loop configuration');
  while(!signal.aborted) {
    const result=await service.cycle();onCycle(result);
    if(signal.aborted)break;
    try{await sleep(intervalMs,undefined,{signal});}catch(error){if(!signal.aborted)throw error;}
  }
}
