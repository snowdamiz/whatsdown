import { relayStepEffect } from './transactions.mjs';

function slot(value){
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>18446744073709551615n)throw new Error('Invalid relay effect context');
  return BigInt(value);
}

// The native wrapper supplies authenticated Mesh state, never HTTP-provided
// reports. This adapter selects the effects of one opaque transaction recipe;
// it neither verifies proofs nor interprets raw Solana account data. Exceptions
// remain exceptions. A caller still needs the finalized expiry barrier before
// an absent/present effect can release or charge an unresolved reservation.
export function createRelayEffectReader(verifier){
  return async(job,step,{minContextSlot})=>{
    const effect=relayStepEffect(step,job.plan);
    const floor=(slot(minContextSlot)>slot(effect.minContextSlot)?minContextSlot:effect.minContextSlot);
    let view,present,context;
    switch(effect.kind){
      case 'initialize':case 'append':case 'seal':case 'verify':case 'close-stage':{
        view=await verifier.stage(job.plan,floor);context=view.context_slot;
        if(effect.kind==='initialize')present=view.status!=='missing';
        if(effect.kind==='close-stage')present=view.status==='missing';
        if(effect.kind==='append')present=view.received_bytes>=effect.receivedBytes;
        if(effect.kind==='seal')present=view.sealed;
        if(effect.kind==='verify'){
          present=true;
          for(const expected of effect.signatures){
            const found=view.verified.find(value=>value.ordinal===expected.ordinal);
            if(!found)present=false;
            else if(found.public_key!==expected.public_key)throw new Error('Relay earned signature key changed');
          }
        }
        break;
      }
      case 'setup':
        view=await verifier.destinations(job.plan,floor);context=view.context_slot;
        present=view[effect.destination].status==='ready';break;
      case 'settle':
        view=await verifier.receipt(job.plan,floor);context=view.context_slot;
        present=view.status==='settled';break;
      case 'create-table':case 'extend-table':case 'deactivate-table':case 'close-table':
        view=await verifier.lookup(job.plan,floor,{closing:['deactivate-table','close-table'].includes(effect.kind)});context=view.contextSlot;
        if(effect.kind==='create-table')present=view.status!=='missing';
        if(effect.kind==='extend-table')present=view.addresses.length>=effect.addressCount;
        if(effect.kind==='deactivate-table')present=['missing','cooling','closable'].includes(view.status);
        if(effect.kind==='close-table')present=view.status==='missing';break;
      default:throw new Error('Unknown relay step effect');
    }
    if(slot(context)<slot(floor)||typeof present!=='boolean')throw new Error('Invalid relay effect context or state');
    return {state:present?'present':'absent',slot:context};
  };
}
