import { rewardsCoordinate } from './transactions.mjs';

// Transport/persistence bounds only. Mesh authenticates the epoch and decides
// whether it is eligible, waiting, or complete before proposing advancement.
export function settlementRange(request,internal=false){
  if(!Object.hasOwn(request??{},'epoch_count'))return null;
  if(request.schema_version!==2||request.action!=='settle'||(!internal&&Object.hasOwn(request,'cursor')))throw new Error('Invalid rewards schedule request');
  const start=rewardsCoordinate(request.epoch),count=rewardsCoordinate(request.epoch_count);
  if(count<1n||count>256n||start+count>=(1n<<64n))throw new Error('Invalid rewards schedule range');
  return {start,last:start+count-1n};
}

export function validateSchedulePlan(plan,range,cursor){
  if(!range)return;
  const epoch=rewardsCoordinate(cursor);
  if(epoch<range.start||epoch>range.last||plan.epoch!==cursor)throw new Error('Rewards schedule epoch mismatch');
  const next=plan.status==='complete'&&epoch<range.last?(epoch+1n).toString():null;
  if(plan.next_epoch!==next||(plan.status==='complete'&&plan.action!=='complete'))throw new Error('Invalid rewards schedule advancement');
}
