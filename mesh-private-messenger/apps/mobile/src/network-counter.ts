// Display decoder only. RPC authentication, pin binding, accounting and the
// historical-slash cache belong to Mesh; this frame is not an anchor verdict.
export type NetworkBondRow = {
  witness_id:string; operator_label:string; public_key:string; address:string; owner:string; mint:string|null; vault:string|null;
  asset:'USDC'|'MORSE'|'legacy'|'unassigned'; layout:1|2; status:0|1|2|3|4;
  principal_units:string|null; pending_units:string|null; pending_recorded_units:string|null;
  balance_units:string|null; donation_units:string|null; opposite_balance_units:string|null;
  usdc_vault_units:string|null; morse_vault_units:string|null;
  bonded_at:string; unbond_at:string; slashed_at:string; underwater_since:string; usd_micros:string|null;
};
export type NetworkBondObservation = {
  context_slot:string; bank_time:string; observed_at:string; digest:string; log_name:'morse-main'; judge:string;
  service_slashed:boolean; witnesses_slashed:number; valuation:'available'|'unavailable'|'unconfigured';
  twap_usd_micros:string|null; rows:NetworkBondRow[];
};
export type NetworkSlashFact = {index:number; witness_id:string; public_key:string; context_slot:string; bank_time:string; digest:string};
export type NetworkCounterReport = {
  schema_version:1; status:'available'|'historical'|'unavailable'|'unconfigured'; reason:string;
  config_id:string; checked_at:string; slash_mask:number; slash_history:NetworkSlashFact[]; observation:NetworkBondObservation|null;
};
function bad():never {throw new Error('Invalid native network counter');}
const object=(value:unknown):Record<string,any> => value!==null && typeof value==='object' && !Array.isArray(value) ? value as Record<string,any> : bad();
const hash=(value:unknown)=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const address=(value:unknown)=>typeof value==='string'&&/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
const integer=(value:unknown,max=18446744073709551615n):value is string=>typeof value==='string'&&/^(0|[1-9][0-9]{0,38})$/.test(value)&&BigInt(value)<=max;
const optional=(value:unknown)=>value===null||integer(value);
const finite=(value:unknown,min:number,max:number)=>typeof value==='number'&&Number.isInteger(value)&&value>=min&&value<=max;

export function parseNetworkCounter(input:Uint8Array):NetworkCounterReport {
  if(input.length<5||input.length>32768)bad();
  let decoded:any;try {const text=new TextDecoder('utf-8',{fatal:true}).decode(input);if(!text.startsWith('NCR1'))bad();decoded=JSON.parse(text.slice(4));}catch{bad();}
  const x=object(decoded);
  if(x.schema_version!==1||!['available','historical','unavailable','unconfigured'].includes(x.status)||typeof x.reason!=='string'||! /^[a-z0-9_-]{1,64}$/.test(x.reason)||
    !(x.config_id===''||hash(x.config_id))||!integer(x.checked_at)||!finite(x.slash_mask,0,131071))bad();
  if(!Array.isArray(x.slash_history)||x.slash_history.length>17)bad();
  let historicMask=0;const historicIndices=new Set<number>();
  for(const v of x.slash_history){const f=object(v);if(!finite(f.index,0,16)||historicIndices.has(f.index)||typeof f.witness_id!=='string'||(f.index===0?f.witness_id!=='':!/^[a-z0-9-]{1,64}$/.test(f.witness_id))||!hash(f.public_key)||!integer(f.context_slot)||!integer(f.bank_time)||!hash(f.digest))bad();historicIndices.add(f.index);historicMask+=2**f.index;}
  if(x.slash_history.length>0&&!hash(x.config_id))bad();
  if(x.observation===null){if(x.status==='available'||x.slash_mask!==0||(x.status==='historical'&&x.slash_history.length===0))bad();return x as NetworkCounterReport;}
  if(!['available','historical'].includes(x.status)||!hash(x.config_id)||x.reason==='slash-contradiction')bad();
  const o=object(x.observation);
  if(!integer(o.context_slot)||!integer(o.bank_time)||!integer(o.observed_at)||!hash(o.digest)||o.log_name!=='morse-main'||!address(o.judge)||
    typeof o.service_slashed!=='boolean'||!finite(o.witnesses_slashed,0,16)||!['available','unavailable','unconfigured'].includes(o.valuation)||!optional(o.twap_usd_micros)||
    !Array.isArray(o.rows)||o.rows.length<1||o.rows.length>17)bad();
  if((o.valuation==='available')!==(o.twap_usd_micros!==null))bad();
  let mask=o.service_slashed?1:0, slashed=0;
  const seen=new Set<string>();
  o.rows.forEach((value:unknown,i:number)=>{
    const r=object(value);
    if(typeof r.witness_id!=='string'||(i===0?r.witness_id!=='':!/^[a-z0-9-]{1,64}$/.test(r.witness_id))||typeof r.operator_label!=='string'||r.operator_label.length<1||r.operator_label.length>48||
      !hash(r.public_key)||![r.address,r.owner].every(address)||![r.mint,r.vault].every(value=>value===null||address(value))||!['USDC','MORSE','legacy','unassigned'].includes(r.asset)||![1,2].includes(r.layout)||!finite(r.status,0,4)||
      ![r.principal_units,r.pending_units,r.pending_recorded_units,r.balance_units,r.donation_units,r.opposite_balance_units,r.usdc_vault_units,r.morse_vault_units].every(optional)||
      ![r.bonded_at,r.unbond_at,r.slashed_at,r.underwater_since].every(value=>integer(value))||!(r.usd_micros===null||integer(r.usd_micros,340282366920938463463374607431768211455n)))bad();
    if(i===0&&r.public_key!=='00'.repeat(32))bad();
    if(i>0){if(seen.has(r.witness_id))bad();seen.add(r.witness_id);}
    if(r.status===0){if(r.asset!=='unassigned'||r.mint!==null||r.vault!==null||[r.principal_units,r.pending_units,r.balance_units,r.donation_units].some(v=>v!==null))bad();}
    else {
      if(r.asset==='unassigned'||r.mint===null||r.vault===null)bad();
      if(r.principal_units===null||r.balance_units===null||r.donation_units===null)bad();
      if(r.asset==='legacy') {if(r.usdc_vault_units!==null||r.morse_vault_units!==null)bad();if(r.layout!==1||r.pending_units!==null||r.pending_recorded_units!==null||r.usd_micros!==null)bad();}
      else if(r.pending_units===null||r.pending_recorded_units===null)bad();
      if(r.asset==='USDC'&&(r.balance_units!==r.usdc_vault_units||r.opposite_balance_units!==r.morse_vault_units))bad();
      if(r.asset==='MORSE'&&(r.balance_units!==r.morse_vault_units||r.opposite_balance_units!==r.usdc_vault_units))bad();
      if(BigInt(r.principal_units)+BigInt(r.pending_units??'0')+BigInt(r.donation_units)!==BigInt(r.balance_units))bad();
      if(r.pending_units!==null&&BigInt(r.pending_units)>BigInt(r.pending_recorded_units))bad();
      if((r.status===3||r.status===4)&&r.principal_units!=='0')bad();
    }
    if(r.usd_micros!==null&&(o.valuation!=='available'||r.asset!=='MORSE'))bad();
    if(i===0&&o.service_slashed!==(r.status===3))bad();
    if(i>0&&r.status===3){mask+=2**i;slashed++;}
  });
  if(mask!==x.slash_mask||slashed!==o.witnesses_slashed)bad();
  if(x.status==='available'&&(historicMask&mask)!==historicMask)bad();
  for(const fact of x.slash_history){if(fact.index>=o.rows.length||fact.witness_id!==o.rows[fact.index].witness_id||fact.public_key!==o.rows[fact.index].public_key)bad();}
  return x as NetworkCounterReport;
}

export function formatNetworkUnits(units:string|null):string|null {
  if(units===null)return null;
  if(!integer(units,340282366920938463463374607431768211455n))bad();
  const padded=units.padStart(7,'0');const fraction=padded.slice(-6).replace(/0+$/,'');
  return padded.slice(0,-6)+(fraction?`.${fraction}`:'');
}
// Presentation can only downgrade a Mesh-authenticated observation. It never
// promotes historical/unavailable state, authenticates accounts or changes the
// anchor verdict. BigInt preserves native u64 times without Number coercion.
export function networkCounterForDisplay(value:NetworkCounterReport, nowMs:number, previousSampleMs?:number):NetworkCounterReport {
  if(value.status!=='available')return value;
  const historical=(reason:string):NetworkCounterReport=>({...value,status:'historical',reason});
  if(!Number.isSafeInteger(nowMs)||nowMs<0)return historical('counter-display-clock');
  if(previousSampleMs!==undefined){
    if(!Number.isSafeInteger(previousSampleMs)||previousSampleMs<0)return historical('counter-display-clock');
    if(nowMs<previousSampleMs)return historical('clock-rollback');
  }
  const now=BigInt(nowMs),checked=BigInt(value.checked_at),bank=BigInt(value.observation!.bank_time);
  if(now<checked||now/1000n<bank)return historical('clock-rollback');
  // Match Mesh counter_fresh exactly: the entire bank+120 second is valid.
  if(now/1000n-bank>120n)return historical('counter-stale-display');
  return value;
}
export function networkCounterSummary(value:NetworkCounterReport, nowMs=Date.now()):NetworkCounterReport['status'] {
  return networkCounterForDisplay(value,nowMs).status;
}
