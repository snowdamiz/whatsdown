import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseNetworkCounter, formatNetworkUnits, networkCounterSummary, networkCounterForDisplay } from './network-counter.ts';
const key = '11111111111111111111111111111111';
const row = (asset='MORSE') => ({ witness_id:'', operator_label:'Morse', public_key:'00'.repeat(32), address:key, owner:key, mint:key, vault:key, asset, layout:2, status:1,
  principal_units:'18446744073709551600', pending_units:'7', pending_recorded_units:'7', balance_units:'18446744073709551615', donation_units:'8', opposite_balance_units:null,usdc_vault_units:null,morse_vault_units:'18446744073709551615',
  bonded_at:'1', unbond_at:'0', slashed_at:'0', underwater_since:'0', usd_micros:null });
const report = () => ({ schema_version:1, status:'available', reason:'fresh-finalized-quorum', config_id:'ab'.repeat(32), checked_at:'1700000000000', slash_mask:0,slash_history:[],
  observation:{context_slot:'18446744073709551615', bank_time:'1700000000', observed_at:'1700000000000', service_slashed:false, witnesses_slashed:0,
    digest:'cd'.repeat(32), log_name:'morse-main', judge:key, valuation:'unconfigured', twap_usd_micros:null, rows:[row()]}});
const wire = (value:unknown) => new TextEncoder().encode(`NCR1${JSON.stringify(value)}`);

test('native counter keeps all u64 amounts exact, separates assets and never formats unavailable as zero', () => {
  const parsed=parseNetworkCounter(wire(report()));
  assert.equal(parsed.observation!.rows[0]!.principal_units, '18446744073709551600');
  assert.equal(formatNetworkUnits('18446744073709551615'), '18446744073709.551615');
  assert.equal(formatNetworkUnits('1000000'), '1'); assert.equal(formatNetworkUnits('1'), '0.000001');
  assert.equal(formatNetworkUnits(null), null);
  const off=parseNetworkCounter(wire({schema_version:1,status:'unconfigured',reason:'counter-not-configured',config_id:'',checked_at:'1',slash_mask:0,slash_history:[],observation:null}));
  assert.equal(off.observation,null); assert.equal(networkCounterSummary(off),'unconfigured');
  const historical={...report(),status:'historical',reason:'counter_rpc_unavailable'};
  assert.equal(networkCounterSummary(parseNetworkCounter(wire(historical))),'historical');
});

test('malformed or inconsistent native counter frames fail closed without an anchor status mutation', () => {
  for(const mutate of [
    (x:any)=>{x.observation.log_name='morse-canary'},
    (x:any)=>{x.observation.rows[0].principal_units='18446744073709551616'},
    (x:any)=>{x.observation.rows[0].balance_units='0'},
    (x:any)=>{x.observation.rows[0].donation_units='7'},
    (x:any)=>{x.observation.rows[0].asset='USD'},
    (x:any)=>{x.observation.rows[0].usd_micros='0'},
    (x:any)=>{x.observation.service_slashed=true},
    (x:any)=>{x.observation.witnesses_slashed=1},
    (x:any)=>{x.status='unavailable'},
    (x:any)=>{x.observation.rows.push({...row(),witness_id:'x',public_key:'11'.repeat(32)});x.slash_mask=4},
    (x:any)=>{x.observation.rows=Array.from({length:18},()=>row())},
  ]) { const x=report();mutate(x); assert.throws(()=>parseNetworkCounter(wire(x))); }
  assert.throws(()=>parseNetworkCounter(new TextEncoder().encode('NCR2{}')));
  assert.throws(()=>parseNetworkCounter(new Uint8Array(32769)));
  assert.throws(()=>parseNetworkCounter(wire({...report(),schema_version:2})));
});

// A sealed native historical fact is separate from the current observed state.
test('retained slashes stay explicitly historical on failure or contradictory current state',()=>{
 const base=report();const fact={index:0,witness_id:'',public_key:'00'.repeat(32),context_slot:'123',bank_time:'1',digest:'ef'.repeat(32)};
 assert.throws(()=>parseNetworkCounter(wire({...base,slash_history:[fact]})));
 const prior=parseNetworkCounter(wire({...base,status:'historical',reason:'slash-contradiction',slash_history:[fact],observation:null}));
 assert.equal(prior.slash_history.length,1);assert.equal(prior.observation,null);
 const missing=parseNetworkCounter(wire({...base,status:'historical',reason:'counter_rpc_unavailable',slash_history:[fact],observation:null}));
 assert.equal(missing.observation,null);assert.equal(missing.slash_history[0]!.context_slot,'123');
 assert.throws(()=>parseNetworkCounter(wire({...base,status:'historical',slash_history:[fact,{...fact}]})));
});

test('actual Mesh maximum synthetic frame decodes all 17 rows and retained slash facts',()=>{
 const bytes=readFileSync(new URL('../../../ops/network-counter/fixtures/capacity.ncr',import.meta.url));
 const report=parseNetworkCounter(bytes);
 assert(bytes.length<=32768);assert.equal(report.status,'historical');
 assert.equal(report.checked_at,'18446744073709551615');assert.equal(report.observation?.context_slot,'18446744073709551615');
 assert.equal(report.observation?.rows.length,17);assert.equal(report.slash_history.length,17);
 for(const row of report.observation!.rows.slice(1)){assert.equal(row.operator_label.length,48);assert.equal(row.witness_id.length,64);}
 for(const fact of report.slash_history.slice(1)){assert.equal(fact.witness_id.length,64);assert.equal(fact.context_slot,'18446744073709551615');}
 assert.throws(()=>parseNetworkCounter(bytes.subarray(0,bytes.length-1)));
});

test('available counter display expires at the exact whole-second policy boundary and fails closed on clock rollback',()=>{
 const parsed=parseNetworkCounter(wire(report()));const at=1700000000000;
 assert.equal(networkCounterSummary(parsed,at+120999),'available');
 assert.equal(networkCounterSummary(parsed,at+121000),'historical');
 assert.equal(networkCounterSummary(parsed,at-1),'historical');
 for(const clock of [NaN,Infinity,-1,at+.5,Number.MAX_SAFE_INTEGER+1])assert.equal(networkCounterSummary(parsed,clock),'historical');
 assert.equal(parsed.status,'available','display summary does not mutate native input');
});


test('display expiry preserves exact rows and historical slashes, never resurrects after rollback or mutates native input',()=>{
 const original=parseNetworkCounter(wire(report()));
 const stale=networkCounterForDisplay(original,1700000121000);
 assert.equal(stale.status,'historical');assert.equal(stale.reason,'counter-stale-display');
 assert.equal(stale.observation,original.observation);assert.equal(stale.slash_history,original.slash_history);
 assert.equal(networkCounterForDisplay(stale,1700000000000),stale);
 assert.equal(networkCounterForDisplay(stale,NaN),stale);
 assert.equal(original.status,'available');
 const wide=parseNetworkCounter(wire({...report(),checked_at:'18446744073709551615',observation:{...report().observation,bank_time:'18446744073709551615'}}));
 assert.equal(networkCounterForDisplay(wide,Number.MAX_SAFE_INTEGER).status,'historical');
});

test('a backward display sample latches historical even above checked_at and preserves exact evidence',()=>{
 const original=parseNetworkCounter(wire(report()));const at=1700000000000;
 const fresh=networkCounterForDisplay(original,at+119000,at);
 assert.equal(fresh.status,'available');
 const rolled=networkCounterForDisplay(fresh,at+60000,at+119000);
 assert.equal(rolled.status,'historical');assert.equal(rolled.reason,'clock-rollback');
 assert.equal(rolled.observation,original.observation);assert.equal(rolled.slash_history,original.slash_history);
 assert.equal(networkCounterForDisplay(rolled,at+119000,at+60000),rolled);
 assert.equal(networkCounterForDisplay(original,at+60000,at+60000).status,'available','a newly accepted native report deliberately starts a new display sample sequence');
 assert.equal(original.status,'available');
});
