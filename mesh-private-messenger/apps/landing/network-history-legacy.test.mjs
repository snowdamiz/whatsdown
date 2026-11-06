import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import './network-history.js';
import './network-report.js';
const api = globalThis.MorseNetworkReport;
const read = name => ({ ...JSON.parse(fs.readFileSync(new URL(`../../ops/public-chain/fixtures/legacy-${name}-history-report.json`, import.meta.url))), scope: 'configured-rpc' });
test('explicit legacy pages render only their versioned configured mint, including active and settled banks', () => {
  for(const name of ['active','settled']) {const report=read(name);assert.equal(api.validateReport(report),report);assert.equal(api.reportState(report,Number(report.generated_at_unix)),'available');}
});
test('legacy schema/asset/page identity cannot be confused with v2 or an unrelated bank', () => {
  for(const change of [
    x=>delete x.history.context_kind,
    x=>x.history.burns={...x.history.witnesses},
    x=>x.history.witnesses.release_pins.push(x.history.witnesses.release_pins[0]),
    x=>x.history.witnesses.mint=x.history.witnesses.program,
    x=>x.history.witnesses.pages[0].values.context_kind='v2',
    x=>x.history.witnesses.pages[0].values.schema_version=2,
    x=>x.history.witnesses.pages[0].values.decimals=9,
    x=>x.history.witnesses.pages[0].values.usdc_mint=x.history.witnesses.mint,
    x=>x.history.witnesses.pages[0].values.rows[1].public_key='00'.repeat(32),
    x=>x.history.witnesses.pages[0].values.rows[1].asset='USDC',
    x=>x.history.witnesses.pages[0].values.rows[1].pending_units='0',
    x=>x.history.witnesses.pages[0].values.context_slot='0',
    x=>x.history.witnesses.pages=[],
    x=>x.history.proofs.pages[0].values.receipts[0].version=2,
    x=>x.history.proofs.pages[0].values.receipts[0].verified_signatures='64',
    x=>x.history.proofs.pages[0].values.receipts[0].row_identity_scope='canonical-witness-id',
    x=>x.history.proofs.pages[0].values.receipts[0].total_slashed_units=600000000,
    x=>x.history.proofs.records[0].value_status='legacy-unrendered',
  ]) {const report=read('settled');change(report);assert.throws(()=>api.validateReport(report));}
});
test('legacy index and later pages retain independent code/freshness/disagreement states', () => {
  const base=read('settled'),now=Number(base.generated_at_unix);
  for(const change of [x=>x.history.witnesses.code_current=false,x=>x.history.proofs.pages[0].values.code_current=false]) {const v=structuredClone(base);change(v);assert.equal(api.reportState(v,now),'code-changed');}
  for(const change of [x=>x.history.witnesses.source_time_unix=String(now-901),x=>x.history.proofs.pages[0].values.source_time_unix=String(now-901)]) {const v=structuredClone(base);change(v);assert.equal(api.reportState(v,now),'stale');}
  const v=structuredClone(base);v.history.witnesses.pages[0].values={availability:'disagreed'};v.history.witnesses.pages[0].complete=false;v.history.witnesses.value_completeness='incomplete';assert.equal(api.reportState(v,now),'disagreed');
});

test('explicit legacy report cannot acquire unrelated selected v2 custody or burn sections',()=>{
 const current=JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/collateral-history-report.json',import.meta.url)));
 const burns=JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/burn-history-report.json',import.meta.url)));
 for(const change of [x=>x.burns=burns.burns,x=>x.bonds=current.bonds,x=>x.slashes=current.slashes]) {const report=read('settled');change(report);assert.throws(()=>api.validateReport(report));}
});
