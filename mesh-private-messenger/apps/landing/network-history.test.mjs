import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import './network-history.js';
import './network-report.js';
const api = globalThis.MorseNetworkReport;
const read = name => JSON.parse(fs.readFileSync(new URL(`../../ops/public-chain/fixtures/${name}-history-report.json`, import.meta.url)));
const configured = name => ({ ...read(name), scope: 'configured-rpc' });

test('actual Mesh discovery retains all 65 identities and four funded frames without a cross-bank total', () => {
  for (const name of ['burn', 'collateral']) {
    const value = configured(name); assert.equal(api.validateReport(value), value);
    assert.equal(value.history.global_totals, null);
    assert.equal(api.reportState(value, Number(value.generated_at_unix)), 'available');
  }
  const value = configured('collateral');
  assert.equal(value.history.witnesses.records.length, 65);
  assert.equal(value.history.witnesses.records.filter(row => row.value_status === 'registry-only').length, 63);
  assert.equal(value.history.witnesses.pages.length, 2);
});

test('page completeness and identity binding are strict across every applicable indexed identifier', () => {
  for (const mutate of [
    x => x.history.witnesses.pages.pop(),
    x => x.history.witnesses.pages.push(x.history.witnesses.pages[0]),
    x => x.history.witnesses.pages[0].requested_addresses.push(x.history.witnesses.pages[1].requested_addresses[0]),
    x => x.history.witnesses.pages[0].values.rows[1].witness_id = 'someone-else',
    x => x.history.witnesses.pages[0].values.log_id = '11'.repeat(32),
    x => x.history.witnesses.pages[0].values.context_slot = '99999',
    x => x.history.proofs.pages[0].values.receipts[0].proof_hash = '22'.repeat(32),
    x => x.history.proofs.records[0].version = 1,
    x => x.history.proofs.records.push(x.history.proofs.records[0]),
    x => x.history.witnesses.record_count--,
    x => x.history.global_totals = '0',
    x => x.history.witnesses.discovery_scope = 'complete-chain-history',
    x => x.history.witnesses.upper_bound = 64,
    x => x.history.witnesses.pages[0].complete = false,
    x => x.history.witnesses.release_pins.pop(),
    x => x.history.witnesses.release_pins[0].deployment_slot = 0,
    x => x.history.witnesses.release_pins[0].program = x.history.witnesses.records[0].address,
  ]) { const value = configured('collateral'); mutate(value); assert.throws(() => api.validateReport(value)); }
  for (const mutate of [
    x => x.history.burns.pages[0].values[0].week_address = x.history.burns.program,
    x => x.history.burns.pages[0].values[0].epoch = '9999',
    x => x.history.burns.pages[0].values[0].program = x.history.burns.records[0].address,
    x => x.history.burns.pages[0].values.pop(),
  ]) { const value = configured('burn'); mutate(value); assert.throws(() => api.validateReport(value)); }
});

test('index bank and every separate value bank participate in stale/code/disagreement state', () => {
  const base = configured('collateral'), now = Number(base.generated_at_unix);
  for (const mutate of [x => x.history.witnesses.code_current = false, x => x.history.witnesses.pages[0].values.code_current = false]) {
    const value = structuredClone(base); mutate(value); assert.equal(api.reportState(value, now), 'code-changed');
  }
  for (const mutate of [x => x.history.witnesses.source_time_unix = String(now - 901), x => x.history.witnesses.pages[1].values.source_time_unix = String(now - 901), x => x.history.proofs.pages[0].values.source_time_unix = String(now + 61)]) {
    const value = structuredClone(base); mutate(value); assert.equal(api.reportState(value, now), 'stale');
  }
  const value = structuredClone(base); value.history.witnesses.pages[0].values = { availability: 'disagreed' }; value.history.witnesses.pages[0].complete = false; value.history.witnesses.value_completeness = 'incomplete';
  assert.equal(api.reportState(value, now), 'disagreed');
  const missing = structuredClone(base); missing.history.witnesses.pages[0].values = { availability: 'unavailable' }; missing.history.witnesses.pages[0].complete = false; missing.history.witnesses.value_completeness = 'incomplete';
  assert.equal(api.reportState(missing, now), 'incomplete');
});

test('unvalidated layouts, legacy identifiers and registry-only entries cannot gain value pages or amounts', () => {
  const value = configured('collateral'); const proof = value.history.proofs;
  proof.records[0] = { ...proof.records[0], version: 99, verification: 'unsupported-layout', canonical_identity: false, proof_hash: null, value_status: 'unsupported' };
  proof.pages = []; proof.supported_layouts_complete = false; proof.value_completeness = 'incomplete';
  assert.equal(api.validateReport(value), value); assert.equal(api.reportState(value, Number(value.generated_at_unix)), 'incomplete');
  const wrong = structuredClone(value); wrong.history.proofs.records[0].canonical_identity = true; assert.throws(() => api.validateReport(wrong));
  proof.records[0] = { ...proof.records[0], version: 1, verification: 'legacy', canonical_identity: true, proof_hash: '12'.repeat(32), value_status: 'legacy-unrendered' }; proof.supported_layouts_complete = true;
  assert.equal(api.validateReport(value), value);
  const noHistory = read('burn'); delete noHistory.history; noHistory.history_completeness = 'selected-epochs-only'; assert.equal(api.validateReport(noHistory), noHistory);
  assert.throws(() => api.validateReport({ ...noHistory, history_completeness: 'bounded-filtered-index-with-separate-value-pages' }));
});
