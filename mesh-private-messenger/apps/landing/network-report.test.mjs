import assert from 'node:assert/strict';
import test from 'node:test';
import './network-history.js';
import './network-report.js';
const api = globalThis.MorseNetworkReport;

const bootstrap = { schema_version: 1, scope: 'bootstrap', generated_at_unix: null, max_age_seconds: null, provider_independence: 'not-established', history_completeness: 'selected-epochs-only', phase5_complete: false, burns: [], bonds: { availability: 'unavailable' }, slashes: { availability: 'unavailable' } };
test('bootstrap and unavailable reports never become zero burns or live execution claims', () => {
  assert.equal(api.validateReport(bootstrap), bootstrap);
  assert.equal(api.reportState(bootstrap, 1000), 'bootstrap');
  const unavailable = { ...bootstrap, scope: 'configured-rpc', generated_at_unix: '1000', max_age_seconds: '60', burns: [{ epoch: '1', availability: 'unavailable' }] };
  assert.equal(api.reportState(unavailable, 1000), 'unavailable');
  assert.equal(api.reportState({ ...unavailable, burns: [{ epoch: '1', availability: 'disagreed' }] }, 1000), 'disagreed');
  assert.equal(api.reportState({ ...unavailable, scope: 'local-fixture' }, 1000), 'local-fixture');
  assert.throws(() => api.validateReport({ ...bootstrap, phase5_complete: true }));
});
test('exact token display preserves integers beyond JavaScript safe precision and rejects malformed input', () => {
  assert.equal(api.formatUnits('9007199254740993000'), '9,007,199,254,740.993000');
  assert.equal(api.formatUnits('17'), '0.000017');
  for (const amount of ['01', '-1', '1e6', 1000000, '18446744073709551616', '<img>']) assert.throws(() => api.formatUnits(amount));
});

test('v2 selected collateral stays asset-separated and prepared amounts remain unavailable', async () => {
  const fs = await import('node:fs');
  const report = JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/mixed-collateral-report.json', import.meta.url)));
  assert.equal(api.validateReport(report), report);
  assert.equal(report.slashes.receipts[0].verified_signature_mask, '63');
  assert.equal(report.slashes.receipts[0].verified_signatures, '6');
  const now = Number(report.bonds.source_time_unix);
  const configured = { ...report, scope: 'configured-rpc' };
  assert.equal(api.reportState(configured, now), 'available');
  assert.equal(api.reportState({ ...configured, bonds: { ...report.bonds, code_current: false } }, now), 'code-changed');
  assert.equal(api.reportState(configured, now + 901), 'stale');
  assert.equal(api.reportState({ ...configured, bonds: { availability: 'disagreed' } }, now), 'disagreed');
  for (const mutate of [
    value => { value.bonds.schema_version = 1; },
    value => { value.bonds.rows[0].asset = 'USD'; },
    value => { value.bonds.rows[0].principal_units = 1; },
    value => { value.bonds.rows[0].pending_liability_units = '-1'; },
    value => { value.bonds.rows[0].opposite_asset_vault = { availability: 'absent', balance_units: '0' }; },
    value => { value.slashes.receipts[0].status = 'prepared'; },
    value => { value.slashes.receipts[0].verified_signatures = '65'; },
    value => { delete value.slashes.receipts[0].verified_signature_mask; },
    value => { value.slashes.receipts[0].assets.push(value.slashes.receipts[0].assets[0]); },
    value => { value.slashes.receipts[0].rows[0].finder_units = '1e6'; },
    value => { value.slashes.selection_scope = 'complete-history'; },
    value => { value.scope = 'bootstrap'; value.burns = []; },
  ]) { const copy = structuredClone(report); mutate(copy); assert.throws(() => api.validateReport(copy)); }
  const unavailable = { ...configured, bonds: { availability: 'unavailable' }, slashes: { availability: 'unavailable' } };
  assert.equal(api.reportState(unavailable, now), 'unavailable');
});

test('publication envelopes keep failed current data separate from retained settled observations', async () => {
  const fs = await import('node:fs');
  const value = JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/legacy-settled-history-report.json', import.meta.url)));
  const s = value.history.proofs.pages[0].values;
  const envelope = { schema_version: 1, policy: 'morse-public-snapshot-v1', generation: 1, status: 'unavailable',
    generated_at_unix: value.generated_at_unix, last_attempt_at_unix: value.generated_at_unix, policy_sha256: 'a'.repeat(64), generator_sha256: 'b'.repeat(64),
    provider_independence: 'not-established', phase5_complete: false, current: null, last_good: { report: value, report_sha256: 'c'.repeat(64), completed_at_unix: value.generated_at_unix },
    observations: [], refused_new_settled_observations: 0, settled_history: [{ identity: 'owned-ledger-key', schema_version: 1,
      judge: s.judge, log_id: s.log_id, source_time_unix: s.source_time_unix, context_slot: s.context_slot,
      first_observed_at_unix: value.generated_at_unix, last_observed_at_unix: value.generated_at_unix, receipt: s.receipts[0] }] };
  assert.equal(api.validatePublication(envelope), envelope);
  assert.throws(() => api.validatePublication({ ...envelope, status: 'available' }));
  assert.throws(() => api.validatePublication({ ...envelope, current: value }));
  assert.throws(() => api.validatePublication({ ...envelope, phase5_complete: true }));
  const malformed = structuredClone(envelope); malformed.settled_history[0].receipt.status = 'prepared';
  assert.throws(() => api.validatePublication(malformed));
});
