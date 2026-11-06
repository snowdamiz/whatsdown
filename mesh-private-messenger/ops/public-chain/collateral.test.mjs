import assert from 'node:assert/strict';
import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createReport, writeReport } from './export.mjs';

const product = fileURLToPath(new URL('../..', import.meta.url));
const corpus = JSON.parse(fs.readFileSync(new URL('./fixtures/token-custody-snapshots.json', import.meta.url)));
const fixtures = corpus.snapshots;
const find = name => { const value = fixtures.find(row => row.name === name); assert(value, name); return value; };
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let integer = BigInt(`0x${bytes.toString('hex')}`), result = '';
  while (integer) { result = alphabet[Number(integer % 58n)] + result; integer /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; result = `1${result}`; }
  return result;
}
const bytes = (s, role) => Buffer.from(s.accounts[role].data_hex, 'hex');
const key = (s, role, at) => base58(bytes(s, role).subarray(at, at + 32));
const number = (s, role, at) => bytes(s, role).readBigUInt64LE(at).toString();
function configuration(s, endpoints) {
  const witnesses = Object.keys(s.accounts).filter(role => /^witness\d+$/.test(role)).map(role => {
    const b = bytes(s, role); return { witness_id: b.subarray(8, 8 + b[4]).toString(), public_key: b.subarray(72, 104).toString('hex') };
  });
  return {
    schema_version: 1, scope: 'local-fixture', endpoints, epochs: ['1'], minimum_context_slot: s.context_slot, max_age_seconds: '900',
    pins: { program: s.token_program, governance: key(s, 'token_config', 4), program_slot: number(s, 'token_data', 4), usdc: s.accounts.usdc.address, treasury: key(s, 'token_config', 80), factory: key(s, 'token_config', 112) },
    collateral: { schema_version: 2, judge: s.program, judge_slot: number(s, 'judge_data', 4), rewards: s.rewards_program, rewards_slot: number(s, 'rewards_data', 4), rewards_governance: key(s, 'pool', 4), log_name: s.log_name, log_version: bytes(s, 'log')[4], service_public_key: bytes(s, 'log').subarray(72, 104).toString('hex'), morse_mint: s.accounts.morse.address, network_started: number(s, 'pool', 164), witnesses, proofs: s.accounts.proof ? [bytes(s, 'proof').subarray(40, 72).toString('hex')] : [] },
  };
}

// These are exact preserved local SBF accounts. Mutations below are rejection
// probes only; no altered account is used as an accepted custody expectation.
test('compiled Mesh authenticates bounded v2 collateral and slash snapshots through a 2-of-3 HTTP quorum', { timeout: 240_000 }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'morse-collateral-report-'));
  let binary = process.env.MORSE_PUBLIC_CHAIN_BIN;
  if (!binary) {
    binary = path.join(directory, 'report');
    const compiler = process.env.MESHC || path.resolve(product, '../mesh-lang/target/debug/meshc');
    const built = spawnSync(compiler, ['build', path.join(product, 'ops/public-chain'), '--output', binary], { encoding: 'utf8', timeout: 150_000 });
    assert.equal(built.status, 0, built.stdout + built.stderr);
  }
  assert(fs.existsSync(binary), 'explicit report binary must exist');
  let selected = find('token-active');
  const modes = ['good', 'good', 'good'];
  let reads = 0, bondsReads = 0, receiptsReads = 0;
  const servers = modes.map((_, index) => http.createServer(async (request, response) => {
    try {
      let body = ''; for await (const chunk of request) body += chunk;
      const rpc = JSON.parse(body); reads++;
      assert.equal(request.method, 'POST'); assert.equal(rpc.method, 'getMultipleAccounts');
      const keys = rpc.params[0];
      assert(keys.length <= 100);
      // Burn is deliberately unavailable in this independent custody corpus.
      // We never fabricate a burn account or splice an account from another bank.
      if (rpc.params[1].dataSlice.length === 2240) { response.writeHead(503).end(); return; }
      assert.deepEqual(rpc.params[1], { commitment: 'finalized', encoding: 'base64', minContextSlot: Number(selected.context_slot), dataSlice: { offset: 0, length: 8416 } });
      const receiptBatch = keys.length < 18;
      receiptBatch ? receiptsReads++ : bondsReads++;
      if (modes[index] === 'outage') { response.writeHead(503).end(); return; }
      const source = modes[index] === 'other-bank' ? find('token-pending') : selected;
      const accountsByAddress = new Map(Object.values(source.accounts).map(account => [account.address, account]));
      const values = keys.map(address => {
        const a = accountsByAddress.get(address); assert(a, `actual observation required for ${address}`);
        return a.missing ? null : { owner: a.owner, executable: a.executable, lamports: Number(a.lamports), rentEpoch: 0, space: Number(a.space), data: [Buffer.from(a.data_hex, 'hex').toString('base64'), 'base64'] };
      });
      const at = role => keys.indexOf(selected.accounts[role]?.address);
      const mutate = (role, change) => { const i = at(role); if (i < 0) return; const b = Buffer.from(values[i].data[0], 'base64'); change(b); values[i].data[0] = b.toString('base64'); };
      const mode = modes[index];
      if (mode === 'owner') values[1].owner = selected.accounts.usdc.owner;
      if (mode === 'partial') values.pop();
      if (mode === 'missing') values[1] = null;
      if (mode === 'wrong-order') [values[0], values[1]] = [values[1], values[0]];
      if (mode === 'padding') mutate('binding', b => { b[319] = 1; });
      if (mode === 'mint') mutate('morse', b => { b[44] = 9; });
      if (mode === 'service') mutate('log', b => { b[72] ^= 1; });
      if (mode === 'program-link') mutate('judge', b => { b[4] ^= 1; });
      if (mode === 'future-code') mutate('judge_data', b => b.writeBigUInt64LE(BigInt(selected.context_slot) + 1n, 4));
      if (mode === 'clock') mutate('clock', b => b.writeBigUInt64LE(BigInt(selected.context_slot) + 1n, 0));
      if (mode === 'pending') mutate('pending0', b => { b[4] ^= 1; });
      if (mode === 'underfunded') mutate('vault0', b => b.writeBigUInt64LE(0n, 64));
      if (mode === 'opposite-vault') {
        const role = selected.accounts.usdc_vault0?.missing ? 'usdc_vault0' : 'morse_vault0';
        const i = at(role); if (i >= 0) values[i] = { owner: source.accounts.morse.owner, executable: false, lamports: 1, space: 165, data: [Buffer.alloc(165).toString('base64'), 'base64'] };
      }
      if (mode === 'receipt-padding') mutate('proof', b => { b[399] = 1; });
      if (mode === 'receipt-total') mutate('proof', b => b.writeBigUInt64LE(b.readBigUInt64LE(272) + 1n, 272));
      if (mode === 'receipt-witness') mutate('proof', b => { b[432] ^= 1; });
      const slot = mode === 'old-context' ? Number(selected.context_slot) - 1 : Number(source.context_slot);
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { context: { slot }, value: values } }));
    } catch (error) { response.writeHead(500).end(); console.error(error); }
  }));
  try {
    for (const server of servers) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
    const endpoints = servers.map(server => `http://127.0.0.1:${server.address().port}`);
    const run = async overrides => createReport({ binary, configuration: { ...configuration(selected, endpoints), ...overrides }, generatedAt: Number(selected.now) });
    let report = await run();
    assert.equal(report.bonds.availability, 'available');
    assert.equal(report.bonds.schema_version, 2); assert.equal(report.bonds.rows.length, 2);
    assert.equal(report.bonds.bank_scope, 'this-section-only'); assert.equal(report.burns[0].availability, 'unavailable');
    assert.equal(report.bonds.rows[1].asset, 'MORSE'); assert.equal(report.bonds.rows[1].principal_units, '50000000');
    assert.equal(report.bonds.rows[1].vault_balance_units, '50000017'); assert.equal(report.bonds.rows[1].donation_surplus_units, '17');
    assert.equal(report.bonds.rows[1].opposite_asset_vault.availability, 'absent');
    assert.equal(report.bonds.valuation.availability, 'unavailable');
    for (const name of ['token-pending', 'token-underwater', 'token-grace-expired', 'token-withdrawn']) {
      selected = find(name); report = await run(); assert.equal(report.bonds.availability, 'available', name);
      const row = report.bonds.rows[1];
      if (name === 'token-pending') { assert.equal(row.pending_liability_units, '1'); assert.equal(row.pending_recorded_units, '1'); assert.equal(row.vault_balance_units, '50000018'); assert.equal(row.donation_surplus_units, '17'); }
      if (name.includes('underwater') || name.includes('grace')) { assert.equal(row.underwater_since_unix, '1703635200'); assert.equal(row.status, 'active', 'show recorded state, do not infer a USD eligibility verdict'); }
      if (name === 'token-withdrawn') { assert.equal(row.status, 'withdrawn'); assert.equal(row.principal_units, '0'); }
    }
    selected = find('mixed-proof-prepared'); report = await run();
    assert.equal(report.slashes.availability, 'available'); assert.equal(report.slashes.receipts[0].status, 'prepared');
    assert.equal(report.slashes.receipts[0].assets[0].slashed_units, null, 'prepared amount is not a zero loss');
    selected = find('mixed-proof-settled'); report = await run();
    assert.equal(report.bonds.availability, 'available'); assert.equal(report.bonds.rows.length, 3);
    assert.equal(report.bonds.rows[1].pending_recorded_units, '7'); assert.equal(report.bonds.rows[1].pending_liability_units, '0');
    assert.equal(report.slashes.availability, 'available');
    const receipt = report.slashes.receipts[0]; assert.equal(receipt.status, 'settled');
    assert.equal(receipt.verified_signature_mask, '63');
    assert.equal(receipt.verified_signatures, '6');
    assert.deepEqual(receipt.assets.map(row => [row.asset, row.slashed_units, row.finder_units]), [['USDC', '600000008', '60000000'], ['MORSE', '133333358', '13333335']]);
    assert.equal(receipt.rows[0].principal_units, '100000000'); assert.equal(receipt.rows[0].slashed_units, '100000007');
    if (process.env.MORSE_PUBLIC_COLLATERAL_REPORT_OUTPUT) writeReport(process.env.MORSE_PUBLIC_COLLATERAL_REPORT_OUTPUT, report);
    for (const mutation of ['owner', 'partial', 'missing', 'wrong-order', 'padding', 'mint', 'service', 'program-link', 'future-code', 'clock', 'old-context']) {
      modes.fill(mutation); const refused = await run(); assert.equal(refused.bonds.availability, 'unavailable', mutation); assert.equal(refused.bonds.rows, undefined, mutation); assert.equal(refused.slashes.availability, 'unavailable', mutation);
    }
    for (const mutation of ['receipt-padding', 'receipt-total', 'receipt-witness']) { modes.fill(mutation); assert.equal((await run()).slashes.availability, 'unavailable', mutation); }
    modes.fill('good'); const original = configuration(selected, endpoints);
    const changed = await run({ collateral: { ...original.collateral, judge_slot: '999' } }); assert.equal(changed.bonds.code_current, false); assert.equal(changed.slashes.code_current, false);
    modes.splice(0, 3, 'good', 'good', 'outage'); assert.equal((await run()).bonds.availability, 'available');
    modes.splice(0, 3, 'good', 'owner', 'outage'); assert.equal((await run()).bonds.availability, 'unavailable');
    selected = find('token-active');
    for (const mutation of ['pending', 'underfunded', 'opposite-vault']) { modes.fill(mutation); assert.equal((await run()).bonds.availability, 'unavailable', mutation); }
    modes.splice(0, 3, 'good', 'other-bank', 'outage'); assert.equal((await run()).bonds.availability, 'disagreed', 'two genuinely different preserved banks');
    selected = find('activated-usdc-migrated'); modes.fill('good'); report = await run(); assert.equal(report.bonds.availability, 'unavailable', 'MBD1 is never reinterpreted as MBD2');
    assert(bondsReads > 30 && receiptsReads > 30); assert.equal(reads, bondsReads + receiptsReads + reads / 3);
    console.log(`MORSE_PUBLIC_COLLATERAL_REPORT ${reads} HTTP requests; exact_SBF_replay quorum_v2 mixed_assets pending grace withdrawn prepared settled mutations code_warning no_partial_amounts`);
  } finally {
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
