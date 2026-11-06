import assert from 'node:assert/strict';
import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createReport, validateConfiguration, writeReport } from './export.mjs';

const product = fileURLToPath(new URL('../..', import.meta.url));
const fixturePath = process.env.MORSE_TOKEN_CARRY_FIXTURES_PATH || fileURLToPath(new URL('./fixtures/token-carry-snapshots.json', import.meta.url));
const fixtures = JSON.parse(fs.readFileSync(fixturePath, 'utf8')).snapshots;
const fixture = fixtures.find(row => row.name === 'legacy-closed');
const pins = Object.fromEntries(['program', 'governance', 'program_slot', 'usdc', 'treasury', 'factory'].map(key => [key, fixture[key]]));
const base = { schema_version: 1, scope: 'local-fixture', pins, epochs: [fixture.epoch], minimum_context_slot: fixture.context_slot, max_age_seconds: '900' };

test('public configuration rejects unbounded discovery, repeated origins and implicit production policy', () => {
  const good = { ...base, endpoints: ['http://127.0.0.1:1', 'http://127.0.0.1:2', 'http://127.0.0.1:3'] };
  assert.doesNotThrow(() => validateConfiguration(good));
  for (const overrides of [{ scope: 'live' }, { epochs: [] }, { epochs: Array(17).fill('1') }, { epochs: ['01'] }, { minimum_context_slot: '18446744073709551616' }, { max_age_seconds: '0' }, { endpoints: ['http://127.0.0.1:1/a', 'http://127.0.0.1:1/b', 'http://127.0.0.1:2'] }, { scope: 'configured-rpc' }, { endpoints: ['http://example.com', ...good.endpoints.slice(1)] }]) {
    assert.throws(() => validateConfiguration({ ...good, ...overrides }));
  }
});

test('collateral configuration requires explicit v2 identities and bounded selected records', () => {
  const collateral = {
    schema_version: 2, judge: fixture.usdc, judge_slot: '1',
    rewards: fixture.treasury, rewards_slot: '1', rewards_governance: fixture.governance,
    log_name: 'custody-test', log_version: 1, service_public_key: '11'.repeat(32),
    morse_mint: fixture.factory, network_started: '1',
    witnesses: [{ witness_id: 'token', public_key: '22'.repeat(32) }], proofs: ['33'.repeat(32)],
  };
  const good = { ...base, endpoints: ['http://127.0.0.1:1', 'http://127.0.0.1:2', 'http://127.0.0.1:3'], collateral };
  assert.doesNotThrow(() => validateConfiguration(good));
  for (const fields of [
    { schema_version: 1 }, { judge_slot: undefined }, { rewards: undefined },
    { service_public_key: '00'.repeat(32) }, { log_version: 3 }, { log_name: '../other' },
    { morse_mint: '11111111111111111111111111111111' }, { network_started: '0' },
    { witnesses: Array(17).fill(collateral.witnesses[0]) },
    { witnesses: [collateral.witnesses[0], collateral.witnesses[0]] },
    { witnesses: [{ witness_id: 'TOKEN', public_key: '22'.repeat(32) }] },
    { proofs: Array(17).fill('33'.repeat(32)) }, { proofs: ['33'.repeat(32), '33'.repeat(32)] },
    { proofs: ['3'.repeat(63)] }, { proofs: ['00'.repeat(32)] },
  ]) assert.throws(() => validateConfiguration({ ...good, collateral: { ...collateral, ...fields } }));
});

test('compiled Mesh publishes only agreeing finalized fixture custody and authentic close receipts', { timeout: 180_000 }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'morse-public-report-'));
  const binary = path.join(directory, 'report');
  const compiler = process.env.MESHC || path.resolve(product, '../mesh-lang/target/debug/meshc');
  const built = spawnSync(compiler, ['build', path.join(product, 'ops/public-chain'), '--output', binary], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(built.status, 0, built.stdout + built.stderr);
  const modes = ['good', 'good', 'good'];
  let selected = fixture;
  let reads = 0;
  const servers = modes.map((_, index) => http.createServer(async (request, response) => {
    let body = ''; for await (const part of request) body += part;
    const rpc = JSON.parse(body); reads++;
    assert.equal(request.method, 'POST');
    assert.equal(rpc.method, 'getMultipleAccounts', 'read-only request');
    assert.deepEqual(rpc.params[0], selected.accounts.map(account => account.address));
    assert.deepEqual(rpc.params[1], { commitment: 'finalized', encoding: 'base64', minContextSlot: Number(selected.context_slot), dataSlice: { offset: 0, length: 2240 } });
    if (modes[index] === 'outage') { response.writeHead(503).end(); return; }
    const accounts = selected.accounts.map(account => account.missing ? null : ({ owner: account.owner, executable: account.executable, lamports: Number(account.lamports), rentEpoch: 0, space: Number(account.space), data: [Buffer.from(account.data_hex, 'hex').toString('base64'), 'base64'] }));
    const mutate = (at, change) => { const bytes = Buffer.from(accounts[at].data[0], 'base64'); change(bytes); accounts[at].data[0] = bytes.toString('base64'); };
    if (modes[index] === 'bad-receipt') mutate(9, bytes => { bytes[212] ^= 1; });
    if (modes[index] === 'donation') mutate(6, bytes => bytes.writeBigUInt64LE(18n, 64));
    if (modes[index] === 'upgrade') mutate(11, bytes => bytes.writeBigUInt64LE(1n, 4));
    if (modes[index] === 'delayed') mutate(4, bytes => bytes.writeBigInt64LE(BigInt(selected.epoch) * 604800n + 25199n, 32));
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { context: { slot: Number(selected.context_slot) }, value: accounts } }));
  }));
  try {
    for (const server of servers) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
    const configuration = { ...base, endpoints: servers.map(server => `http://127.0.0.1:${server.address().port}`) };
    const run = () => createReport({ binary, configuration: { ...configuration, pins: Object.fromEntries(Object.keys(pins).map(key => [key, selected[key]])), epochs: [selected.epoch] }, generatedAt: 1792627200 });
    const report = await run();
    if (process.env.MORSE_PUBLIC_REPORT_OUTPUT) writeReport(process.env.MORSE_PUBLIC_REPORT_OUTPUT, report);
    assert.equal(report.scope, 'local-fixture');
    assert.equal(report.provider_independence, 'not-established');
    assert.equal(report.burns[0].availability, 'available');
    assert.equal(report.burns[0].status, 'closed');
    assert.equal(report.burns[0].week_donation_surplus_units, '17');
    assert.equal(report.burns[0].carry_donation_surplus_units, '19');
    assert.equal(report.burns[0].receipt.carried_units, '230000000');
    assert.equal(report.burns[0].rows.length, 24);
    assert.equal(report.burns[0].rows.filter(row => row.status === 'carried').length, 23);
    assert.equal(report.burns[0].quote.status, 'unavailable');
    assert.equal(report.bonds.availability, 'unavailable');
    assert.equal(report.slashes.availability, 'unavailable');
    assert.equal(report.phase5_complete, false);
    assert(!JSON.stringify(report).includes('127.0.0.1'), 'endpoint secrets stay private');
    modes.splice(0, 3, 'good', 'good', 'bad-receipt');
    assert.equal((await run()).burns[0].availability, 'available');
    modes.splice(0, 3, 'good', 'donation', 'upgrade');
    const disagreed = (await run()).burns[0];
    assert.equal(disagreed.availability, 'disagreed');
    assert.equal(disagreed.budget_units, undefined);
    modes.splice(0, 3, 'good', 'bad-receipt', 'outage');
    assert.equal((await run()).burns[0].availability, 'unavailable');
    modes.splice(0, 3, 'upgrade', 'upgrade', 'good');
    assert.equal((await run()).burns[0].code_current, false);
    selected = fixtures.find(row => row.name === 'legacy-partial');
    modes.splice(0, 3, 'good', 'good', 'good');
    assert.equal((await run()).burns[0].status, 'missed');
    selected = fixtures.find(row => row.name === 'mixed-funded');
    const funded = (await run()).burns[0];
    assert.equal(funded.status, 'delayed', 'the first chunk is already due at the fixture clock');
    assert.equal(funded.rows.filter(row => row.status === 'scheduled').length, 23);
    modes.splice(0, 3, 'delayed', 'delayed', 'delayed');
    assert.equal((await run()).burns[0].status, 'delayed');
    assert.equal(reads, 24);
    const output = path.join(directory, 'network-data.js');
    writeReport(output, { ...report, note: '</script><script>alert(1)</script>' });
    assert(!fs.readFileSync(output, 'utf8').includes('</script>'));
    console.log('MORSE_PUBLIC_CHAIN_REPORT finalized12_roles_quorum_receipt_donation_disagreement_unavailable_code_drift');
  } finally {
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
