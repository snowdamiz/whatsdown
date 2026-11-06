// Owned complete-bank peer only. Financial parsing, authentication, quorum and
// report policy belong to the compiled Mesh reader, never this fixture shell.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import test from 'node:test';
import { createReport, validateConfiguration } from './export.mjs';

const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function decode58(text) {
  let value = 0n;
  for (const c of text) { const digit = alphabet.indexOf(c); assert(digit >= 0); value = value * 58n + BigInt(digit); }
  let body = value === 0n ? Buffer.alloc(0) : Buffer.from((value.toString(16).length % 2 ? '0' : '') + value.toString(16), 'hex');
  const zeroes = [...text].findIndex(c => c !== '1');
  return Buffer.concat([Buffer.alloc(zeroes < 0 ? text.length : zeroes), body]);
}
const token = JSON.parse(fs.readFileSync(new URL('./fixtures/history-token.json', import.meta.url)));
const judge = JSON.parse(fs.readFileSync(new URL('./fixtures/history-judge.json', import.meta.url)));
const tokenLater = JSON.parse(fs.readFileSync(new URL('./fixtures/history-token-later.json', import.meta.url)));
const judgeLater = JSON.parse(fs.readFileSync(new URL('./fixtures/history-judge-later.json', import.meta.url)));
function encode58(bytes) {
  let integer = BigInt('0x' + bytes.toString('hex')), result = '';
  while (integer) { result = alphabet[Number(integer % 58n)] + result; integer /= 58n; }
  for (const byte of bytes) { if (byte) break; result = '1' + result; }
  return result;
}
function config(bank, endpoints) {
  const m = bank.metadata;
  if (m.token_program) {
    const a = m.accounts, data = role => Buffer.from(a[role].data_hex, 'hex');
    const key = (role, at) => encode58(data(role).subarray(at, at + 32));
    const number = (role, at) => data(role).readBigUInt64LE(at).toString();
    return { schema_version: 1, scope: 'local-fixture', endpoints, epochs: [],
      pins: { program: m.token_program, governance: key('token_config', 4), program_slot: number('token_data', 4),
        usdc: a.usdc.address, treasury: key('token_config', 80), factory: key('token_config', 112) },
      collateral: { schema_version: 2, judge: m.program, judge_slot: number('judge_data', 4),
        rewards: m.rewards_program, rewards_slot: number('rewards_data', 4), rewards_governance: key('pool', 4),
        log_name: m.log_name, log_version: data('log')[4], service_public_key: data('log').subarray(72, 104).toString('hex'),
        morse_mint: a.morse.address, network_started: number('pool', 164), witnesses: [], proofs: [] },
      minimum_context_slot: bank.context_slot, max_age_seconds: '900',
      history: { schema_version: 1, maximum_records: 128, page_size: 1 } };
  }
  return { schema_version: 1, scope: 'local-fixture', endpoints,
    pins: { program: m.program, governance: m.governance, program_slot: m.program_slot,
      usdc: m.usdc, treasury: m.treasury, factory: m.factory },
    epochs: [m.epoch], minimum_context_slot: bank.context_slot, max_age_seconds: '900',
    history: { schema_version: 1, maximum_records: 128, page_size: 16 } };
}
function wire(account, length) {
  return { owner: account.owner, executable: account.executable,
    lamports: JSON.rawJSON(account.lamports), rentEpoch: JSON.rawJSON(account.rent_epoch || '0'), space: JSON.rawJSON(account.space),
    data: [Buffer.from(account.data_hex, 'hex').subarray(0, length).toString('base64'), 'base64'] };
}
async function peers(bank, later = bank) {
  const modes = ['good', 'reverse', 'good'];
  const requests = [], errors = [];
  const values = new Map(bank.value_accounts.map(a => [a.address, a]));
  const absent = new Set(bank.absent_accounts);
  const laterValues = new Map(later.value_accounts.map(a => [a.address, a]));
  const servers = modes.map((_, provider) => http.createServer(async (request, response) => {
    try {
      assert.equal(request.method, 'POST');
      let body = ''; for await (const chunk of request) { body += chunk; assert(body.length <= 16384); }
      const rpc = JSON.parse(body); assert.equal(rpc.jsonrpc, '2.0');
      requests.push({ provider, mode: modes[provider], request: rpc });
      let rows;
      let valueBank = false;
      const mode = modes[provider];
      if (request.url === '/forbidden') throw new Error('redirect followed');
      if (mode === 'outage') { response.writeHead(503).end(); return; }
      if (mode === 'redirect') { response.writeHead(302, { location: '/forbidden' }).end(); return; }
      if (mode === 'oversized') { response.writeHead(200).end('x'.repeat(524289)); return; }
      if (rpc.method === 'getProgramAccounts') {
        const [program, options] = rpc.params;
        assert.equal(options.withContext, true); assert.equal(options.commitment, 'finalized');
        assert.equal(options.encoding, 'base64'); assert.equal(options.minContextSlot, Number(bank.context_slot));
        const owned = bank.owned.find(row => row.program === program); assert(owned, 'only actual owned programs may be queried');
        rows = owned.accounts.filter(account => options.filters.every(filter => {
          if (filter.dataSize !== undefined) return Number(account.space) === filter.dataSize;
          const bytes = decode58(filter.memcmp.bytes), data = Buffer.from(account.data_hex, 'hex');
          return data.subarray(filter.memcmp.offset, filter.memcmp.offset + bytes.length).equals(bytes);
        })).map(account => ({ pubkey: account.address, account: wire(account, Number(account.space)) }));
        if (mode === 'reverse') rows.reverse();
        if (mode === 'omit-last') rows.pop();
        if (mode === 'omit-first') rows.shift();
        if (mode === 'duplicate' && rows.length) rows.push(rows[0]);
        if (mode === 'count-overflow' && rows.length) { const a = rows[0]; while (rows.length < 129) rows.push(a); }
        if (rows.length) {
          const a = rows[0], raw = Buffer.from(a.account.data[0], 'base64');
          if (mode === 'wrong-owner' || mode === 'future-wrong-owner') a.account.owner = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
          if (mode === 'wrong-pda') a.pubkey = program;
          if (mode === 'quoted-space') a.account.space = String(raw.length);
          if (mode === 'zero-funding') a.account.lamports = 0;
          if (mode === 'executable') a.account.executable = true;
          if (mode === 'future' || mode === 'future-wrong-owner') raw[3] = 99;
          if (mode === 'filter') raw[0] ^= 1;
          if (mode === 'trailing') { a.account.data[0] = Buffer.concat([raw, Buffer.from([0])]).toString('base64'); a.account.space = raw.length + 1; }
          else a.account.data[0] = raw.toString('base64');
        }
      } else {
        assert.equal(rpc.method, 'getMultipleAccounts', 'read-only methods only');
        const [keys, options] = rpc.params;
        assert.equal(options.commitment, 'finalized'); assert.equal(options.encoding, 'base64');
        assert(options.minContextSlot >= Number(bank.context_slot));
        assert.equal(options.dataSlice.offset, 0); assert(options.dataSlice.length <= 8416);
        valueBank = mode === 'later-value' && rpc.id === 1;
        const observed = valueBank ? laterValues : values;
        rows = keys.map(address => {
          if (observed.has(address)) return wire(observed.get(address), options.dataSlice.length);
          assert(absent.has(address), `same-bank actual absence required for ${address}`);
          return null;
        });
        if (mode === 'value-missing' && rpc.id === 1) rows[0] = null;
        if (mode === 'value-owner' && rpc.id === 1 && rows[0]) rows[0].owner = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
      }
      let slot = Number(valueBank ? later.context_slot : bank.context_slot);
      if (mode === 'value-old-context' && rpc.id === 1) {
        slot--;
        const at = rpc.params[0].indexOf('SysvarC1ock11111111111111111111111111111111');
        if (at >= 0) { const raw = Buffer.from(rows[at].data[0], 'base64'); raw.writeBigUInt64LE(BigInt(slot), 0); rows[at].data[0] = raw.toString('base64'); }
      }
      if (mode === 'quoted-context') slot = String(slot);
      if (mode === 'old-context') slot--;
      if (mode === 'context-moved' && rpc.id >= 50 && rpc.id <= 52) {
        slot++;
        const at = rpc.params[0].indexOf('SysvarC1ock11111111111111111111111111111111');
        if (at >= 0) { const raw = Buffer.from(rows[at].data[0], 'base64'); raw.writeBigUInt64LE(BigInt(slot), 0); rows[at].data[0] = raw.toString('base64'); }
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: mode === 'wrong-id' ? rpc.id + 1 : rpc.id, result: { context: { slot }, value: rows } }));
    } catch (error) { errors.push(String(error.stack)); response.writeHead(500).end(); }
  }));
  for (const server of servers) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
  return { modes, requests, errors, endpoints: servers.map(server => `http://127.0.0.1:${server.address().port}`),
    async close() { for (const server of servers) await new Promise(resolve => server.close(resolve)); } };
}

test('native discovery authenticates every funded frame from one complete owned-bank list and records separate value banks', { timeout: 180000 }, async () => {
  const binary = process.env.MORSE_PUBLIC_CHAIN_BIN; assert(binary && fs.existsSync(binary), 'explicit compiled Mesh binary required');
  const p = await peers(token);
  try {
    const report = await createReport({ binary, configuration: config(token, p.endpoints), generatedAt: Number(token.source_time_unix) });
    assert.deepEqual(p.errors, []);
    assert(report.history, 'selected-only report must not masquerade as a complete history index');
    assert.equal(report.history.burns.availability, 'available');
    assert.equal(report.history.burns.index_slot, token.context_slot);
    assert.equal(report.history.burns.records.length, 4);
    assert.equal(report.history.burns.discovery_scope, 'complete-returned-filtered-family-at-index-bank');
    assert(p.requests.some(row => row.request.method === 'getProgramAccounts'));
    assert.equal(report.history.burns.value_completeness, 'complete-for-applicable-supported-records');
    assert.equal(report.history.burns.pages.flatMap(page => page.requested_addresses).length, 4);
    if (process.env.MORSE_HISTORY_REPORT_DIR) fs.writeFileSync(process.env.MORSE_HISTORY_REPORT_DIR + '/burn-history.json', JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  } finally {
    if (process.env.MORSE_HISTORY_TRACE_FILE) fs.writeFileSync(process.env.MORSE_HISTORY_TRACE_FILE, JSON.stringify({ requests: p.requests, errors: p.errors }, null, 2) + '\n');
    await p.close();
  }
});


test('native witness/proof index retains all65 registries, pages applicable values and authenticates actual empty burn scope', { timeout: 180000 }, async () => {
  const p = await peers(judge);
  try {
    const configuration = config(judge, p.endpoints);
    const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration, generatedAt: Number(judge.source_time_unix) });
    assert.deepEqual(p.errors, []);
    assert.equal(report.history.burns.availability, 'available');
    assert.equal(report.history.burns.records.length, 0);
    assert.equal(report.history.witnesses.availability, 'available');
    assert.equal(report.history.witnesses.records.length, 65);
    assert.equal(report.history.witnesses.records.filter(row => row.value_status === 'registry-only').length, 63);
    assert.equal(report.history.witnesses.pages.length, 2);
    assert(report.history.witnesses.pages.every(page => page.complete));
    assert.equal(new Set(report.history.witnesses.pages.flatMap(page => page.requested_addresses)).size, 2);
    assert.equal(report.history.proofs.records.length, 1);
    assert.equal(report.history.proofs.pages.length, 1);
    assert(report.history.proofs.pages[0].complete);
    assert.equal(report.history.global_totals, null);
    if (process.env.MORSE_HISTORY_REPORT_DIR) fs.writeFileSync(process.env.MORSE_HISTORY_REPORT_DIR + '/collateral-history.json', JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  } finally { await p.close(); }
});

test('complete-list quorum refuses malformed owners PDAs versions filters counts bodies and moving discovery context without truncation', { timeout: 180000 }, async () => {
  const p = await peers(token);
  const run = () => createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: config(token, p.endpoints), generatedAt: Number(token.source_time_unix) });
  try {
    for (const mode of ['outage', 'redirect', 'oversized', 'wrong-id', 'duplicate', 'count-overflow', 'wrong-owner', 'wrong-pda', 'quoted-space', 'zero-funding', 'executable', 'filter', 'trailing', 'quoted-context', 'old-context', 'context-moved', 'future-wrong-owner']) {
      p.modes.splice(0, 3, mode, mode, 'good');
      const report = await run();
      assert.equal(report.history.burns.availability, 'unavailable', mode);
      assert.equal(report.history.burns.records, undefined, mode);
    }
    p.modes.splice(0, 3, 'omit-last', 'omit-first', 'good');
    assert.equal((await run()).history.burns.availability, 'disagreed');
    p.modes.splice(0, 3, 'omit-last', 'reverse', 'good');
    assert.equal((await run()).history.burns.records.length, 4);
    p.modes.splice(0, 3, 'future', 'future', 'outage');
    const unknown = (await run()).history.burns;
    assert.equal(unknown.availability, 'available');
    assert.equal(unknown.supported_layouts_complete, false);
    assert.equal(unknown.value_completeness, 'incomplete');
    assert(unknown.records.some(row => !row.canonical_identity && row.epoch === null && row.value_status === 'unsupported'));
    assert.deepEqual(p.errors, []);
  } finally { await p.close(); }
});


test('value-page refusals retain every indexed identifier and explicitly mark incomplete values', { timeout: 180000 }, async () => {
  for (const bank of [token, judge]) {
    const p = await peers(bank);
    try {
      p.modes.splice(0, 3, 'value-missing', 'value-owner', 'good');
      const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: config(bank, p.endpoints), generatedAt: Number(bank.source_time_unix) });
      assert.deepEqual(p.errors, []);
      const section = bank === token ? report.history.burns : report.history.witnesses;
      assert.equal(section.availability, 'available');
      assert.equal(section.records.length, bank === token ? 4 : 65);
      assert.equal(section.value_completeness, 'incomplete');
      const applicable = section.records.filter(row => row.value_status === 'requested');
      assert.deepEqual(section.pages.flatMap(page => page.requested_addresses), applicable.map(row => row.address));
      assert(section.pages.every(page => !page.complete));
      if (bank === judge) {
        assert.equal(report.history.proofs.record_count, 1);
        assert.equal(report.history.proofs.value_completeness, 'incomplete');
        assert.equal(report.history.proofs.pages[0].values.availability, 'unavailable');
      }
    } finally { await p.close(); }
  }
});


test('genuine later-bank pages are accepted while discovery keeps its original exact bank and separate source times', { timeout: 180000 }, async () => {
  for (const [bank, later] of [[token, tokenLater], [judge, judgeLater]]) {
    assert.equal(BigInt(later.context_slot), BigInt(bank.context_slot) + 7n);
    assert.deepEqual(later.owned, bank.owned, 'only actual cloned Clock/slot changed');
    const p = await peers(bank, later);
    try {
      p.modes.splice(0, 3, 'later-value', 'later-value', 'later-value');
      const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: config(bank, p.endpoints), generatedAt: Number(later.source_time_unix) });
      assert.deepEqual(p.errors, []);
      const section = bank === token ? report.history.burns : report.history.witnesses;
      assert.equal(section.index_slot, bank.context_slot);
      assert.equal(section.source_time_unix, bank.source_time_unix);
      assert.equal(section.value_completeness, 'complete-for-applicable-supported-records');
      const values = section.pages.flatMap(page => Array.isArray(page.values) ? page.values : [page.values]);
      assert(values.length > 0);
      assert(values.every(value => value.availability === 'available' && value.context_slot === later.context_slot && value.source_time_unix === later.source_time_unix));
      assert.equal(report.history.global_totals, null);
      if (process.env.MORSE_HISTORY_LATER_REPORT_DIR) fs.writeFileSync(process.env.MORSE_HISTORY_LATER_REPORT_DIR + '/' + (bank === token ? 'burn' : 'collateral') + '-later-history.json', JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    } finally { await p.close(); }
  }
});


test('bounded history is explicit opt-in; default selected report and endpoint privacy remain unchanged', { timeout: 180000 }, async () => {
  const p = await peers(token);
  try {
    const good = config(token, p.endpoints);
    for (const history of [null, {}, { schema_version: 2, maximum_records: 128, page_size: 16 }, { schema_version: 1, maximum_records: 0, page_size: 16 }, { schema_version: 1, maximum_records: 129, page_size: 16 }, { schema_version: 1, maximum_records: 128, page_size: 0 }, { schema_version: 1, maximum_records: 128, page_size: 17 }, { schema_version: 1, maximum_records: 128, page_size: 1, complete: true }]) assert.throws(() => validateConfiguration({ ...good, history }));
    delete good.history;
    assert.throws(() => validateConfiguration({ ...good, epochs: [] }));
    const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: good, generatedAt: Number(token.source_time_unix) });
    assert.equal(report.history, undefined); assert.equal(report.history_completeness, 'selected-epochs-only');
    assert.equal(report.burns.length, 1); assert.equal(report.burns[0].availability, 'available');
    assert(p.requests.every(row => row.request.method === 'getMultipleAccounts'));
    assert(!JSON.stringify(report).includes('127.0.0.1'));
    assert.deepEqual(p.errors, []);
  } finally { await p.close(); }
});


test('host envelope refuses an old selected-only binary for an explicit discovery request', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'morse-history-envelope-'));
  try {
    const binary = path.join(directory, 'selected-only');
    const output = { schema_version: 1, scope: 'local-fixture', phase5_complete: false, burns: [{ epoch: token.metadata.epoch, availability: 'unavailable' }], history_completeness: 'selected-epochs-only' };
    fs.writeFileSync(binary, '#!/usr/bin/env node\nconsole.log(' + JSON.stringify(JSON.stringify(output)) + ');\n', { mode: 0o700 });
    await assert.rejects(createReport({ binary, configuration: config(token, ['http://127.0.0.1:1', 'http://127.0.0.1:2', 'http://127.0.0.1:3']) }), /discovery scope mismatch/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});


test('a valid discovery index cannot authorize a value bank below its recorded slot', { timeout: 180000 }, async () => {
  for (const bank of [token, judge]) {
    const p = await peers(bank);
    try {
      p.modes.splice(0, 3, 'value-old-context', 'value-old-context', 'good');
      const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: config(bank, p.endpoints), generatedAt: Number(bank.source_time_unix) });
      const section = bank === token ? report.history.burns : report.history.witnesses;
      assert.equal(section.availability, 'available'); assert.equal(section.index_slot, bank.context_slot);
      assert.equal(section.record_count, bank === token ? 4 : 65);
      assert.equal(section.value_completeness, 'incomplete');
      assert(section.pages.every(page => !page.complete)); assert.deepEqual(p.errors, []);
    } finally { await p.close(); }
  }
});
