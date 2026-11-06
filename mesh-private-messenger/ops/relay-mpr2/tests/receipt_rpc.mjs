// Real production executable against retained SBF bytes over three owned RPCs.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const required = name => { assert(process.env[name], `${name} required`); return process.env[name]; };
const binary = resolve(required('MORSE_MPR2_BINARY'));
const custodyPath = required('MORSE_TOKEN_CUSTODY_FIXTURES_PATH');
const vectorsPath = required('MORSE_MPR2_VECTORS');
const output = resolve(required('MORSE_MPR2_HTTP_OUTPUT'));
const compiler = resolve(required('MESHC'));
await mkdir(output, { recursive: true });
const hash = value => createHash('sha256').update(value).digest('hex');
const custodyBytes = await readFile(custodyPath);
assert.equal(hash(custodyBytes), '448e6668036e6dd2184bc7a4fd60e2740545b1270ba070c59858c9bb7eb196b5');
const custody = JSON.parse(custodyBytes), vectorsBytes = await readFile(vectorsPath);
const vectors = JSON.parse(vectorsBytes).cases;
const fixtures = JSON.parse(await readFile(required('MORSE_MPR2_TEST_FIXTURE'), 'utf8'));
const winnerCase = fixtures.prepared_cases.at(-1);
assert(winnerCase);
const original = custody.snapshots.find(row => row.name === 'mixed-proof-settled');
const raw = Buffer.from(original.accounts.proof.data_hex, 'hex'), proofHash = raw.subarray(40, 72).toString('hex');
const vector = vectors.find(row => { const wire = Buffer.from(row.wire_hex, 'hex'); return wire.length && hash(Buffer.concat([wire.subarray(0, 5), wire.subarray(37)])) === proofHash; });
assert(vector, 'actual same-proof wire must be retained');
const wire = Buffer.from(vector.wire_hex, 'hex');
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(raw) { let number = BigInt(`0x${raw.toString('hex')}`), text = ''; while (number) { text = alphabet[Number(number % 58n)] + text; number /= 58n; } for (const byte of raw) { if (byte) break; text = '1' + text; } return text; }
const calls = [], errors = [], servers = [];
let mode = 'settled';
const source = () => mode.startsWith('winner-') ? { accounts: winnerCase.accounts } : custody.snapshots.find(row => row.name === (mode === 'prepared' ? 'mixed-proof-prepared' : 'mixed-proof-settled'));
try {
  for (let origin = 0; origin < 3; origin++) {
    const server = createServer(async (req, res) => {
      try {
        let body = ''; for await (const chunk of req) { body += chunk; assert(body.length <= 32768); }
        const call = JSON.parse(body); assert.equal(call.method, 'getMultipleAccounts');
        const [keys, options] = call.params; assert.equal(options.commitment, 'finalized'); assert.deepEqual(options.dataSlice, { offset: 0, length: 9216 });
        assert([4, 9].includes(keys.length)); calls.push({ mode, origin, keys });
        if ((mode === 'two-of-three' && origin === 1) || (mode === 'disagree' && origin === 2)) {
          res.writeHead(503); res.end(); return;
        }
        const snapshot = source(), accounts = new Map(Object.entries(snapshot.accounts).map(([name, row]) => [row.address ?? name, row]));
        // Only permanent and recovery roles may be fetched. A mutable source or
        // bond read would make the permanent-after-rotation test fail here.
        if (!mode.startsWith('winner-')) {
          assert(!keys.includes(snapshot.accounts.oracle.address));
          assert(!keys.includes(snapshot.accounts.directory.address));
        }
        const values = keys.map(key => {
          const value = accounts.get(key); if (!value || value.missing) return 'null';
          if ((mode === 'missing' || mode === 'disagree' && origin === 1) && key === snapshot.accounts.proof.address) return 'null';
          const owner = mode === 'wrong-owner' && origin > 0 && key === snapshot.accounts.proof.address ? '11111111111111111111111111111111' : value.owner;
          const data = Buffer.from(value.data_hex, 'hex');
          if (mode === 'wrong-witness' && key === snapshot.accounts.proof.address) data.fill(200, 432, 464);
          // Negative: winner changes between permanent selection and effect batch.
          if (mode === 'winner-race' && keys.length === 9 && data.subarray(0, 4).toString('hex') === '4d505202') data.fill(200, 72, 104);
          return `{"owner":${JSON.stringify(owner)},"executable":${value.executable},"lamports":${value.lamports},"rentEpoch":0,"space":${value.space},"data":[${JSON.stringify(data.subarray(0, 9216).toString('base64'))},"base64"]}`;
        });
        res.writeHead(200, { 'content-type': 'application/json' });
        if (mode === 'transport' && origin === 2 && await readFile(join(output, 'guard'), 'utf8') === 'armed') {
          await writeFile(join(output, 'guard'), 'retired');
        }
        res.end(`{"jsonrpc":"2.0","id":${call.id},"result":{"context":{"slot":100000},"value":[${values.join(',')}]}}`);
      } catch (error) { errors.push(String(error.stack)); res.writeHead(500); res.end(); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); servers.push(server);
  }
  const config = { ...fixtures['mixed-proof-settled'].config,
    submitter: base58(raw.subarray(104, 136)), fee_payer: base58(raw.subarray(104, 136)), witnesses: [],
    // Both changed source revision and expired original proof are deliberate.
    source_revision: '99', endpoints: servers.map(server => `http://127.0.0.1:${server.address().port}`) };
  const pins = join(output, 'pins.json'), input = join(output, 'wire.frk'), request = join(output, 'request.json');
  await writeFile(pins, JSON.stringify(config)); await writeFile(input, wire);
  let number = 0;
  async function run(method, extra = {}, expectedCode = 0) {
    await writeFile(request, JSON.stringify({ schema_version: 2, method, min_context_slot: '100000', ...extra }));
    const child = spawn(binary, ['--pins', pins, '--input', input, '--request', request], { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; child.stdout.on('data', value => stdout += value); child.stderr.on('data', value => stderr += value);
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000);
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); }); clearTimeout(timer);
    await writeFile(join(output, `${++number}-${method}.json`), stdout);
    assert.equal(code, expectedCode, `${stdout}\n${stderr}`); return JSON.parse(stdout);
  }
  mode = 'prepared';
  const prepared = await run('receipt'); assert.equal(prepared.status, 'prepared');
  assert.equal(prepared.receipt.usdc_finder_units, '0'); assert.equal(prepared.receipt.morse_finder_units, '0');
  assert.equal((await run('close', {}, 1)).error, 'relay_close_requires_settled_receipt');
  const effect = { schema_version: 1, full_hash: hash(wire), reason: 'prepare_permanent_receipt' };
  assert.equal((await run('effect', { effect })).state, 'present');
  mode = 'settled';
  const settled = await run('receipt'); assert.equal(settled.status, 'settled'); assert.equal(settled.receipt.proof_hash, proofHash);
  const legacy = await run('legacy-receipt'); assert.equal(legacy.status, 'settled'); assert.deepEqual(legacy.receipt, settled.receipt);
  const destinations = await run('legacy-destinations'); assert.equal(destinations.schema_version, 1);
  assert.equal(destinations.proof_hash, proofHash); assert.equal(destinations.finder.status, 'missing'); assert.equal(destinations.locked.status, 'missing');
  const resumed = await run('resume'); assert.equal(resumed.status, 'settled'); assert.deepEqual(resumed.settled_receipt, settled.receipt);
  const admitted = await run('admit'); assert.equal(admitted.status, 'settled'); assert.equal(admitted.settled_receipt.finder, settled.receipt.finder);
  const different = Buffer.from(wire); different.fill(200, 5, 37); await writeFile(input, different);
  const competing = await run('admit'); assert.equal(competing.settled_receipt.finder, settled.receipt.finder); assert.notEqual(competing.finder, settled.receipt.finder);
  await writeFile(input, wire);
  mode = 'wrong-owner'; assert.equal((await run('receipt', {}, 1)).error, 'relay_receipt_quorum');
  mode = 'settled'; assert.equal((await run('receipt', { min_context_slot: '100001' }, 1)).error, 'relay_receipt_quorum');
  mode = 'two-of-three'; assert.deepEqual(await run('receipt'), settled);
  assert.deepEqual(calls.filter(row => row.mode === mode).map(row => row.origin), [0, 1, 2]);
  mode = 'disagree'; assert.equal((await run('receipt', {}, 1)).error, 'relay_receipt_quorum');
  mode = 'missing'; const missing = await run('receipt'); assert.equal(missing.status, 'missing'); assert.equal(missing.receipt, null);
  // Expired actual prepared snapshots still reconcile old payout operations
  // through the receipt winner, with another requested finder AND wallet.
  mode = 'winner-ready';
  const winnerWire = Buffer.from(winnerCase.wire_hex, 'hex');
  const winnerReceipt = Buffer.from(winnerCase.receipt_hex, 'hex');
  const competingWire = Buffer.from(winnerWire); competingWire.fill(200, 5, 37);
  await writeFile(input, competingWire);
  await writeFile(pins, JSON.stringify({ ...winnerCase.config,
    submitter: 'E6Lu6twRJzX5iXouS9o23fBHX9upgXbApcZyRY3cLYVL',
    fee_payer: 'E6Lu6twRJzX5iXouS9o23fBHX9upgXbApcZyRY3cLYVL', witnesses: [],
    source_revision: '999', endpoints: config.endpoints }));
  const payoutEffect = { schema_version: 1, full_hash: hash(competingWire), reason: 'payout_accounts' };
  assert.equal((await run('effect', { effect: payoutEffect })).state, 'present');
  assert.equal((await run('effect', { effect: { ...payoutEffect, reason: 'settle_mixed_assets' } })).state, 'absent');
  const ownStage = await run('stage'); assert.equal(ownStage.status, 'missing');
  for (const call of calls.filter(row => row.mode === 'winner-ready' && row.keys.length === 9)) {
    assert.notEqual(call.keys[4], base58(winnerReceipt.subarray(328, 360)));
  }
  assert.equal((await run('close', {}, 1)).error, 'relay_close_requires_settled_receipt');
  assert.equal((await run('effect', { effect: { ...payoutEffect, full_hash: hash(winnerWire) } }, 1)).error, 'relay_effect_binding');
  mode = 'winner-race';
  assert.equal((await run('effect', { effect: payoutEffect }, 1)).error, 'relay_recovery_quorum');
  await writeFile(input, wire); await writeFile(pins, JSON.stringify(config));
  mode = 'wrong-witness'; assert.equal((await run('receipt', {}, 1)).error, 'relay_receipt_quorum');
  mode = 'transport';
  const guard = join(output, 'guard'); await writeFile(guard, 'idle');
  const transport = spawn(compiler, ['test', fileURLToPath(new URL('./receipt_transport.test.mpl', import.meta.url)), '--opt-level', '2'], {
    env: { ...process.env, MORSE_MPR2_RPC_SOURCES: JSON.stringify(config.endpoints), MORSE_MPR2_RPC_GUARD: guard },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let transportOutput = ''; transport.stdout.on('data', value => transportOutput += value); transport.stderr.on('data', value => transportOutput += value);
  const transportTimer = setTimeout(() => transport.kill('SIGKILL'), 120000);
  const transportCode = await new Promise((resolve, reject) => { transport.once('error', reject); transport.once('close', resolve); }); clearTimeout(transportTimer);
  await writeFile(join(output, 'transport.log'), transportOutput);
  assert.equal(transportCode, 0, transportOutput);
  assert.deepEqual(calls.filter(row => row.mode === mode).map(row => row.origin), [0, 1, 2, 0, 1, 0, 1, 2]);
  assert.deepEqual(errors, []);
  await writeFile(join(output, 'results.json'), JSON.stringify({ scope: 'compiled-production-CLI; retained-SBF-record-HTTP-replay; no fresh SBF execution',
    cases: number, transport_boundary: 'PASS', calls, binary_sha256: hash(await readFile(binary)), custody_sha256: hash(custodyBytes), vectors_sha256: hash(vectorsBytes), errors }, null, 2));
  console.log(`${number} compiled relay CLI checks passed (${calls.length} authenticated RPC requests)`);
} finally { for (const server of servers) await new Promise(resolve => server.close(resolve)); }
