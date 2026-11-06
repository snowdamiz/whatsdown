import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import test from 'node:test';

const product = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const proof = process.env.MORSE_PROOF_DIR || path.resolve(product, '../.morse/witness-proof');
const compiler = process.env.MESHC || path.join(process.env.MESH_LANG_ROOT || path.resolve(product, '../mesh-lang'), 'target/debug/meshc');
const fixturePath = process.env.MORSE_TOKEN_BURN_FIXTURES_PATH || path.join(proof, 'token-burn-fixtures.json');
const names = ['config','morse','profile','usdc','oracle','clock','jupiter','jupiter_data','raydium','raydium_data','pool','factory','vault0','vault1','observation','week3','week_vault3','program','program_data'];

test('compiled Mesh reads real SBF receipts through bounded finalized RPC and two-provider agreement', { timeout: 120000 }, async () => {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const addresses = names.map(name => fixture.accounts[name].address);
  const accounts = names.map(name => {
    const account = fixture.accounts[name];
    return { owner: account.owner, executable: account.executable, lamports: Number(account.lamports), rentEpoch: 0, space: Number(account.space), data: [Buffer.from(account.data_hex, 'hex').toString('base64'), 'base64'] };
  });
  let retry = 0;
  let sends = 0;
  const privateDirectory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'morse-burn-journal-')));
  const keyDirectory = path.join(privateDirectory, 'key');
  fs.mkdirSync(keyDirectory, { mode: 0o700 });
  let redirectsFollowed = 0;
  const seen = new Map();
  const problems = [];
  const server = http.createServer(async (request, response) => {
    try {
      assert.equal(request.method, 'POST');
      let body = '';
      for await (const chunk of request) { body += chunk; assert(body.length <= 16384); }
      const rpc = JSON.parse(body);
      assert.equal(rpc.jsonrpc, '2.0');
      if (request.url === '/must-not-send') throw new Error('expired packet was submitted');
      if (request.url === '/send') {
        assert.equal(rpc.method, 'sendTransaction'); assert.equal(rpc.id, 2);
        assert.equal(rpc.params[0], fixture.transactions[95].wire_base64);
        assert.deepEqual(rpc.params[1], { encoding: 'base64', skipPreflight: false, preflightCommitment: 'confirmed', maxRetries: 0, minContextSlot: Number(fixture.context_slot) });
        sends++;
        if (sends === 1) response.writeHead(503).end('ambiguous local submission');
        else response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: 2, result: fixture.transactions[95].signature }));
        return;
      }
      assert.equal(rpc.method, 'getMultipleAccounts'); assert.equal(rpc.id, 1);
      assert.deepEqual(rpc.params[0], addresses);
      assert.deepEqual(rpc.params[1], { commitment: 'finalized', encoding: 'base64', minContextSlot: Number(fixture.context_slot), dataSlice: { offset: 0, length: 5728 } });
      seen.set(request.url, (seen.get(request.url) || 0) + 1);
      if (request.url === '/redirect-target') { redirectsFollowed++; throw new Error('redirect followed'); }
      if (request.url === '/redirect') { response.writeHead(302, { location: '/redirect-target' }).end(); return; }
      if (request.url === '/retry' && ++retry === 1) { response.writeHead(503).end('temporary'); return; }
      if (request.url === '/oversized') { response.writeHead(200).end('x'.repeat(262145)); return; }
      const result = { context: { slot: Number(fixture.context_slot) }, value: structuredClone(accounts) };
      const output = { jsonrpc: '2.0', id: request.url === '/wrong-id' ? 2 : 1, result };
      if (request.url === '/failure') { delete output.result; output.error = { code: -32004, message: 'unavailable' }; }
      if (request.url === '/stale') result.context.slot--;
      if (request.url === '/numeric-string') result.context.slot = fixture.context_slot;
      if (request.url === '/wrong-owner') result.value[2].owner = fixture.payer;
      if (request.url === '/reordered') [result.value[2], result.value[3]] = [result.value[3], result.value[2]];
      if (request.url === '/missing') result.value[2] = null;
      if (request.url === '/paused') {
        const data = Buffer.from(result.value[7].data[0], 'base64'); data.writeBigUInt64LE(1n, 4);
        result.value[7].data[0] = data.toString('base64');
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(output));
    } catch (error) { problems.push(error.stack); response.writeHead(500).end('fixture error'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const run = (stage, target) => new Promise((resolve, reject) => {
      const env = { ...process.env, MORSE_TOKEN_TEST_RPC: `http://127.0.0.1:${server.address().port}`, MORSE_TOKEN_BURN_FIXTURES_PATH: fixturePath,
        MORSE_TOKEN_JOURNAL_STAGE: stage, MORSE_TOKEN_JOURNAL_PATH: path.join(privateDirectory, 'journal.sqlite'), MORSE_TOKEN_JOURNAL_KEY: keyDirectory };
      delete env.CARGO_TARGET_DIR;
      const child = spawn(compiler, ['test', target], { cwd: product, env, stdio: ['ignore','pipe','pipe'] });
      let log = ''; child.stdout.on('data', data => { log += data; }); child.stderr.on('data', data => { log += data; });
      child.on('error', reject); child.on('close', code => resolve({ code, log }));
    });
    const result = await run('write', 'ops/token');
    process.stdout.write(result.log);
    assert.equal(result.code, 0, result.log);
    for (let restart = 0; restart < 2; restart++) {
      const recovered = await run('restart', 'ops/token/burn_journal.test.mpl');
      process.stdout.write(recovered.log);
      assert.equal(recovered.code, 0, recovered.log);
      assert(recovered.log.includes('MORSE_TOKEN_PACKET_JOURNAL:'));
    }
    for (const concurrent of await Promise.all([run('concurrent', 'ops/token/burn_journal.test.mpl'), run('concurrent', 'ops/token/burn_journal.test.mpl')])) {
      process.stdout.write(concurrent.log);
      assert.equal(concurrent.code, 0, concurrent.log);
      assert(concurrent.log.includes('MORSE_TOKEN_PACKET_CONCURRENT:'));
    }
    assert.deepEqual(problems, []);
    assert.equal(redirectsFollowed, 0);
    for (const route of ['/good','/wrong-id','/failure','/stale','/wrong-owner','/reordered','/missing','/redirect','/oversized','/numeric-string','/paused','/retry','/good-a','/good-b']) assert((seen.get(route) || 0) > 0, route);
    assert.equal(seen.get('/retry'), 2);
    assert.equal(sends, 2);
    console.log('MORSE_TOKEN_FINALIZED_RPC_PROOF: actual local SBF state, strict IDs/types/owners/contexts, no redirects, bounded retry and independent-source contract; no live RPC submission.');
  } finally { await new Promise(resolve => server.close(resolve)); fs.rmSync(privateDirectory, { recursive: true, force: true }); fs.rmSync(keyDirectory + '-other', { recursive: true, force: true }); }
});
