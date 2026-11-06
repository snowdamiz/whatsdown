import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const product = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const proof = process.env.MORSE_PROOF_DIR || path.resolve(product, '../.morse/witness-proof');
const fixturePath = process.env.MORSE_TOKEN_CUSTODY_FIXTURES_PATH || path.join(proof, 'token-custody-fixtures.json');
const compiler = process.env.MESHC || path.join(process.env.MESH_LANG_ROOT || path.resolve(product, '../mesh-lang'), 'target/debug/meshc');
const roles = ['pool','token_pool','epoch','token_epoch','pool_usdc_vault','pool_morse_vault','usdc','morse','log','economics','binding','token_config','oracle','reserve_profile','clock','attendance_clock','attendance_epoch','token','token_data','judge','judge_data','rewards','rewards_data','reserve_receipt','reserve_allocation','reserve_vault'];

test('compiled Mesh authenticates real v2 SBF snapshots through bounded finalized RPC', { timeout: 120000 }, async () => {
  const root = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const fixture = root.snapshots.find(value => value.name === 'token-rewards-finalized');
  assert(fixture);
  const keys = roles.map(name => fixture.accounts[name].address);
  const accounts = roles.map(name => {
    const a = fixture.accounts[name];
    assert(Number.isSafeInteger(Number(a.lamports)));
    return { owner: a.owner, executable: a.executable, lamports: Number(a.lamports), rentEpoch: 0,
      space: Number(a.space), data: [Buffer.from(a.data_hex, 'hex').toString('base64'), 'base64'] };
  });
  const collecting = root.snapshots.find(value => value.name === 'token-rewards-collecting');
  const identityKeys = [1, 2, 3].map(index => collecting.accounts[`attendance_witness${index}`].address);
  const identityAccounts = [1, 2, 3].map(index => {
    const a = collecting.accounts[`attendance_witness${index}`];
    return { owner: a.owner, executable: a.executable, lamports: Number(a.lamports), rentEpoch: 0,
      space: Number(a.space), data: [Buffer.from(a.data_hex, 'hex').toString('base64'), 'base64'] };
  });
  const seen = new Map();
  const problems = [];
  let redirects = 0;
  let retries = 0;
  const server = http.createServer(async (request, response) => {
    try {
      assert.equal(request.method, 'POST');
      let body = '';
      for await (const chunk of request) { body += chunk; assert(body.length <= 16384); }
      const rpc = JSON.parse(body);
      if (rpc.id === 3) {
        assert.equal(rpc.jsonrpc, '2.0'); assert.equal(rpc.method, 'getMultipleAccounts');
        assert.deepEqual(rpc.params[0], identityKeys);
        assert.deepEqual(rpc.params[1], { commitment: 'finalized', encoding: 'base64', minContextSlot: Number(collecting.context_slot), dataSlice: { offset: 0, length: 320 } });
        seen.set(request.url, (seen.get(request.url) || 0) + 1);
        const values = structuredClone(identityAccounts);
        if (request.url.startsWith('/identity-owner')) values[0].owner = fixture.payer;
        if (request.url.startsWith('/identity-key')) {
          const bytes = Buffer.from(values[0].data[0], 'base64'); bytes[72] ^= 1;
          values[0].data[0] = bytes.toString('base64');
        }
        if (request.url === '/identity-missing') values[1] = null;
        if (request.url === '/identity-reordered') [values[0], values[1]] = [values[1], values[0]];
        response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: request.url === '/identity-id' ? 4 : 3,
          result: { context: { slot: Number(collecting.context_slot) }, value: values } }));
        return;
      }
      assert.equal(rpc.id, 1); assert.equal(rpc.jsonrpc, '2.0');
      assert.equal(rpc.method, 'getMultipleAccounts');
      assert.deepEqual(rpc.params[0], keys);
      assert.deepEqual(rpc.params[1], { commitment: 'finalized', encoding: 'base64', minContextSlot: Number(fixture.context_slot), dataSlice: { offset: 0, length: 8416 } });
      seen.set(request.url, (seen.get(request.url) || 0) + 1);
      if (request.url === '/redirect-target') { redirects++; throw new Error('redirect followed'); }
      if (request.url === '/redirect') { response.writeHead(307, { location: '/redirect-target' }).end(); return; }
      if (request.url === '/oversized') { response.writeHead(200).end('x'.repeat(524289)); return; }
      if (request.url === '/retry' && ++retries === 1) { response.writeHead(503).end('retry locally'); return; }
      const result = { context: { slot: Number(fixture.context_slot) }, value: structuredClone(accounts) };
      const reply = { jsonrpc: '2.0', id: request.url === '/wrong-id' ? 2 : 1, result };
      const mutate = (index, change) => {
        const bytes = Buffer.from(result.value[index].data[0], 'base64'); change(bytes);
        result.value[index].data[0] = bytes.toString('base64');
      };
      if (request.url === '/failure') { delete reply.result; reply.error = { code: -32004, message: 'unavailable' }; }
      if (request.url === '/stale') result.context.slot--;
      if (request.url === '/numeric-string') result.context.slot = fixture.context_slot;
      if (request.url.startsWith('/wrong-owner')) result.value[1].owner = fixture.payer;
      if (request.url === '/reordered') [result.value[1], result.value[2]] = [result.value[2], result.value[1]];
      if (request.url === '/missing') result.value[3] = null;
      if (request.url === '/underfunded') mutate(5, b => b.writeBigUInt64LE(1n, 64));
      if (request.url === '/bad-mint') mutate(7, b => { b[44] = 9; });
      if (request.url === '/bad-receipt') mutate(23, b => { b[212] ^= 1; });
      if (request.url === '/wrong-space') result.value[2].space++;
      if (request.url === '/truncated') result.value[2].data[0] = Buffer.from(result.value[2].data[0], 'base64').subarray(0, 8415).toString('base64');
      if (request.url.startsWith('/donation')) mutate(4, b => b.writeBigUInt64LE(b.readBigUInt64LE(64) + (request.url.endsWith('a') ? 1n : 2n), 64));
      if (request.url.startsWith('/upgrade')) mutate(18, b => b.writeBigUInt64LE(1n, 4));
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(reply));
    } catch (error) { problems.push(error.stack); response.writeHead(500).end('local fixture error'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const output = await new Promise((resolve, reject) => {
      const env = { ...process.env, MORSE_TOKEN_CUSTODY_FIXTURES_PATH: fixturePath,
        MORSE_TOKEN_REWARDS_RPC: `http://127.0.0.1:${server.address().port}` };
      delete env.CARGO_TARGET_DIR;
      const child = spawn(compiler, ['test', 'ops/token-v2/reward_rpc.test.mpl'], { cwd: product, env, stdio: ['ignore','pipe','pipe'] });
      let text = ''; child.stdout.on('data', b => { text += b; }); child.stderr.on('data', b => { text += b; });
      child.on('error', reject); child.on('close', code => resolve({ code, text }));
    });
    process.stdout.write(output.text);
    assert.equal(output.code, 0, output.text);
    assert.match(output.text, /MORSE_TOKEN_REWARDS_FINALIZED_RPC/);
    assert.equal(redirects, 0);
    assert.equal(retries, 2);
    for (const url of ['/wrong-id','/failure','/stale','/numeric-string','/wrong-owner','/reordered','/missing','/oversized','/redirect','/underfunded','/bad-mint','/bad-receipt','/wrong-space','/truncated','/good-a','/wrong-owner-a','/good-b','/donation-a','/donation-b','/upgrade-a','/upgrade-b', '/identity-owner', '/identity-key', '/identity-missing', '/identity-reordered', '/identity-id', '/identity-good-a', '/identity-good-b']) assert(seen.has(url), url);
    assert.deepEqual(problems, []);
    console.log(`MORSE_TOKEN_REWARD_RPC: ${seen.size} bounded finalized endpoint cases, no redirects`);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
