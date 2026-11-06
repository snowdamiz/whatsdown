import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, symlink, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PublicSnapshot, snapshotPolicy } from '../cloudflare/public-snapshot.mjs';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { once } from 'node:events';

const sha = value => createHash('sha256').update(value).digest('hex');
const token = 'owned-local-authentication-token-'.repeat(2);
const snapshot = JSON.parse(await readFile(new URL('./fixtures/token-carry-snapshots.json', import.meta.url))).snapshots.find(row => row.name === 'legacy-closed');
async function port() { const s = http.createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const p = s.address().port; await new Promise(r => s.close(r)); return p; }
async function start(binary, env, t) {
  const p = await port(); const child = spawn(binary, ['--serve'], { env: { ...process.env, ...env, PORT: String(p) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
  t.after(async () => { if (child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'exit'); } });
  for (let i = 0; i < 150; i++) {
    if (child.exitCode !== null) throw new Error(`native reader exited before health: ${output}`);
    try { if ((await fetch(`http://127.0.0.1:${p}/health`)).status === 200) return { child, url: `http://127.0.0.1:${p}` }; } catch {}
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error(`native reader health timeout: ${output}`);
}

test('native internal endpoint accepts only server-pinned policy and bearer token; identity is pinned to the build-produced executable digest', { timeout: 30000 }, async t => {
  const binary = process.env.MORSE_PUBLIC_CHAIN_BIN; assert(binary, 'explicit frozen compiler build required');
  let reads = 0;
  const servers = Array.from({ length: 3 }, () => http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body); reads++;
    assert.equal(rpc.method, 'getMultipleAccounts', 'only canonical Mesh reader account queries');
    assert.deepEqual(rpc.params[0], snapshot.accounts.map(a => a.address));
    response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id,
      result: { context: { slot: Number(snapshot.context_slot) }, value: snapshot.accounts.map(a => a.missing ? null : {
        owner: a.owner, executable: a.executable, lamports: Number(a.lamports), rentEpoch: 0, space: Number(a.space), data: [Buffer.from(a.data_hex, 'hex').toString('base64'), 'base64'] }) } }));
  }));
  for (const s of servers) { s.listen(0, '127.0.0.1'); await once(s, 'listening'); }
  t.after(async () => { await Promise.all(servers.map(s => new Promise(r => s.close(r)))); });
  const config = { schema_version: 1, scope: 'local-fixture', endpoints: servers.map(s => `http://127.0.0.1:${s.address().port}`),
    pins: Object.fromEntries(['program', 'governance', 'program_slot', 'usdc', 'treasury', 'factory'].map(k => [k, snapshot[k]])),
    epochs: [snapshot.epoch], minimum_context_slot: snapshot.context_slot, max_age_seconds: '900' };
  const raw = JSON.stringify(config);
  assert.equal((await readFile(binary + '.sha256', 'utf8')), sha(await readFile(binary)) + '\n', 'owned build companion matches exact executable');
  const env = { MORSE_PUBLIC_REPORT_CONFIG: raw, MORSE_PUBLIC_REPORT_POLICY_SHA256: sha(raw),
    MORSE_PUBLIC_REPORT_GENERATOR_SHA256: sha(await readFile(binary)), MORSE_PUBLIC_REPORT_INTERNAL_TOKEN: token, MORSE_PUBLIC_REPORT_ALLOW_FIXTURE: 'owned-local-only' };
  const { url } = await start(binary, env, t);
  const request = (body, authorization = `Bearer ${token}`) => fetch(`${url}/internal/v1/public-report`, { method: 'POST', headers: { authorization }, body });
  assert.equal((await request('a'.repeat(64), 'Bearer wrong')).status, 401); assert.equal(reads, 0);
  for (const body of ['a'.repeat(65), 'A'.repeat(64), JSON.stringify({ nonce: 'a'.repeat(64), pins: config.pins })]) assert.equal((await request(body)).status, 400);
  assert.equal(reads, 0, 'caller cannot override pins/clock/origins');
  const before = Math.floor(Date.now() / 1000);
  const response = await request('a'.repeat(64)); assert.equal(response.status, 200, await response.clone().text());
  const result = await response.json(); const after = Math.floor(Date.now() / 1000);
  assert.equal(result.nonce, 'a'.repeat(64)); assert.equal(result.policy_sha256, sha(raw)); assert.equal(result.generator_sha256, sha(await readFile(binary)));
  assert(Number(result.started_at_unix) >= before && Number(result.completed_at_unix) <= after);
  assert.equal(result.report.generated_at_unix, result.started_at_unix); assert.equal(result.report.burns[0].availability, 'available');
  assert.equal(result.report.burns[0].status, 'closed'); assert.equal(result.report.burns[0].receipt.carried_units, '230000000');
  assert.equal(result.report.provider_independence, 'not-established'); assert.equal(result.report.phase5_complete, false); assert.equal(reads, 3);
  assert(!JSON.stringify(result).includes('127.0.0.1')); assert(!JSON.stringify(result).includes(token));
  // Actual native read follows the real wall clock. Historical account clocks
  // must remain stale; fixture replay never becomes a healthy publication.
  const p = await snapshotPolicy({ configurationJson: raw, policySha256: sha(raw), generatorSha256: sha(await readFile(binary)) }, { fixture: true });
  const db = new DatabaseSync(':memory:');
  const store = { sql: { exec(query, ...args) { const statement = db.prepare(query);
    const rows = statement.columns().length ? statement.all(...args) : (statement.run(...args), []); return { toArray: () => rows }; } },
    transactionSync(fn) { db.exec('BEGIN'); try { const v = fn(); db.exec('COMMIT'); return v; } catch (e) { db.exec('ROLLBACK'); throw e; } }, async setAlarm() {} };
  try {
    const core = new PublicSnapshot(store, p, { read: async reservation => (await request(reservation.nonce)).json() });
    const published = await core.tick(); assert.equal(published.status, 'stale'); assert.equal(published.current, null); assert.equal(published.last_good, null);
    if (process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY) {
      await writeFile(join(process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY, 'native-read-real-clock-envelope.json'), JSON.stringify(published, null, 2) + '\n');
      await writeFile(join(process.env.MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY, 'native-read-report.json'), JSON.stringify(result, null, 2) + '\n');
    }
  } finally { db.close(); }
  const directory = await mkdtemp(join(tmpdir(), 'morse-reader-companion-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const alias = join(directory, 'owned-reader'); await symlink(binary, alias);
  await assert.rejects(start(alias, env, t), /before health/, 'missing fixed build companion');
  for (const content of ['0'.repeat(64) + '\n', sha(await readFile(binary)) + ' ', 'A'.repeat(64)]) {
    await writeFile(alias + '.sha256', content); await assert.rejects(start(alias, env, t), /before health/, 'malformed or mismatched fixed build companion');
  }
  await assert.rejects(start(binary, { ...env, MORSE_PUBLIC_REPORT_GENERATOR_SHA256: '0'.repeat(64) }, t), /before health/);
  await assert.rejects(start(binary, { ...env, MORSE_PUBLIC_REPORT_POLICY_SHA256: '0'.repeat(64) }, t), /before health/);
  await assert.rejects(start(binary, { ...env, MORSE_PUBLIC_REPORT_ALLOW_FIXTURE: '' }, t), /before health/);
});
