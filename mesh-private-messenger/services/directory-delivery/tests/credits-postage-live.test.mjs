import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const core = fileURLToPath(new URL('..', import.meta.url));
const product = path.resolve(core, '../..');
const compiler = process.env.MESHC ?? path.resolve(product, '../../mesh-lang/target/debug/meshc');
const pgBin = process.env.CREDIT_TEST_PG_BIN ?? execFileSync('pg_config', ['--bindir'], { encoding: 'utf8' }).trim();
const execute = promisify(execFile);
async function run(file, args, options = {}) {
  try { return (await execute(file, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 4 * 1024 * 1024, ...options })).stdout; }
  catch (error) { error.message += `\n${error.stdout ?? ''}\n${error.stderr ?? ''}`; throw error; }
}
async function port() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const value = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return value;
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  let timer;
  await Promise.race([once(child, 'exit'), new Promise((resolve) => { timer = setTimeout(resolve, 5000); })]);
  clearTimeout(timer);
  if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await once(child, 'exit'); }
}
async function ready(base, child, logs) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`service exited: ${logs()}`);
    try { if ((await fetch(base + '/health')).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`service did not become healthy: ${logs()}`);
}
// Published proof-only material. Every DB, object and process is disposable.
const seed = '5b'.repeat(32);
const privateKey = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex'), format: 'der', type: 'pkcs8' });
const serviceKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const common = {
  ...process.env,
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: seed,
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  CREDIT_FIXTURE_WITNESS_A_SEED: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  CREDIT_FIXTURE_WITNESS_B_SEED: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  MESSENGER_DELIVERY_SEALING_SEED_HEX: '77'.repeat(32),
  MESSENGER_DELIVERY_INTERNAL_TOKEN: '12'.repeat(32),
  MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN: '34'.repeat(32),
  MESSENGER_CREDITS_PURPOSE: 'test',
  MESSENGER_OBJECT_CREDIT_SERVICE_PUBLIC_KEY_HEX: serviceKey,
  MESSENGER_OBJECT_WORK_DIFFICULTY: '4',
  MESSENGER_OBJECT_INTERNAL_TOKEN: '12'.repeat(32),
  MESSENGER_JOBS_URL: '',
  MORSE_PAID_INBOX_POSTAGE: 'on',
  MORSE_PAID_RETENTION: 'off',
};

test('paid postage commits one account charge and all linked-device enqueues across independent cores', { timeout: 180_000 }, async (t) => {
  const temp = await mkdtemp(path.join(tmpdir(), 'morse-paid-postage-'));
  const data = path.join(temp, 'postgres'); const pgPort = await port();
  const children = []; let started = false;
  t.after(async () => {
    await Promise.all(children.map(stop));
    if (started) await run(path.join(pgBin, 'pg_ctl'), ['-D', data, '-w', '-m', 'fast', 'stop']);
    await rm(temp, { recursive: true, force: true });
  });
  await run(path.join(pgBin, 'initdb'), ['-D', data, '-U', 'postage_test', '-A', 'trust', '--no-locale']);
  await run(path.join(pgBin, 'pg_ctl'), ['-D', data, '-l', path.join(temp, 'postgres.log'), '-w', 'start', '-o', `-h 127.0.0.1 -p ${pgPort} -F`]); started = true;
  await run(path.join(pgBin, 'createdb'), ['-h', '127.0.0.1', '-p', String(pgPort), '-U', 'postage_test', 'postage_core_test']);
  const url = `postgres://postage_test@127.0.0.1:${pgPort}/postage_core_test?sslmode=disable`;
  for (const migration of (await readdir(path.join(core, 'migrations'))).filter(n => n.endsWith('.sql')).sort()) await run(path.join(pgBin, 'psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', url, '-f', path.join(core, 'migrations', migration)]);
  await run(path.join(pgBin, 'psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', url, '-c', "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', decode(repeat('00',188),'hex'), decode(repeat('00',6),'hex'), now())"]);
  const binary = path.join(temp, 'postage-core');
  await run(compiler, ['build', core, '-o', binary], { env: common });
  const edgeBinary = path.join(temp, 'postage-edge');
  await run(compiler, ['build', path.join(product, 'services/privacy-edge'), '-o', edgeBinary], { env: common });
  const used = new Set([pgPort]);
  async function uniquePort() { let value; do { value = await port(); } while (used.has(value)); used.add(value); return value; }
  async function start(enabled) {
    const httpPort = await uniquePort(); let logs = '';
    const child = spawn(binary, [], { env: { ...common, MESSENGER_DATABASE_URL: url, MESSENGER_PORT: String(httpPort), MESSENGER_STREAM_PORT: String(await uniquePort()), MORSE_PAID_INBOX_POSTAGE: enabled ? 'on' : 'off' }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', value => { logs += value; }); child.stderr.on('data', value => { logs += value; }); children.push(child);
    await ready(`http://127.0.0.1:${httpPort}`, child, () => logs);
    return `http://127.0.0.1:${httpPort}`;
  }
  const a = await start(true), b = await start(true), off = await start(false);
  const edgePort = await uniquePort(); let edgeLogs = '';
  const edge = spawn(edgeBinary, [], { env: { ...common, MESSENGER_PRIVACY_EDGE_PORT: String(edgePort), MESSENGER_DELIVERY_INTERNAL_URL: a, MESSENGER_ABUSE_DIFFICULTY: '4' }, stdio: ['ignore', 'pipe', 'pipe'] });
  edge.stdout.on('data', value => { edgeLogs += value; }); edge.stderr.on('data', value => { edgeLogs += value; }); children.push(edge);
  const edgeBase = `http://127.0.0.1:${edgePort}`; await ready(edgeBase, edge, () => edgeLogs);
  assert.equal((await fetch(a + '/internal/credits/postage', { method: 'POST', body: Buffer.alloc(0) })).status, 401);
  assert.equal((await fetch(a + '/internal/credits/postage/reconcile', { method: 'POST', body: Buffer.alloc(0) })).status, 401);
  const output = await run(compiler, ['test', path.join(core, 'security/postage.test.mpl')], { env: { ...common, MESSENGER_TEST_DATABASE_URL: url, CREDIT_POSTAGE_CORE_A: a, CREDIT_POSTAGE_CORE_B: b, CREDIT_POSTAGE_CORE_OFF: off, CREDIT_POSTAGE_EDGE_A: edgeBase } });
  console.log(output.trim()); assert.match(output, /1 passed/); assert.match(output, /CREDITS_POSTAGE_ATOMIC/);
});
