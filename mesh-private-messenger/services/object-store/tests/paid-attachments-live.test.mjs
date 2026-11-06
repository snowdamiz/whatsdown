import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const service = fileURLToPath(new URL('..', import.meta.url));
const product = path.resolve(service, '../..');
const core = path.join(product, 'services/directory-delivery');
const compiler = process.env.MESHC ?? path.resolve(product, '../../mesh-lang/target/debug/meshc');
const layouts = process.env.CREDIT_ATTACHMENT_LAYOUT ? [process.env.CREDIT_ATTACHMENT_LAYOUT] : ['2', '1'];
assert(layouts.every((value) => value === '1' || value === '2'), 'invalid proof layout');
let builtHere = false;
const pgBin = process.env.CREDIT_TEST_PG_BIN ?? execFileSync('pg_config', ['--bindir'], { encoding: 'utf8' }).trim();
const execute = promisify(execFile);
let commandIndex = 0;
let activeEvidence = null;
async function run(file, args, options = {}) {
  const index = commandIndex++;
  const evidence = activeEvidence;
  const started = new Date().toISOString();
  try {
    const result = await execute(file, args, { encoding: 'utf8', timeout: 240_000, maxBuffer: 4 * 1024 * 1024, ...options });
    if (evidence) await writeFile(path.join(evidence, `command-${index}.json`), JSON.stringify({ file, args, started, exit_code: 0, stdout: result.stdout, stderr: result.stderr }, null, 2));
    return result.stdout;
  } catch (error) {
    if (evidence) await writeFile(path.join(evidence, `command-${index}.json`), JSON.stringify({ file, args, started, exit_code: error.code, signal: error.signal, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }, null, 2));
    error.message += `\n${error.stdout ?? ''}\n${error.stderr ?? ''}`;
    throw error;
  }
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
  MORSE_PAID_LARGE_ATTACHMENTS: 'on',
  MORSE_PAID_RETENTION: 'off',
};

for (const layout of layouts) test(`paid attachment layout${layout} uses actual core spends and bounded streaming with recovery`, { timeout: 900_000, concurrency: false }, async (t) => {
  const evidenceBase = process.env.M5_PROOF_DIRECTORY ? path.resolve(process.env.M5_PROOF_DIRECTORY) : null;
  if (evidenceBase) await mkdir(evidenceBase, { recursive: true });
  const temp = evidenceBase ? path.join(evidenceBase, `layout-${layout}`) : await mkdtemp(path.join(tmpdir(), `morse-attachments-layout${layout}-`));
  if (evidenceBase) await mkdir(temp);
  activeEvidence = evidenceBase ? temp : null;
  console.log('owned evidence directory: ' + temp);
  const data = path.join(temp, 'postgres'); const objects = path.join(temp, 'objects');
  await mkdir(objects);
  const pgPort = await port(); const children = []; let started = false;
  t.after(async () => {
    await Promise.all(children.map(stop));
    if (started) await run(path.join(pgBin, 'pg_ctl'), ['-D', data, '-w', '-m', 'fast', 'stop']);
    if (evidenceBase) await writeFile(path.join(temp, 'teardown.json'), JSON.stringify({ stoppedOwnedServices: true, stoppedOwnedPostgres: started, evidencePreserved: true }, null, 2));
    else await rm(temp, { recursive: true, force: true });
  });
  await run(path.join(pgBin, 'initdb'), ['-D', data, '-U', 'attachments_test', '-A', 'trust', '--no-locale']);
  await run(path.join(pgBin, 'pg_ctl'), ['-D', data, '-l', path.join(temp, 'postgres.log'), '-w', 'start', '-o', `-h 127.0.0.1 -p ${pgPort} -F`]); started = true;
  for (const db of ['attachments_core_test', 'attachments_object_test']) await run(path.join(pgBin, 'createdb'), ['-h', '127.0.0.1', '-p', String(pgPort), '-U', 'attachments_test', db]);
  const coreUrl = `postgres://attachments_test@127.0.0.1:${pgPort}/attachments_core_test?sslmode=disable`;
  const objectUrl = `postgres://attachments_test@127.0.0.1:${pgPort}/attachments_object_test?sslmode=disable`;
  for (const migration of (await readdir(path.join(core, 'migrations'))).filter((name) => name.endsWith('.sql')).sort()) {
    await run(path.join(pgBin, 'psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', coreUrl, '-f', path.join(core, 'migrations', migration)]);
  }
  await run(path.join(pgBin, 'psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', coreUrl, '-c', "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', decode(repeat('00',188),'hex'), decode(repeat('00',6),'hex'), now())"]);
  if (!process.env.CREDIT_ATTACHMENT_SKIP_BUILD && !builtHere) {
    await run(compiler, ['build', core, '--opt-level', '2'], { env: common });
    await run(compiler, ['build', service, '--opt-level', '2'], { env: common });
    builtHere = true;
  }
  const used = new Set([pgPort]);
  async function uniquePort() { let value; do { value = await port(); } while (used.has(value)); used.add(value); return value; }
  async function start(binary, env, portName) {
    const httpPort = await uniquePort(); let logs = '';
    const child = spawn(binary, [], { env: { ...common, ...env, [portName]: String(httpPort) }, stdio: ['ignore', 'pipe', 'pipe'] });
    const recordLog = (value) => { logs += value; };
    child.stdout.on('data', recordLog); child.stderr.on('data', recordLog);
    child.on('exit', () => { void writeFile(path.join(temp, `${path.basename(binary)}-${httpPort}.log`), logs); });
    children.push(child);
    await ready(`http://127.0.0.1:${httpPort}`, child, () => logs);
    return `http://127.0.0.1:${httpPort}`;
  }
  const coreBase = await start(path.join(core, 'directory-delivery'), { MESSENGER_DATABASE_URL: coreUrl, MESSENGER_STREAM_PORT: String(await uniquePort()) }, 'MESSENGER_PORT');
  const storeEnv = { MESSENGER_OBJECT_DATABASE_URL: objectUrl, MESSENGER_OBJECT_STORAGE_ROOT: objects, MESSENGER_OBJECT_CREDIT_CORE_URL: coreBase };
  const a = await start(path.join(service, 'object-store'), storeEnv, 'MESSENGER_OBJECT_PORT');
  const b = await start(path.join(service, 'object-store'), storeEnv, 'MESSENGER_OBJECT_PORT');
  const off = await start(path.join(service, 'object-store'), { ...storeEnv, MORSE_PAID_LARGE_ATTACHMENTS: 'off' }, 'MESSENGER_OBJECT_PORT');
  const unauthorized = await fetch(coreBase + '/internal/credits/attachments/grant', { method: 'POST', body: Buffer.alloc(0) });
  assert.equal(unauthorized.status, 401);
  const output = await run(compiler, ['test', path.join(service, 'security/paid-fixture/paid.test.mpl'), '--opt-level', '2'], { env: {
    ...common, CREDIT_ATTACHMENT_LAYOUT: layout, CREDIT_ATTACHMENT_CORE_DATABASE_URL: coreUrl, CREDIT_ATTACHMENT_OBJECT_DATABASE_URL: objectUrl,
    MESSENGER_OBJECT_STORAGE_ROOT: objects, CREDIT_ATTACHMENT_CORE: coreBase,
    CREDIT_ATTACHMENT_OBJECT_A: a, CREDIT_ATTACHMENT_OBJECT_B: b, CREDIT_ATTACHMENT_OBJECT_OFF: off,
  } });
  await writeFile(path.join(temp, 'paid.log'), output); console.log(output.trim()); assert.match(output, /1 passed/);
  // Existing free-path tests use only our isolated object DB and directory.
  const free = await run(compiler, ['test', path.join(service, 'tests/attachment_buckets.test.mpl'), '--opt-level', '2'], { env: {
    ...common, CREDIT_ATTACHMENT_LAYOUT: layout, MESSENGER_STORAGE_TEST_DATABASE_URL: objectUrl, MESSENGER_OBJECT_STORAGE_ROOT: objects,
  } });
  await writeFile(path.join(temp, 'free.log'), free); console.log(free.trim()); assert.match(free, /passed/);
  if (layout === '1') {
    const originalFree = await run(compiler, ['test', path.join(service, 'tests/object_store.test.mpl'), '--opt-level', '2'], { env: {
      ...common, MESSENGER_STORAGE_TEST_DATABASE_URL: objectUrl,
    } });
    await writeFile(path.join(temp, 'legacy-free.log'), originalFree); console.log(originalFree.trim()); assert.match(originalFree, /passed/);
  }
  await writeFile(path.join(temp, 'result.json'), JSON.stringify({ status: 'passed', layout, paid: '1 passed', free: '1 passed', clock: 'fresh paid HTTP service clock; synthetic direct free/maintenance fixture timestamps' }, null, 2));
});
