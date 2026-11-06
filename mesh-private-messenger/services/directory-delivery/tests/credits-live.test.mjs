import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const service = fileURLToPath(new URL('..', import.meta.url));
const product = path.resolve(service, '../..');
const workspace = path.dirname(product);
const compiler = process.env.MESHC ?? path.resolve(workspace, '../mesh-lang/target/debug/meshc');
const bin = process.env.CREDIT_CORE_BIN ?? path.join(service, 'directory-delivery');
const fixtureProject = path.join(service, 'tests/credits-fixture');
const fixture = path.join(fixtureProject, 'credits-fixture');
const pgBin = process.env.CREDIT_TEST_PG_BIN ?? execFileSync('pg_config', ['--bindir'], { encoding: 'utf8' }).trim();
const pg = (name) => path.join(pgBin, name);
const deliveryToken = '12'.repeat(32);
const issuerToken = '34'.repeat(32);
// Published/proof-only material; never deployment credentials.
const serviceSeed = '5b'.repeat(32);
const witnessASeed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const witnessBSeed = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
const proofEnv = {
  ...process.env,
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: serviceSeed,
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  MESSENGER_DELIVERY_SEALING_SEED_HEX: '77'.repeat(32),
  MESSENGER_DELIVERY_INTERNAL_TOKEN: deliveryToken,
  MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN: issuerToken,
  MESSENGER_CREDITS_PURPOSE: 'test',
  MESSENGER_JOBS_URL: '',
  MORSE_PAID_RETENTION: 'off',
  MORSE_PAID_INBOX_POSTAGE: 'on',
  CREDIT_FIXTURE_WITNESS_A_SEED: witnessASeed,
  CREDIT_FIXTURE_WITNESS_B_SEED: witnessBSeed,
};
const run = (file, args, options = {}) => {
  try { return execFileSync(file, args, { encoding: 'utf8', timeout: 120_000, ...options }); }
  catch (error) { error.message += `\n${error.stdout ?? ''}\n${error.stderr ?? ''}`; throw error; }
};
const execFileAsync = promisify(execFile);
async function runAsync(file, args, options = {}) {
  try { return (await execFileAsync(file, args, { encoding: 'utf8', timeout: 120_000, ...options })).stdout; }
  catch (error) { error.message += `\n${error.stdout ?? ''}\n${error.stderr ?? ''}`; throw error; }
}
async function port() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
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
async function ready(base, child, log) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`core exited: ${log()}`);
    try { if ((await fetch(`${base}/health`)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`core failed to start: ${log()}`);
}
async function post(base, route, document, token = deliveryToken) {
  const response = await fetch(base + route, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(document), signal: AbortSignal.timeout(15_000),
  });
  const body = await response.text();
  let parsed = null;
  if (body) { try { parsed = JSON.parse(body); } catch { parsed = body; } }
  return { status: response.status, body: parsed };
}

test('independent cores share atomic spends, immutable holds and witnessed issuer admission', { timeout: 240_000 }, async (t) => {
  const temp = await mkdtemp(path.join(tmpdir(), 'morse-credit-ledger-'));
  const data = path.join(temp, 'postgres');
  const dbPort = await port();
  const url = `postgres://credits_test@127.0.0.1:${dbPort}/credits_test?sslmode=disable`;
  let pgStarted = false;
  const children = [];
  const logs = [];
  t.after(async () => {
    await Promise.all(children.map(stop));
    if (pgStarted) run(pg('pg_ctl'), ['-D', data, '-w', '-m', 'fast', 'stop']);
    await rm(temp, { recursive: true, force: true });
  });
  run(pg('initdb'), ['-D', data, '-U', 'credits_test', '-A', 'trust', '--no-locale']);
  run(pg('pg_ctl'), ['-D', data, '-l', path.join(temp, 'postgres.log'), '-w', 'start', '-o', `-h 127.0.0.1 -p ${dbPort} -F`]);
  pgStarted = true;
  run(pg('createdb'), ['-h', '127.0.0.1', '-p', String(dbPort), '-U', 'credits_test', 'credits_test']);
  const sql = (query) => run(pg('psql'), ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1', url, '-c', query]).trim();
  const notifications = [];
  let rejectNotifications = false;
  const jobs = createHttpServer(async (request, response) => {
    let transaction = '';
    for await (const chunk of request) transaction += chunk;
    assert(['/directory', '/witness'].includes(request.url));
    assert.match(transaction, /^[0-9]{1,20}$/);
    notifications.push({ kind: request.url, state: sql(`SELECT pg_xact_status('${transaction}'::xid8)::text`) });
    response.writeHead(rejectNotifications ? 503 : 204); response.end();
  });
  jobs.listen(0, '127.0.0.1');
  await once(jobs, 'listening');
  t.after(() => new Promise((resolve, reject) => jobs.close((error) => error ? reject(error) : resolve())));
  const jobsUrl = `http://127.0.0.1:${jobs.address().port}`;
  const migrations = (await readdir(path.join(service, 'migrations'))).filter((name) => name.endsWith('.sql')).sort();
  for (const name of migrations) run(pg('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', url, '-f', path.join(service, 'migrations', name)]);
  // The central ledger requires an active RFC6962 log. Cutover correctness has
  // its own suite; this isolated database supplies that prerequisite directly.
  sql("INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', decode(repeat('00',188),'hex'), decode(repeat('00',6),'hex'), now())");
  sql('CREATE TABLE credit_test_effects (effect_id bytea PRIMARY KEY)');
  const lockingProof = run(compiler, ['test', path.join(service, 'security/credits-locking.test.mpl')], { env: { ...proofEnv, MESSENGER_TEST_DATABASE_URL: url, MESH_SCHEDULER_MIN_WORKERS: '1', MESH_SCHEDULER_MAX_WORKERS: '1' } });
  assert.match(lockingProof, /1 passed/);
  console.log('CREDITS_ACTOR_LOCK_PROOF: one scheduler worker; suspended transaction owner; competing PostgreSQL lock waiter; both commit');
  run(compiler, ['build', fixtureProject], { env: proofEnv });
  const prepared = JSON.parse(run(fixture, [], { env: proofEnv }));
  const usedPorts = new Set([dbPort]);
  const uniquePort = async () => { let value; do { value = await port(); } while (usedPorts.has(value)); usedPorts.add(value); return value; };
  for (let index = 0; index < 2; index += 1) {
    const httpPort = await uniquePort();
    const streamPort = await uniquePort();
    let log = '';
    const child = spawn(bin, [], { env: { ...proofEnv, MESSENGER_DATABASE_URL: url, MESSENGER_PORT: String(httpPort), MESSENGER_STREAM_PORT: String(streamPort), MESSENGER_JOBS_URL: jobsUrl }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (chunk) => { log += chunk; });
    child.stderr.on('data', (chunk) => { log += chunk; });
    children.push(child); logs.push(() => log);
    await ready(`http://127.0.0.1:${httpPort}`, child, () => log);
    child.base = `http://127.0.0.1:${httpPort}`;
  }
  const [a, b] = children.map((child) => child.base);
  const redeem = (base, request, token) => post(base, '/internal/credits/redeem', request, token);
  const discoveryQuery = (previous = 0n, purpose = 1) => { const query = Buffer.from('0143494b010000000000000000', 'hex'); query[4] = purpose; query.writeBigUInt64BE(previous, 5); return query; };
  const discover = async (query = discoveryQuery()) => {
    const response = await fetch(a + '/v1/credits/issuer', { method: 'POST', body: query, signal: AbortSignal.timeout(15_000) });
    return { status: response.status, body: Buffer.from(await response.arrayBuffer()), headers: response.headers };
  };
  const adminEvidence = async (query = discoveryQuery(), token = issuerToken) => {
    const response = await fetch(a + '/internal/credits/issuers/evidence', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: query, signal: AbortSignal.timeout(15_000) });
    return { status: response.status, body: Buffer.from(await response.arrayBuffer()) };
  };
  const adminCursor = async (token = issuerToken) => {
    const response = await fetch(a + '/internal/credits/issuers/cursor', { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15_000) });
    return { status: response.status, body: Buffer.from(await response.arrayBuffer()) };
  };
  assert.equal((await adminEvidence(discoveryQuery(), deliveryToken)).status, 401);
  assert.equal((await adminCursor(deliveryToken)).status, 401);
  assert.equal((await adminCursor()).status, 200);
  assert.equal((await adminCursor()).body.length, 0);
  assert.equal((await discover(Buffer.alloc(0))).status, 400);
  assert.equal((await discover(discoveryQuery(0n, 0))).status, 400, 'caller cannot select another configured purpose');
  assert.equal((await discover()).status, 503, 'discovery needs a current admitted issuer and ready witnessed checkpoint');
  assert.equal((await redeem(a, prepared.requests.race_a, 'wrong-token')).status, 401);
  for (const kind of [1, 2]) {
    const invalid = Buffer.from(prepared.requests.race_a.action, 'hex');
    invalid[4] = kind; invalid.writeBigUInt64BE(0n, 77);
    assert.equal((await redeem(a, { ...prepared.requests.race_a, action: invalid.toString('hex') })).status, 400, 'invalid action quantities are caller errors');
  }
  assert.equal((await post(a, '/internal/credits/issuers/announce', { leaf: prepared.leaf }, deliveryToken)).status, 401);
  const announced = await post(a, '/internal/credits/issuers/announce', { leaf: prepared.leaf }, issuerToken);
  assert.equal(announced.status, 201, JSON.stringify(announced));
  const changedQuoteLeaf = Buffer.from(prepared.leaf, 'hex'); changedQuoteLeaf[changedQuoteLeaf.length - 1] ^= 1;
  assert.equal((await post(b, '/internal/credits/issuers/announce', { leaf: changedQuoteLeaf.toString('hex') }, issuerToken)).status, 409, 'the complete witnessed leaf pins the quote signer even when the RSA key is unchanged');
  assert.equal((await redeem(a, prepared.requests.race_a)).status, 400, 'publication alone cannot admit a key');
  const evidence = JSON.parse(run(fixture, [], { env: { ...proofEnv, CREDIT_FIXTURE_MODE: 'witness', CREDIT_FIXTURE_CHECKPOINT: announced.body.checkpoint, CREDIT_FIXTURE_LEAF: prepared.leaf } }));
  const submitWitness = async (hex) => {
    const response = await fetch(a + '/v2/transparency/witnesses', { method: 'POST', body: Buffer.from(hex, 'hex'), signal: AbortSignal.timeout(15_000) });
    assert.equal(response.status, 201);
  };
  const verifyDiscovery = (value, previous = '') => JSON.parse(run(fixture, [], { env: { ...proofEnv, CREDIT_FIXTURE_MODE: 'verify', CREDIT_FIXTURE_EVIDENCE: value.body.toString('hex'), CREDIT_FIXTURE_LEAF: prepared.leaf, CREDIT_FIXTURE_PREVIOUS_CHECKPOINT: previous } }));
  assert.equal((await adminEvidence(Buffer.alloc(0))).status, 400);
  assert.equal((await adminEvidence()).status, 503, 'admin candidate evidence also needs stored witness signatures');
  assert.equal((await discover()).status, 503, 'publication alone is never public admission');
  await submitWitness(evidence.witness_a);
  assert.equal((await adminEvidence()).status, 503, 'one stored witness is below the pinned majority');
  assert.equal((await discover()).status, 503);
  await submitWitness(evidence.witness_b);
  const candidate = await adminEvidence();
  assert.equal(candidate.status, 200);
  assert.equal(verifyDiscovery(candidate).tree_size, '1');
  assert.equal((await discover()).status, 503, 'even a witnessed candidate remains unavailable to public purchase until admitted');
  assert.equal(sql('SELECT count(*) FROM credit_issuer_announcements WHERE admitted_at IS NOT NULL'), '0');
  assert.equal((await adminCursor()).body.length, 0, 'candidate evidence cannot advance the core admission cursor');
  assert.equal((await adminEvidence(discoveryQuery(18446744073709551615n))).status, 409);
  assert.equal((await post(a, '/internal/credits/issuers/admit', { evidence: evidence.unwitnessed }, issuerToken)).status, 400);
  assert.equal((await post(a, '/internal/credits/issuers/admit', { evidence: candidate.body.toString('hex') }, issuerToken)).status, 201);
  assert.equal((await post(b, '/internal/credits/issuers/admit', { evidence: candidate.body.toString('hex') }, issuerToken)).status, 200);
  const changedQuoteEvidence = JSON.parse(run(fixture, [], { env: { ...proofEnv, CREDIT_FIXTURE_MODE: 'witness', CREDIT_FIXTURE_CHECKPOINT: announced.body.checkpoint, CREDIT_FIXTURE_LEAF: changedQuoteLeaf.toString('hex') } }));
  assert.equal((await post(b, '/internal/credits/issuers/admit', { evidence: changedQuoteEvidence.evidence }, issuerToken)).status, 400, 'idempotent admission cannot silently accept a changed quote signer');
  const admittedCursor = await adminCursor();
  assert.equal(admittedCursor.status, 200);
  assert.equal(admittedCursor.body.toString('hex'), announced.body.checkpoint);
  const checkpointCount = sql('SELECT count(*) FROM transparency_v2_checkpoints');
  const firstDiscovery = await discover();
  assert.equal(firstDiscovery.status, 200);
  assert.equal(firstDiscovery.headers.get('content-type'), 'application/octet-stream');
  assert.equal(firstDiscovery.headers.get('cache-control'), 'no-store');
  assert.equal(verifyDiscovery(firstDiscovery).tree_size, '1');
  assert.equal(verifyDiscovery(await discover(discoveryQuery(1n)), announced.body.checkpoint).tree_size, '1');
  assert.equal((await discover(discoveryQuery(18446744073709551615n))).status, 409, 'full U64 is checked before signed/narrow conversion');
  assert.equal(sql('SELECT count(*) FROM transparency_v2_checkpoints'), checkpointCount, 'discovery never creates checkpoints');
  const otherPurposeLeaf = Buffer.from(prepared.rogue_leaf, 'hex'); otherPurposeLeaf[12] = 0;
  const pendingCheckpoint = await post(a, '/internal/credits/issuers/announce', { leaf: otherPurposeLeaf.toString('hex') }, issuerToken);
  assert.equal(pendingCheckpoint.status, 201);
  const whilePending = await discover();
  assert.equal(whilePending.status, 200);
  assert.deepEqual(whilePending.body, firstDiscovery.body, 'a newer unwitnessed checkpoint does not hide ready evidence');
  assert.equal((await discover(discoveryQuery(2n))).status, 409, 'discovery cannot downgrade a client ahead of the ready quorum');
  const nextWitnesses = JSON.parse(run(fixture, [], { env: { ...proofEnv, CREDIT_FIXTURE_MODE: 'attest', CREDIT_FIXTURE_CHECKPOINT: pendingCheckpoint.body.checkpoint } }));
  await submitWitness(nextWitnesses.witness_a); await submitWitness(nextWitnesses.witness_b);
  const advanced = await discover(discoveryQuery(1n));
  assert.equal(advanced.status, 200);
  assert.equal(verifyDiscovery(advanced, announced.body.checkpoint).tree_size, '2', 'compiled client verifies a real nontrivial consistency extension');
  sql('UPDATE credit_issuer_announcements SET epoch = epoch - 1 WHERE purpose = 1');
  assert.equal((await discover()).status, 503, 'current discovery never selects an admitted previous-epoch issuer');
  sql('UPDATE credit_issuer_announcements SET epoch = epoch + 1 WHERE purpose = 1');
  const timestamps = sql("SELECT sequence::text||':'||timestamp_ms::text FROM transparency_v2_checkpoints ORDER BY sequence").split('\n').map((row) => row.split(':'));
  sql('UPDATE transparency_v2_checkpoints SET timestamp_ms = 1');
  assert.equal((await discover()).status, 503, 'stale checkpoints fail closed without synthetic witnesses');
  for (const [sequence, timestamp] of timestamps) sql(`UPDATE transparency_v2_checkpoints SET timestamp_ms = ${timestamp} WHERE sequence = ${sequence}`);
  assert.equal((await discover()).status, 200);

  const originalCount = sql('SELECT count(*) FROM transparency_entries');
  assert.equal((await post(b, '/internal/credits/issuers/announce', { leaf: prepared.leaf }, issuerToken)).status, 200);
  assert.equal((await post(b, '/internal/credits/issuers/announce', { leaf: prepared.rogue_leaf }, issuerToken)).status, 409);
  assert.equal(sql('SELECT count(*) FROM transparency_entries'), originalCount, 'conflicting publication never appends');
  const rogue = { ...prepared.requests.rogue, keys: [prepared.rogue_leaf] };
  assert.equal((await redeem(a, rogue)).status, 400, 'caller supplied key cannot mint credit');
  // Force both independent PostgreSQL transactions into the spend statement
  // at once. This trigger exists only in the disposable test database.
  sql("CREATE FUNCTION credit_test_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE TRIGGER credit_test_pause BEFORE INSERT ON credit_spent FOR EACH ROW EXECUTE FUNCTION credit_test_pause()");
  const racing = Promise.all([redeem(a, prepared.requests.race_a), redeem(b, prepared.requests.race_b)]);
  let overlapped = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    if (Number(sql("SELECT count(*) FROM pg_stat_activity WHERE datname = 'credits_test' AND state = 'active' AND query LIKE 'WITH proposed AS%'")) >= 2) { overlapped = true; break; }
  }
  assert(overlapped, 'both independent service requests must overlap inside their PostgreSQL spend transactions');
  const raced = await racing;
  sql('DROP TRIGGER credit_test_pause ON credit_spent; DROP FUNCTION credit_test_pause()');
  assert.deepEqual(raced.map((value) => value.status).sort(), [201, 409], JSON.stringify(raced));
  const winner = raced[0].status === 201 ? prepared.requests.race_a : prepared.requests.race_b;
  const firstHold = raced.find((value) => value.status === 201).body;
  assert.equal(sql('SELECT count(*) FROM credit_spent'), '1');
  assert.equal(sql('SELECT count(*) FROM credit_holds'), '1');
  const retry = await redeem(b, winner);
  assert.equal(retry.status, 200); assert.equal(retry.body.hold_id, firstHold.hold_id);
  assert.equal((await redeem(a, prepared.requests.mixed)).status, 409);
  assert.equal(sql('SELECT count(*) FROM credit_spent'), '1', 'mixed spent/fresh frame rolls back every fresh spend');
  assert.equal(sql('SELECT count(*) FROM credit_holds'), '1', 'failed frame leaves no hold');
  assert.equal((await redeem(a, prepared.requests.fresh)).status, 201, 'fresh token from rolled-back frame remains spendable');
  const changed = winner === prepared.requests.race_a ? prepared.requests.replacement_a : prepared.requests.replacement_b;
  assert.equal(changed.action, winner.action, 'only the offered token changes in this retry');
  assert.equal((await redeem(a, changed)).status, 409, 'an operation cannot replace its immutable payment frame');
  assert.equal((await redeem(b, prepared.requests.second)).status, 201, 'conflicting retry does not spend replacement token');
  assert.equal((await redeem(a, prepared.requests.signup)).status, 400, 'base difficulty cannot be priced by the caller');
  const rawPostagePolicy = async (body) => fetch(a + '/v1/credits/postage-policy', { method: 'POST', body: Buffer.from(body, 'hex'), signal: AbortSignal.timeout(15_000) });
  assert.equal((await fetch(a + '/v1/devices/register', { method: 'PUT', body: Buffer.from(prepared.postage_registration, 'hex'), signal: AbortSignal.timeout(15_000) })).status, 201);
  assert.equal((await rawPostagePolicy(prepared.postage_policy_five)).status, 201);
  assert.equal((await redeem(a, prepared.requests.postage)).status, 400, 'postage price comes from the authenticated account policy, not the offered token count');
  assert.equal((await rawPostagePolicy(prepared.postage_policy_one)).status, 201);
  rejectNotifications = true;
  assert.equal((await redeem(a, prepared.requests.postage)).status, 503, 'unavailable durable scheduling rolls back redemption');
  assert.equal(sql('SELECT count(*) FROM credit_spent'), '3');
  assert.equal(sql('SELECT count(*) FROM credit_holds'), '3');
  rejectNotifications = false;
  assert.equal((await redeem(a, prepared.requests.postage)).status, 201, 'rejected price/scheduling attempts leave the token spendable');
  assert(notifications.filter((notice) => notice.kind === '/directory').length >= 7, 'startup and each committed hold must register a durable directory wakeup');
  assert(notifications.every((notice) => notice.state === 'in progress'), 'durable wakeups must be registered before their PostgreSQL transaction commits');
  const effects = run(compiler, ['test', path.join(service, 'security/credits-effect.test.mpl')], { env: { ...proofEnv, MESSENGER_TEST_DATABASE_URL: url, CREDIT_TEST_ACTION: winner.action } });
  assert.match(effects, /1 passed/);
  const completedRetry = await redeem(a, winner);
  assert.equal(completedRetry.status, 200); assert.equal(completedRetry.body.state, 'consumed');
  assert.equal(completedRetry.body.hold_id, firstHold.hold_id);
  assert.equal(sql('SELECT count(*) FROM credit_test_effects'), '1');
  assert.equal(sql('SELECT count(*) FROM credit_spent'), '4');
  // Synthetic expired records belong only to this disposable proof database.
  const actionHex = winner.action;
  sql(`INSERT INTO credit_holds (hold_id, action, action_kind, target, request_hash, frame_hash, credits, expires_at, retain_until) SELECT sha256(('old-hold-'||n)::bytea), decode('${actionHex}','hex'), 1, decode(repeat('77',32),'hex'), decode(repeat('00',32),'hex'), decode(repeat('00',32),'hex'), 1, 1, 2 FROM generate_series(1,5) n`);
  sql("INSERT INTO credit_spent (nullifier,issuer_epoch,retain_until,hold_id) SELECT sha256(('old-token-'||n)::bytea),0,2,sha256(('old-hold-'||n)::bytea) FROM generate_series(1,5) n");
  const pruned = await post(a, '/internal/credits/prune', { limit: 2 }, issuerToken);
  assert.equal(pruned.status, 200); assert.equal(pruned.body.spent, 2); assert.equal(pruned.body.holds, 2);
  assert.equal(sql('SELECT count(*) FROM credit_spent WHERE retain_until = 2'), '3');
  assert.equal(sql('SELECT count(*) FROM credit_spent WHERE retain_until > 2'), '4', 'unexpired spends never pruned');
  assert.equal((await post(a, '/internal/credits/prune', { limit: 1001 }, issuerToken)).status, 400);
  sql(`INSERT INTO credit_holds (hold_id, action, action_kind, target, request_hash, frame_hash, credits, expires_at, retain_until) SELECT sha256(('scheduled-hold-'||n)::bytea), decode('${actionHex}','hex'), 1, decode(repeat('77',32),'hex'), decode(repeat('00',32),'hex'), decode(repeat('00',32),'hex'), 1, 1, 2 FROM generate_series(1,131) n`);
  sql("INSERT INTO credit_spent (nullifier,issuer_epoch,retain_until,hold_id) SELECT sha256(('scheduled-token-'||n)::bytea),0,2,sha256(('scheduled-hold-'||n)::bytea) FROM generate_series(1,131) n");
  const scheduled = async () => {
    const response = await fetch(a + '/internal/v1/jobs/directory', { method: 'POST', headers: { Authorization: `Bearer ${deliveryToken}` }, body: '0', signal: AbortSignal.timeout(15_000) });
    assert.equal(response.status, 200);
    return Number(await response.text());
  };
  assert.equal(await scheduled(), 3000, 'remaining expired credit rows must keep the durable worker due immediately');
  assert.equal(sql('SELECT count(*) FROM credit_spent WHERE retain_until = 2'), '6', 'scheduled pruning is bounded to 128 spends per run');
  assert.equal(sql('SELECT count(*) FROM credit_holds WHERE retain_until = 2'), '6');
  const due = await scheduled();
  assert.equal(sql('SELECT count(*) FROM credit_spent WHERE retain_until = 2'), '0');
  assert.equal(sql('SELECT count(*) FROM credit_spent'), '4');
  assert.equal(sql('SELECT count(*) FROM credit_holds'), '4');
  assert.equal(String(due), sql('SELECT ((min(retain_until)+1)*1000)::text FROM credit_spent'), 'idle scheduler wakes after the next absolute credit retention deadline');
  assert(due > Date.now());
  // Existing log-reset/idle-scheduler contracts run against another database
  // in this owned cluster, with all migrations and no issuer FK bypass.
  run(pg('createdb'), ['-h', '127.0.0.1', '-p', String(dbPort), '-U', 'credits_test', 'credits_reset_test']);
  const resetUrl = url.replace('/credits_test?', '/credits_reset_test?');
  for (const name of migrations) run(pg('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', resetUrl, '-f', path.join(service, 'migrations', name)]);
  const resetProof = run(compiler, ['test', path.join(service, 'tests/transparency_retention.test.mpl')], { env: { ...proofEnv, MESSENGER_TEST_DATABASE_URL: resetUrl } });
  assert.match(resetProof, /3 passed/);
  for (const [file, count] of [['storage.test.mpl', 1], ['hardening.test.mpl', 1], ['api.test.mpl', 2]]) {
    const freeProof = run(compiler, ['test', path.join(service, 'tests', file)], { env: { ...proofEnv, MESSENGER_TEST_DATABASE_URL: resetUrl } });
    assert.match(freeProof, new RegExp(`${count} passed`));
  }

  run(pg('createdb'), ['-h', '127.0.0.1', '-p', String(dbPort), '-U', 'credits_test', 'credits_retention_test']);
  const retentionUrl = url.replace('/credits_test?', '/credits_retention_test?');
  for (const name of migrations) run(pg('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', retentionUrl, '-f', path.join(service, 'migrations', name)]);
  run(pg('psql'), ['-X', '-q', '-v', 'ON_ERROR_STOP=1', retentionUrl, '-c', "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', decode(repeat('00',188),'hex'), decode(repeat('00',6),'hex'), now())"]);
  const paidPort = await uniquePort(); const paidStreamPort = await uniquePort();
  let paidLog = '';
  const paidCore = spawn(bin, [], { env: { ...proofEnv, MESSENGER_DATABASE_URL: retentionUrl, MESSENGER_PORT: String(paidPort), MESSENGER_STREAM_PORT: String(paidStreamPort), MESSENGER_JOBS_URL: jobsUrl, MORSE_PAID_RETENTION: 'on' }, stdio: ['ignore', 'pipe', 'pipe'] });
  paidCore.stdout.on('data', (chunk) => { paidLog += chunk; }); paidCore.stderr.on('data', (chunk) => { paidLog += chunk; }); children.push(paidCore);
  const paidBase = `http://127.0.0.1:${paidPort}`;
  await ready(paidBase, paidCore, () => paidLog);
  let retentionProof;
  try { retentionProof = await runAsync(compiler, ['test', path.join(service, 'security/credits-retention.test.mpl')], { env: { ...proofEnv, MESSENGER_TEST_DATABASE_URL: retentionUrl, CREDIT_TEST_CORE_URL: paidBase, CREDIT_TEST_DISABLED_CORE_URL: a }, timeout: 120_000 }); }
  catch (error) { error.message += `\nCORE_LOG: ${paidLog}\nPG_ACTIVITY: ${sql("SELECT state||':'||COALESCE(wait_event,'')||':'||query FROM pg_stat_activity WHERE datname = 'credits_retention_test'")}`; throw error; }
  assert.match(retentionProof, /1 passed/);
  console.log('CREDITS_RETENTION_PROOF: owner authorization; rollback after spending; concurrent exact recovery; original ciphertext/TTL; future deposits; bounded parking; signed receipt');
  console.log('CREDITS_DISCOVERY_PROOF: public admitted-only; admin candidate+cursor; real stored quorum; ready fallback; compiled client consistency verification');
  console.log('CREDITS_RESET_PROOF: existing7 PostgreSQL retention/reset, free delivery, hardening and authorization contracts passed');
  console.log('CREDITS_LEDGER_PROOF: two cores; one concurrent winner; mixed rollback; immutable retry; atomic durable effect; bounded retention');
});
