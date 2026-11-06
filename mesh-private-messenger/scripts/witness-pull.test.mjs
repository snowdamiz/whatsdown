import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const run = promisify(execFile);
const source = fileURLToPath(new URL('../services/transparency-witness', import.meta.url));
const seed = '5b'.repeat(32); // Public fixture key, never a deployed witness.
const key = createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${seed}`, 'hex'), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
function checkpoint(root, sequence = 1, previous = Buffer.alloc(32), version = 1, size = 1) {
  const wide = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const fields = Buffer.concat([wide(sequence), wide(size), Buffer.isBuffer(root) ? root : Buffer.alloc(32, root), previous, wide(Date.now()), publicKey]);
  return Buffer.concat([Buffer.from([version, 75, 84, 75]), fields,
    sign(null, Buffer.concat([Buffer.from('mesh-key-transparency-v1'), Buffer.from([0, version]), fields]), key)]);
}
async function fixture(action) {
  const dir = await mkdtemp(join(tmpdir(), 'morse-pull-proof-'));
  const binary = join(dir, 'witness');
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const env = { ...process.env, MESSENGER_WITNESS_ID: 'witness-c',
    MESSENGER_WITNESS_CHECKPOINT_PATH: join(dir, 'checkpoint'),
    MESSENGER_WITNESS_SIGNING_SEED_HEX: seed, MESSENGER_WITNESS_PUBLIC_KEY_HEX: publicKey.toString('hex'),
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: publicKey.toString('hex'), WITNESS_INITIAL_CHECKPOINT_HEX: 'new-identity' };
  try {
    await run(process.env.MESHC, ['build', source, '--output', binary]);
    await action({ dir, binary, server, base, env });
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
}
test('two file-backed witness processes cannot release signatures for conflicting checkpoints', { skip: !process.env.MESHC }, async () => {
  await fixture(async ({ dir, binary, server, base, env }) => {
    const frames = [checkpoint(3), checkpoint(4)];
    const waiting = [];
    let submissions = 0;
    server.on('request', (request, response) => {
      if (request.url.endsWith('/checkpoint')) {
        waiting.push([response, frames[request.url.startsWith('/left/') ? 0 : 1]]);
        if (waiting.length === 2) for (const [target, frame] of waiting) target.end(frame);
      } else if (request.url.endsWith('/witnesses')) {
        submissions++; response.writeHead(201).end();
      } else response.writeHead(404).end();
    });
    const results = await Promise.allSettled(['left', 'right'].map(side => run(binary, [], {
      env: { ...env, MESSENGER_BASE_URL: `${base}/${side}` }, timeout: 15_000,
    })));
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(submissions, 1);
    const failure = results.find(r => r.status === 'rejected');
    assert.match(failure.reason.stderr, /checkpoint changed concurrently|database is locked/);
    const saved = Buffer.from(await readFile(join(dir, 'checkpoint'), 'utf8'), 'base64');
    assert.ok(frames.some(frame => frame.equals(saved)));
  });
});
test('pull mode survives an unavailable directory and stops promptly on SIGTERM', { skip: !process.env.MESHC }, async () => {
  await fixture(async ({ binary, server, base, env }) => {
    let requests = 0;
    let posted;
    const submission = new Promise(resolve => { posted = resolve; });
    server.on('request', (request, response) => {
      if (request.url.endsWith('/checkpoint')) {
        if (++requests === 1) response.writeHead(503).end();
        else response.end(checkpoint(3));
      } else if (request.url.endsWith('/witnesses')) { response.writeHead(201).end(); posted(); }
      else response.writeHead(404).end();
    });
    const child = spawn(binary, [], { env: { ...env, MESSENGER_BASE_URL: base, MESSENGER_WITNESS_MODE: 'pull' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; child.stdout.on('data', x => { output += x; }); child.stderr.on('data', x => { output += x; });
    let timer;
    const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
    try {
      await Promise.race([submission, exited.then(result => { throw new Error(`witness exited before recovery: ${JSON.stringify(result)} ${output}`); }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`no recovery: ${output}`)), 22_000); })]);
      child.kill('SIGTERM');
      const result = await Promise.race([exited, new Promise((_, reject) => setTimeout(() => reject(new Error('slow shutdown')), 3000).unref())]);
      assert.deepEqual(result, { code: 0, signal: null });
      assert.equal(requests, 2);
    } finally { clearTimeout(timer); child.kill('SIGKILL'); await exited; }
  });
});

test('a signed broken history link is retained durably without advancing signing state', { skip: !process.env.MESHC }, async () => {
  await fixture(async ({ dir, binary, server, base, env }) => {
    let current = checkpoint(3);
    const first = current;
    let submissions = 0;
    server.on('request', (request, response) => {
      if (request.url.endsWith('/checkpoint')) response.end(current);
      else if (request.url.endsWith('/witnesses')) { submissions++; response.writeHead(201).end(); }
      else response.writeHead(404).end();
    });
    const attest = () => run(binary, [], { env: { ...env, MESSENGER_BASE_URL: base } });
    await attest();
    current = checkpoint(3, 2); // Signed, but does not name its immediately preceding checkpoint.
    await assert.rejects(attest(), error => /link mismatch/.test(error.stderr));
    assert.equal(submissions, 1);
    assert.equal(Buffer.from(await readFile(join(dir, 'checkpoint'), 'utf8'), 'base64').toString('hex'), first.toString('hex'));
    const captured = JSON.parse(await readFile(join(dir, 'checkpoint.evidence-history.json'), 'utf8'));
    assert.equal(captured.previous, first.toString('hex'));
    assert.equal(captured.current, current.toString('hex'));
    assert.equal(captured.error, 'transparency checkpoint link mismatch');
  });
});

test('pull witnesses verify a pinned legacy bridge before a durable one-way RFC transition', { skip: !process.env.MESHC }, async () => {
  await fixture(async ({ dir, binary, server, base, env }) => {
    const cat = (...parts) => Buffer.concat(parts.map(part => typeof part === 'string' ? Buffer.from(part) : part));
    const hash = (...parts) => createHash('sha256').update(cat(...parts)).digest();
    const u32 = value => { const result = Buffer.alloc(4); result.writeUInt32BE(value); return result; };
    const vec = bytes => cat(u32(bytes.length), bytes);
    const seal = checkpoint(7, 8, Buffer.alloc(32), 1, 5);
    const sealHash = hash('mesh-msg/v1/transparency-checkpoint', 'mesh-key-transparency-v1', Buffer.from([0, 1]), seal.subarray(4));
    const sealSignature = sign(null, cat('mesh-msg/v1/transparency-witness', 'legacy-a', sealHash), key);
    const witnesses = cat(Buffer.from([1]), 'KTW', Buffer.from([0, 1]), vec(Buffer.from('legacy-a')), sealHash, sealSignature);
    const missingWitnesses = cat(Buffer.from([1]), 'KTW', Buffer.from([0, 0]));
    const current = checkpoint(hash(Buffer.from([0, 1]), 'KTM', seal), 1, Buffer.alloc(32), 2);
    const bridge = signatures => cat(Buffer.from([1]), 'KTB', seal, vec(signatures),
      vec(cat(Buffer.from([2]), 'KTC', u32(5), u32(5), Buffer.from([0, 0]))),
      vec(cat(Buffer.from([3]), 'KTI', u32(0), u32(1), Buffer.from([0, 0]))));
    const securityConfig = createRequire(import.meta.url)('../apps/mobile/plugins/security-config.cjs');
    const frame = securityConfig({
      MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: publicKey.toString('hex'),
      MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '12'.repeat(32), MESSENGER_ABUSE_DIFFICULTY: '8',
      MESSENGER_WITNESS_THRESHOLD: '1', MESSENGER_WITNESS_SET_JSON: JSON.stringify([
        { id: 'witness-c', publicKey: publicKey.toString('hex'), operator: 'Fixture' },
      ]), MESSENGER_TRANSPARENCY_LOG_VERSION: '2', MESSENGER_LEGACY_WITNESS_THRESHOLD: '1',
      MESSENGER_LEGACY_WITNESS_SET_JSON: JSON.stringify([
        { id: 'legacy-a', publicKey: publicKey.toString('hex'), operator: 'Fixture' },
      ]),
    });
    let rfcStatus = 404, candidate = current, bridgeBytes = bridge(missingWitnesses);
    const submissions = [], queries = [], routes = [];
    server.on('request', async (request, response) => {
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      routes.push(request.url);
      if (request.url === '/v1/transparency/checkpoint') response.end(seal);
      else if (request.url === '/v2/transparency/checkpoint') response.writeHead(rfcStatus).end(rfcStatus === 200 ? candidate : undefined);
      else if (request.url === '/v2/transparency/legacy-bridge') { queries.push(body); response.end(bridgeBytes); }
      else if (request.url.endsWith('/witnesses')) { submissions.push(request.url); response.writeHead(201).end(); }
      else response.writeHead(404).end();
    });
    const attest = config => run(binary, [], { env: { ...env, MESSENGER_BASE_URL: base, ...(config ? { MESSENGER_SECURITY_CONFIG: config } : {}) }, timeout: 15_000 });
    const saved = async () => Buffer.from(await readFile(join(dir, 'checkpoint'), 'utf8'), 'base64');
    await attest();
    await attest(frame); // Explicit pre-cutover 404 may still use the pinned legacy log.
    assert.deepEqual(submissions, ['/v1/transparency/witnesses', '/v1/transparency/witnesses']);
    rfcStatus = 200;
    await assert.rejects(attest(frame), error => /legacy bridge verification failed/.test(error.stderr));
    assert.deepEqual(await saved(), seal);
    assert.equal(submissions.length, 2);
    bridgeBytes = bridge(witnesses);
    await attest(frame);
    assert.deepEqual(await saved(), current);
    assert.equal(submissions.at(-1), '/v2/transparency/witnesses');
    assert.equal(queries.length, 2);
    for (const query of queries) assert.deepEqual(query, cat(Buffer.from([1]), 'KBQ', u32(5), u32(1)));
    await attest(frame); // Retry after persistence releases the same signature without a new bridge.
    assert.equal(queries.length, 2);
    candidate = seal;
    await assert.rejects(attest(frame), error => /checkpoint log version mismatch/.test(error.stderr));
    rfcStatus = 404;
    const legacyReads = routes.filter(route => route === '/v1/transparency/checkpoint').length;
    await assert.rejects(attest(frame), error => /checkpoint missing after initialization/.test(error.stderr));
    assert.equal(routes.filter(route => route === '/v1/transparency/checkpoint').length, legacyReads);
    await assert.rejects(attest(), error => /unsupported_transparency_log/.test(error.stderr));
    assert.deepEqual(await saved(), current);
    assert.equal(submissions.length, 4);
  });
});
