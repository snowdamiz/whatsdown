import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('witness checkpoints survive restarts and reject stale writes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-checkpoint-'));
  const options = convertV4MiniflareOptions({
    name: 'morse-checkpoint-test',
    compatibilityDate: '2026-09-18',
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: 'export { CheckpointStore } from "./checkpoint.mjs"; export default { fetch: (r, e) => e.STATE.getByName("witness-a").fetch(r) };' },
      { type: 'ESModule', path: 'checkpoint.mjs', contents: await readFile(new URL('./checkpoint.mjs', import.meta.url), 'utf8') },
      { type: 'ESModule', path: 'storage.mjs', contents: await readFile(new URL('./storage.mjs', import.meta.url), 'utf8') },
    ],
    durableObjects: { STATE: { className: 'CheckpointStore', useSQLite: true, unsafeUniqueKey: 'morse-checkpoint-test' } },
  });
  options.resourcePersistencePath = directory;
  let mf = new Miniflare(options);
  const put = (body, previous) => mf.dispatchFetch('http://checkpoint.internal/', { method: 'PUT', headers: { 'If-Match': previous }, body });
  try {
    assert.equal((await mf.dispatchFetch('http://checkpoint.internal/')).status, 404);
    assert.equal((await put('first', 'none')).status, 204);
    assert.equal((await put('second', 'none')).status, 409);
    assert.equal((await put('second', createHash('sha256').update('first').digest('hex'))).status, 204);
    assert.equal(await (await mf.dispatchFetch('http://checkpoint.internal/')).text(), 'second');
    await mf.dispose();
    mf = new Miniflare(options);
    assert.equal(await (await mf.dispatchFetch('http://checkpoint.internal/')).text(), 'second');
    assert.equal((await put('first', 'none')).status, 409);
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test('native witness accepts an empty new log, persists signed HTTP checkpoints, and rejects their disappearance', {
  skip: !process.env.MESHC,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-witness-'));
  const binary = join(directory, 'witness');
  const run = promisify(execFile);
  const seed = '5b'.repeat(32);
  const key = createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${seed}`, 'hex'), format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
  const one = Buffer.alloc(8); one.writeBigUInt64BE(1n);
  const fields = Buffer.concat([one, one, Buffer.alloc(32, 5), Buffer.alloc(32), one, publicKey]);
  const signature = sign(null, Buffer.concat([Buffer.from('mesh-key-transparency-v1'), Buffer.from([0, 1]), fields]), key);
  const checkpoint = Buffer.concat([Buffer.from([1]), Buffer.from('KTK'), fields, signature]);
  const mf = new Miniflare(convertV4MiniflareOptions({
    compatibilityDate: '2026-09-18',
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: `export { CheckpointStore } from './checkpoint.mjs';
        let checkpoint; let rejectWrites = true; let submissions = 0;
        export default { async fetch(r,e) {
          const path = new URL(r.url).pathname;
          if (path === '/submissions') return new Response(String(submissions));
          if (path === '/allow-writes') { rejectWrites = false; return new Response(null, {status:204}); }
          if (path === '/checkpoint' && r.method === 'PUT' && rejectWrites) return new Response(null, {status:409});
          if (path === '/fixture') { checkpoint = r.method === 'PUT' ? await r.arrayBuffer() : undefined; return new Response(null, {status:204}); }
          if (path === '/core/v1/transparency/checkpoint') return new Response(checkpoint, {status:checkpoint ? 200 : 404});
          if (path === '/core/v1/transparency/witnesses') { submissions++; return new Response(null, {status:201}); }
          return e.STATE.getByName('witness-a').fetch(r);
        } };` },
      { type: 'ESModule', path: 'checkpoint.mjs', contents: await readFile(new URL('./checkpoint.mjs', import.meta.url), 'utf8') },
      { type: 'ESModule', path: 'storage.mjs', contents: await readFile(new URL('./storage.mjs', import.meta.url), 'utf8') },
    ],
    durableObjects: { STATE: { className: 'CheckpointStore', useSQLite: true } },
  }));
  try {
    await run(process.env.MESHC, ['build', fileURLToPath(new URL('../../services/transparency-witness', import.meta.url)), '--output', binary]);
    const origin = (await mf.ready).origin;
    const attest = () => run(binary, [], { env: { ...process.env,
      MESSENGER_BASE_URL: `${origin}/core`, MESSENGER_WITNESS_ID: 'witness-a',
      MESSENGER_WITNESS_CHECKPOINT_PATH: `${origin}/checkpoint`,
      MESSENGER_WITNESS_SIGNING_SEED_HEX: seed,
      MESSENGER_WITNESS_PUBLIC_KEY_HEX: publicKey.toString('hex'),
      MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: publicKey.toString('hex'),
    } });
    await attest();
    await mf.dispatchFetch(`${origin}/fixture`, { method: 'PUT', body: checkpoint });
    await assert.rejects(attest(), error => error.stderr.includes('checkpoint write failed'));
    assert.equal(await (await mf.dispatchFetch(`${origin}/submissions`)).text(), '0', 'failed durable checkpoint must not release a signature');
    await mf.dispatchFetch(`${origin}/allow-writes`);
    await attest();
    assert.deepEqual(Buffer.from(await (await mf.dispatchFetch(`${origin}/checkpoint`)).arrayBuffer()), checkpoint);
    await attest();
    const invalidPrior = Buffer.from(checkpoint); invalidPrior[invalidPrior.length - 1] ^= 1;
    const replace = (body, previous) => mf.dispatchFetch(`${origin}/checkpoint`, { method: 'PUT', body, headers: { 'If-Match': createHash('sha256').update(previous).digest('hex') } });
    assert.equal((await replace(invalidPrior, checkpoint)).status, 204);
    await assert.rejects(attest(), error => error.stderr.includes('cached witness checkpoint signature failed'));
    assert.equal((await replace(checkpoint, invalidPrior)).status, 204);
    await mf.dispatchFetch(`${origin}/fixture`, { method: 'DELETE' });
    await assert.rejects(attest(), error => error.stderr.includes('checkpoint missing after initialization'));
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});
