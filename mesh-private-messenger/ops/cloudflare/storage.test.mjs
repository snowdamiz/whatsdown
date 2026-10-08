import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { objectStoreCore } from './storage.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

test('R2 preserves exact concurrent replays and rejects overwrites, invalid keys, and oversized parts', async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({
    compatibilityDate: '2026-09-18',
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: 'export { objectStorage as default } from "./storage.mjs";' },
      { type: 'ESModule', path: 'storage.mjs', contents: await readFile(new URL('./storage.mjs', import.meta.url), 'utf8') },
    ],
    r2Buckets: ['OBJECTS'],
  }));
  try {
    const path = `http://objects.internal/${'a'.repeat(64)}.256`;
    const put = (body) => mf.dispatchFetch(path, { method: 'PUT', body });
    const statuses = await Promise.all([put('opaque'), put('opaque')]).then(rs => rs.map(r => r.status).sort());
    assert.deepEqual(statuses, [200, 201]);
    assert.equal((await put('changed')).status, 409);
    assert.equal(await (await mf.dispatchFetch(path)).text(), 'opaque');
    assert.equal((await put(new Uint8Array(65609))).status, 413);
    assert.equal((await mf.dispatchFetch(path.replace('.256', '.8193'))).status, 400);
    assert.equal((await mf.dispatchFetch(path.replace('.256', '.08192'))).status, 400);
    assert.equal((await mf.dispatchFetch('http://objects.internal/arbitrary-key')).status, 400);
    assert.equal((await mf.dispatchFetch(path, { method: 'DELETE' })).status, 204);
    assert.equal((await mf.dispatchFetch(path)).status, 404);
    if (process.env.MESHC) {
      const url = await mf.ready;
      await promisify(execFile)(process.env.MESHC, ['test', fileURLToPath(new URL('../../services/object-store/tests/remote_files.test.mpl', import.meta.url))], {
        env: { ...process.env, MESSENGER_OBJECT_TEST_STORAGE_ROOT: url.origin },
      });
    }
  } finally {
    await mf.dispose();
  }
});

// A large attachment has up to 8,193 parts: deleting it is one call that
// removes every part in batches, not one call per part.
test('R2 deletes every part of a large object in one request', async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({
    compatibilityDate: '2026-09-18',
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: 'export { objectStorage as default } from "./storage.mjs";' },
      { type: 'ESModule', path: 'storage.mjs', contents: await readFile(new URL('./storage.mjs', import.meta.url), 'utf8') },
    ],
    r2Buckets: ['OBJECTS'],
  }));
  try {
    const object = `http://objects.internal/${'b'.repeat(64)}`;
    for (const index of [0, 1500, 8192]) {
      assert.equal((await mf.dispatchFetch(`${object}.${index}`, { method: 'PUT', body: 'part' })).status, 201);
    }
    const remove = (count, method = 'DELETE') => mf.dispatchFetch(object, { method, headers: count === undefined ? {} : { 'X-Part-Count': count } });
    for (const count of [undefined, '0', '8194', '01', '1e3']) assert.equal((await remove(count)).status, 400);
    assert.equal((await remove('8193', 'GET')).status, 400);
    assert.equal((await remove('8193')).status, 204);
    for (const index of [0, 1500, 8192]) assert.equal((await mf.dispatchFetch(`${object}.${index}`)).status, 404);
  } finally {
    await mf.dispose();
  }
});

// The object store reaches the core for one thing: redeeming a large file's credits.
test('the object store reaches only the core redeem route', async () => {
  const forwarded = [];
  const env = { DIRECTORY: { getByName: (name) => ({ fetch: (request) => { forwarded.push([name, request.url]); return new Response(null, { status: 201 }); } }) } };
  const redeem = 'http://delivery.internal/internal/v1/credits/redeem';
  assert.equal((await objectStoreCore(new Request(redeem, { method: 'POST', body: 'x' }), env)).status, 201);
  assert.deepEqual(forwarded, [['primary', redeem]]);
  for (const [url, method] of [[redeem, 'GET'], [`${redeem}?x=1`, 'POST'], ['http://delivery.internal/internal/v1/envelopes/sealed', 'POST'],
    ['http://delivery.internal/internal/v1/credits/issuer-keys', 'POST']]) {
    assert.equal((await objectStoreCore(new Request(url, { method }), env)).status, 404);
  }
  assert.equal(forwarded.length, 1);
});
