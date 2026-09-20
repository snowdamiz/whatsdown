import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
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
    assert.equal((await mf.dispatchFetch(path.replace('.256', '.257'))).status, 400);
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
