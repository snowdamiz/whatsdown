import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { postgresEnv } from './postgres.mjs';

const run = promisify(execFile);

test('native jobs register durably before commit and roll back when registration fails', {
  skip: !process.env.MESHC || !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, async () => {
  const database = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(database).pathname.endsWith('_test'));
  let reject = false;
  let transaction;
  let failure;
  const status = async id => (await run('psql', ['-X', '-Atc', `SELECT pg_xact_status('${id}'::xid8)`], { env: postgresEnv(database) })).stdout.trim();
  const server = createServer(async (request, response) => {
    try {
      let body = '';
      for await (const chunk of request) body += chunk;
      assert.match(body, /^[1-9][0-9]{0,19}$/);
      assert.equal(request.url, '/directory');
      transaction = body;
      assert.equal(await status(transaction), 'in progress');
      response.writeHead(reject ? 503 : 204).end();
    } catch (error) {
      failure = error;
      response.writeHead(500).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    for (reject of [false, true]) {
      transaction = undefined;
      await run(process.env.MESHC, ['test', fileURLToPath(new URL('../../packages/service-jobs/tests/notify.test.mpl', import.meta.url))], {
        env: { ...process.env, MESSENGER_JOBS_URL: `http://127.0.0.1:${server.address().port}`, MESSENGER_JOB_EXPECT_FAILURE: String(reject) },
      });
      if (failure) throw failure;
      assert.ok(transaction, 'a durable wakeup must be registered');
      assert.equal(await status(transaction), reject ? 'aborted' : 'committed');
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('scheduled jobs survive failures and restarts, retain concurrent wakeups, and stop when idle', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'morse-jobs-'));
  const options = convertV4MiniflareOptions({
    name: 'morse-job-test', compatibilityDate: '2026-09-18',
    modules: [
      { type: 'ESModule', path: 'entry.mjs', contents: `
        import { DurableObject } from 'cloudflare:workers';
        export { JobScheduler } from './jobs.mjs';
        export class Service extends DurableObject {
          async mode(value) { await this.ctx.storage.put('mode', value); }
          async calls() { return await this.ctx.storage.get('calls') ?? 0; }
          async fetch(request) {
            if (request.headers.get('Authorization') !== 'Bearer test-token') return new Response(null, {status:401});
            await this.ctx.storage.put('calls', (await this.calls()) + 1);
            const mode = await this.ctx.storage.get('mode');
            if (mode === 'pending') return new Response(null, {status:202});
            if (mode === 'fail') return new Response(null, {status:503});
            if (mode === 'slow') await new Promise(resolve => setTimeout(resolve, 300));
            return new Response(mode?.startsWith('due:') ? mode.slice(4) : '0');
          }
        }
        export default { async fetch(request, env) {
          const job = env.JOBS.getByName('directory');
          const service = env.DIRECTORY.getByName('primary');
          switch (new URL(request.url).pathname) {
            case '/register': await job.register('directory', await request.text()); break;
            case '/tick': await job.run(); break;
            case '/mode': await service.mode(await request.text()); break;
            case '/stats': return Response.json({...(await job.status()), calls:await service.calls()});
          }
          return new Response(null, {status:204});
        } };` },
      { type: 'ESModule', path: 'jobs.mjs', contents: await readFile(new URL('./jobs.mjs', import.meta.url), 'utf8') },
      { type: 'ESModule', path: 'storage.mjs', contents: await readFile(new URL('./storage.mjs', import.meta.url), 'utf8') },
    ],
    bindings: { MESSENGER_DELIVERY_INTERNAL_TOKEN: 'test-token' },
    durableObjects: {
      JOBS: { className: 'JobScheduler', useSQLite: true, unsafeUniqueKey: 'morse-jobs-test' },
      DIRECTORY: { className: 'Service', useSQLite: true, unsafeUniqueKey: 'morse-service-test' },
    },
  });
  options.resourcePersistencePath = directory;
  let mf = new Miniflare(options);
  const post = (path, body = '') => mf.dispatchFetch(`http://test${path}`, { method: 'POST', body });
  const stats = async () => (await mf.dispatchFetch('http://test/stats')).json();
  try {
    await post('/mode', 'pending');
    await post('/register', '42');
    await post('/register', '42');
    await post('/tick');
    assert.equal((await stats()).pending, 1);
    await mf.dispose();
    mf = new Miniflare(options);
    await post('/mode', 'fail');
    await post('/tick');
    assert.equal((await stats()).pending, 1);
    assert.ok((await stats()).failures >= 1);
    await post('/mode', 'slow');
    const tick = post('/tick');
    await setTimeout(100);
    await post('/register', '43');
    await tick;
    assert.equal((await stats()).pending, 1, 'a wakeup arriving during work must remain scheduled');
    await post('/mode', 'idle');
    await post('/tick');
    assert.equal((await stats()).pending, 0);
    assert.equal((await stats()).due, 0);
    const calls = (await stats()).calls;
    await setTimeout(1500);
    assert.equal((await stats()).calls, calls, 'an idle scheduler must not query the service');
    const due = Date.now() + 60_000;
    await post('/mode', `due:${due}`);
    await post('/register', '44');
    await post('/tick');
    await mf.dispose();
    mf = new Miniflare(options);
    assert.equal((await stats()).due, due);
    const before = (await stats()).calls;
    await post('/tick');
    assert.equal((await stats()).calls, before, 'a future retry must not run early');
  } finally {
    await mf.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});
