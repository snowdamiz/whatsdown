import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, readdir, mkdtemp, mkdir, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout } from 'node:timers/promises';
import test from 'node:test';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { postgresEnv, runSql } from './postgres.mjs';

const run = promisify(execFile);

async function unusedPort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function until(check, label) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (await check()) return;
    await setTimeout(200);
  }
  throw new Error(`${label} timed out`);
}

test('native encrypted delivery and witnesses work with polling disabled and durable Cloudflare wakeups', {
  skip: !process.env.MESHC || !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
  timeout: 600_000,
}, async () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'));
  const name = `morse_events_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  const directory = await mkdtemp(join(tmpdir(), 'morse-event-live-'));
  const children = [];
  let mf;
  let control;
  let created = false;
  const ports = await Promise.all(Array.from({ length: 5 }, unusedPort));
  const core = `http://127.0.0.1:${ports[0]}`;
  const edge = `http://127.0.0.1:${ports[1]}`;
  const push = `http://127.0.0.1:${ports[2]}`;
  const objects = `http://127.0.0.1:${ports[3]}`;
  const token = '0123456789abcdef'.repeat(4);
  const env = { ...process.env,
    MESSENGER_DATABASE_URL: database.href,
    MESSENGER_OBJECT_DATABASE_URL: database.href,
    MESSENGER_PUSH_BROKER_DATABASE_URL: database.href,
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '5b'.repeat(32),
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b',
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    MESSENGER_DELIVERY_SEALING_SEED_HEX: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    MESSENGER_PUSH_BROKER_SEED_HEX: '0d'.repeat(32),
    MESSENGER_DELIVERY_INTERNAL_TOKEN: token,
    MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token,
    MESSENGER_OBJECT_INTERNAL_TOKEN: token,
    MESSENGER_PUSH_MODE: 'disabled',
    MESSENGER_DIRECT_DELIVERY_COMPATIBILITY: '',
    MESSENGER_DELIVERY_INTERNAL_URL: core,
    MESSENGER_ABUSE_DIFFICULTY: '8',
    MESSENGER_OBJECT_WORK_DIFFICULTY: '4',
    MESSENGER_PORT: String(ports[0]), MESSENGER_PRIVACY_EDGE_PORT: String(ports[1]),
    MESSENGER_PUSH_BROKER_PORT: String(ports[2]), MESSENGER_OBJECT_PORT: String(ports[3]),
    MESSENGER_STREAM_PORT: String(ports[4]), MESSENGER_OBJECT_STORAGE_ROOT: join(directory, 'parts'),
  };
  try {
    runSql(parent, `CREATE DATABASE ${name}`); created = true;
    await run(process.execPath, [fileURLToPath(new URL('./migrate.mjs', import.meta.url))], { env });
    await mkdir(env.MESSENGER_OBJECT_STORAGE_ROOT);
    for (const service of ['directory-delivery', 'privacy-edge', 'push-broker', 'object-store', 'transparency-witness']) {
      await run(process.env.MESHC, ['build', fileURLToPath(new URL(`../../services/${service}`, import.meta.url)), '--output', join(directory, service)], { maxBuffer: 4 * 1024 * 1024 });
    }
    control = createServer(async (request, response) => {
      const which = request.url === '/a' ? 'A' : request.url === '/b' ? 'B' : undefined;
      if (!which) { response.writeHead(404).end(); return; }
      try {
        await run(join(directory, 'transparency-witness'), [], { env: { ...env,
          MESSENGER_BASE_URL: core, MESSENGER_WITNESS_ID: `witness-${which.toLowerCase()}`,
          MESSENGER_WITNESS_CHECKPOINT_PATH: `${env.MESSENGER_JOBS_URL}/checkpoint/${which}`,
          MESSENGER_WITNESS_PUBLIC_KEY_HEX: env[`MESSENGER_WITNESS_${which}_PUBLIC_KEY_HEX`],
          MESSENGER_WITNESS_SIGNING_SEED_HEX: which === 'A'
            ? '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
            : '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
        }, timeout: 60_000 });
        response.writeHead(204).end();
      } catch { response.writeHead(503).end(); }
    });
    await new Promise(resolve => control.listen(0, '127.0.0.1', resolve));
    const modules = await Promise.all(['jobs', 'checkpoint', 'storage'].map(async name => ({ type: 'ESModule', path: `${name}.mjs`, contents: await readFile(new URL(`./${name}.mjs`, import.meta.url), 'utf8') })));
    mf = new Miniflare(convertV4MiniflareOptions({
      compatibilityDate: '2026-09-18',
      modules: [{ type: 'ESModule', path: 'entry.mjs', contents: `
        import { DurableObject } from 'cloudflare:workers';
        export { JobScheduler } from './jobs.mjs';
        export { CheckpointStore } from './checkpoint.mjs';
        export class Native extends DurableObject {
          async fetch(request) {
            const kind = new URL(request.url).pathname.split('/').at(-1);
            const origin = kind === 'push' ? this.env.PUSH_URL : kind === 'objects' ? this.env.OBJECT_URL : this.env.CORE_URL;
            const url = new URL(request.url); url.host = new URL(origin).host;
            await this.ctx.storage.put('calls', (await this.calls()) + 1);
            return fetch(new Request(url, request));
          }
          async calls() { return await this.ctx.storage.get('calls') ?? 0; }
        }
        export class WitnessA extends DurableObject { async attest() { if (!(await fetch(this.env.EXEC_URL + '/a')).ok) throw new Error('Witness A failed'); } }
        export class WitnessB extends DurableObject { async attest() { if (!(await fetch(this.env.EXEC_URL + '/b')).ok) throw new Error('Witness B failed'); } }
        export default { async fetch(request, env) {
          const path = new URL(request.url).pathname;
          if (path.startsWith('/checkpoint/')) return env.STATE.getByName(path).fetch(request);
          if (path === '/status') return Response.json({ jobs: await Promise.all(['directory','witness','push','objects'].map(k => env.JOBS.getByName(k).status())), calls: await env.DIRECTORY.getByName('primary').calls() });
          const kind = path.slice(1);
          if (request.method !== 'POST' || !['directory','witness','push','objects'].includes(kind)) return new Response(null,{status:404});
          await env.JOBS.getByName(kind).register(kind, await request.text());
          return new Response(null,{status:204});
        } };` }, ...modules],
      bindings: { CORE_URL: core, PUSH_URL: push, OBJECT_URL: objects, EXEC_URL: `http://127.0.0.1:${control.address().port}`,
        MESSENGER_DELIVERY_INTERNAL_TOKEN: token, MESSENGER_PUSH_BROKER_INTERNAL_TOKEN: token, MESSENGER_OBJECT_INTERNAL_TOKEN: token },
      durableObjects: {
        JOBS: { className: 'JobScheduler', useSQLite: true }, STATE: { className: 'CheckpointStore', useSQLite: true },
        DIRECTORY: { className: 'Native', useSQLite: true }, PUSH_BROKER: { className: 'Native', useSQLite: true }, OBJECT_STORE: { className: 'Native', useSQLite: true },
        WITNESS_A: { className: 'WitnessA', useSQLite: true }, WITNESS_B: { className: 'WitnessB', useSQLite: true },
      },
    }));
    env.MESSENGER_JOBS_URL = (await mf.ready).origin;
    for (const [service, origin] of [['directory-delivery', core], ['privacy-edge', edge], ['push-broker', push], ['object-store', objects]]) {
      const log = await open(join(directory, `${service}.log`), 'w');
      const child = spawn(join(directory, service), { env, stdio: ['ignore', log.fd, log.fd] });
      children.push(child); await log.close();
      await until(async () => {
        if (child.exitCode !== null) throw new Error(`${service} exited: ${await readFile(join(directory, `${service}.log`), 'utf8')}`);
        try { return (await fetch(`${origin}/health`, { signal: AbortSignal.timeout(1000) })).ok; } catch { return false; }
      }, service);
    }
    for (const [origin, kind] of [[core, 'directory'], [push, 'push'], [objects, 'objects']]) {
      const path = `${origin}/internal/v1/jobs/${kind}`;
      assert.equal((await fetch(path, { method: 'POST', body: '0' })).status, 401);
      const response = await fetch(path, { method: 'POST', body: '0', headers: { authorization: `Bearer ${token}` } });
      assert.equal(response.status, 200); assert.equal(await response.text(), '0');
    }
    assert.equal((await fetch(`${objects}/v1/objects/${'0'.repeat(64)}/parts/0`, {
      headers: { 'x-object-capability': '1'.repeat(64) },
    })).status, 404, 'object capabilities must work through proxies that lowercase headers');
    assert.equal((await fetch(`${push}/internal/v1/push`, {
      method: 'POST', body: 'invalid', headers: { authorization: `Bearer ${token}` },
    })).status, 422, 'authenticated broker requests must reach body validation');
    await run(process.env.MESHC, ['test', fileURLToPath(new URL('../../tests/m13-live', import.meta.url))], { env: { ...env,
      MESSENGER_M13_CORE_URL: core, MESSENGER_M13_EDGE_URL: edge,
      MESSENGER_M13_ALICE_DB_PATH: join(directory, 'alice.db'), MESSENGER_M13_BOB_DB_PATH: join(directory, 'bob.db'),
      MESSENGER_M13_PROOF_PLAINTEXT: 'm13 live private suite-2 message',
    }, maxBuffer: 4 * 1024 * 1024 });
    await run(process.env.MESHC, ['test', fileURLToPath(new URL('../../tests/cloudflare-live', import.meta.url))], {
      env: { ...env, MESSENGER_EVENT_OBJECT_URL: objects }, maxBuffer: 4 * 1024 * 1024,
    });
    const status = async () => (await mf.dispatchFetch('http://test/status')).json();
    await until(async () => (await status()).jobs.every(job => job.pending === 0 && job.failures === 0), 'event jobs');
    const query = async sql => (await run('psql', ['-X', '-Atc', sql], { env: postgresEnv(database.href) })).stdout.trim();
    assert.equal(await query("SELECT count(*) FROM messenger_outbox_events WHERE completed_at IS NULL"), '0');
    assert.equal(await query("SELECT count(*) FROM witness_signatures"), '2');
    await until(async () => await query('SELECT count(*) FROM objects') === '0', 'object expiry');
    assert.deepEqual(await readdir(env.MESSENGER_OBJECT_STORAGE_ROOT), []);
    const calls = (await status()).calls;
    await setTimeout(1500);
    assert.equal((await status()).calls, calls, 'no service queries are made while waiting for future deadlines');
    assert.match(await readFile(join(directory, 'directory-delivery.log'), 'utf8'), /with 0 workers/);
  } finally {
    await mf?.dispose();
    if (control) await new Promise(resolve => control.close(resolve));
    for (const child of children) child.kill('SIGTERM');
    await Promise.all(children.map(async child => {
      if (child.exitCode !== null) return;
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), setTimeout(5000).then(() => child.kill('SIGKILL'))]);
    }));
    if (created) runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`);
    await rm(directory, { recursive: true, force: true });
  }
});
