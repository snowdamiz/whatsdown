import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { runSql } from '../ops/cloudflare/postgres.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import test from 'node:test';

async function interoperability(meshTest, environment = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'morse-c2sp-interop-'));
  let server;
  try {
    const binary = join(directory, 'witness');
    const built = spawnSync('go', ['build', '-o', binary, '.'], {
      cwd: fileURLToPath(new URL('../tests/c2sp-interop/', import.meta.url)),
      encoding: 'utf8', timeout: 180_000,
    });
    assert.equal(built.status, 0, built.error?.message ?? built.stderr);
    server = spawn(binary, [], { stdio: ['ignore', 'pipe', 'pipe'] });
    let errors = '';
    server.stderr.on('data', chunk => { errors = (errors + chunk).slice(-8192); });
    const ready = await new Promise((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(new Error(`witness did not start: ${errors}`)), 10_000);
      server.once('error', error => { clearTimeout(timer); reject(error); });
      server.once('exit', code => { clearTimeout(timer); reject(new Error(`witness exited ${code}: ${errors}`)); });
      server.stdout.on('data', chunk => {
        output += chunk;
        if (output.includes('\n')) {
          clearTimeout(timer);
          try { resolve(JSON.parse(output.split('\n')[0])); } catch (error) { reject(error); }
        }
      });
    });
    const result = spawnSync(process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url)), [
      'test', fileURLToPath(new URL(meshTest, import.meta.url)),
    ], {
      encoding: 'utf8', timeout: 55_000,
      env: { ...process.env, ...environment, MORSE_C2SP_TEST_URL: ready.url, MORSE_C2SP_TEST_NAME: ready.name,
        MORSE_C2SP_TEST_PUBLIC_KEY: ready.public_key },
    });
    assert.equal(result.status, 0, `${result.error?.message ?? ''}\n${result.stdout}\n${result.stderr}\n${errors}`);
  } finally {
    if (server && server.exitCode === null && server.signalCode === null) {
      const exited = once(server, 'exit');
      server.kill('SIGTERM');
      await exited;
    }
    rmSync(directory, { recursive: true, force: true });
  }
}

test('Mesh interoperates with the pinned transparency-dev C2SP witness', { timeout: 240_000 }, async () => {
  await interoperability('../packages/messenger-protocol/security/c2sp-interop.test.mpl');
});

test('the directory admits a third-party cosignature after a stored RFC migration', {
  timeout: 240_000, skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, async () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'), 'use an isolated test database');
  const name = `morse_c2sp_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  const migrations = new URL('../services/directory-delivery/migrations/', import.meta.url);
  runSql(parent, `CREATE DATABASE ${name}`);
  try {
    for (const file of readdirSync(migrations).filter(file => /^\d{3}_.+\.sql$/.test(file)).sort()) {
      runSql(database.href, readFileSync(new URL(file, migrations), 'utf8'));
    }
    await interoperability('../services/directory-delivery/security/c2sp_push.test.mpl', {
      MESSENGER_TEST_DATABASE_URL: database.href,
      MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '61'.repeat(32),
      MORSE_C2SP_PUSH: 'on',
    });
  } finally { runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`); }
});
