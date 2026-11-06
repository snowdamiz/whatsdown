import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { runSql } from '../ops/cloudflare/postgres.mjs';

test('the explicit cutover tool enforces its release policy and resumes durable operations', {
  timeout: 120_000, skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'), 'use an isolated test database');
  const name = `morse_cutover_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  const directory = mkdtempSync(join(tmpdir(), 'morse-cutover-command-'));
  const packagePath = fileURLToPath(new URL('../tools/transparency-cutover', import.meta.url));
  const compiler = process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url));
  const binary = join(directory, 'transparency-cutover');
  const env = { ...process.env, MESSENGER_DATABASE_URL: database.href,
    MESSENGER_TEST_DATABASE_URL: database.href, MESSENGER_SECURITY_CONFIG: '',
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '61'.repeat(32) };
  const run = (command, args, options = {}) => execFileSync(command, args, { env, encoding: 'utf8', timeout: 60_000, ...options });
  runSql(parent, `CREATE DATABASE ${name}`);
  try {
    run(process.execPath, [fileURLToPath(new URL('../ops/cloudflare/migrate.mjs', import.meta.url))]);
    run(compiler, ['build', packagePath, '--output', binary]);
    assert.equal(JSON.parse(run(binary, ['status'])).phase, 'legacy');
    assert.throws(() => run(binary, []), error => /usage:/.test(error.stderr));
    assert.throws(() => run(binary, ['prepare']), error => /invalid_messenger_configuration/.test(error.stderr));
    assert.equal(JSON.parse(run(binary, ['status'])).phase, 'legacy');
    run(compiler, ['test', join(packagePath, 'tests')]);
    assert.equal(JSON.parse(run(binary, ['status'])).phase, 'active');
    assert.throws(() => run(binary, ['rollback']), error => /usage:/.test(error.stderr));
    assert.equal(JSON.parse(run(binary, ['status'])).phase, 'active');
  } finally {
    runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`);
    rmSync(directory, { recursive: true, force: true });
  }
});
