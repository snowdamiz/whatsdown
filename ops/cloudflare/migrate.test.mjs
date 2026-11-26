import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { runSql } from './postgres.mjs';
import { fileURLToPath } from 'node:url';

test('database migrations can be applied twice without recreating tables', {
  skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, () => {
  const url = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(url).pathname.endsWith('_test'), 'use an isolated test database');
  const script = fileURLToPath(new URL('./migrate.mjs', import.meta.url));
  // Every numbered migration must be verified; counting the files keeps this true when one is added.
  const migrations = readdirSync(new URL('../../services/directory-delivery/migrations/', import.meta.url))
    .filter(name => /^\d{3}_.+\.sql$/.test(name)).length;
  assert.ok(migrations >= 12);
  for (let attempt = 0; attempt < 2; attempt++) {
    const output = execFileSync(process.execPath, [script], { env: { ...process.env, MESSENGER_DATABASE_URL: url }, encoding: 'utf8' });
    assert.match(output, new RegExp(`Verified ${migrations} database migrations`));
  }
});

// The native test truncates its own schema to exercise concurrent publication and rollback.
test('native directory verifies account lookup, revocation, checkpoint freshness and atomic rotation', {
  skip: !process.env.MESHC || !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
  timeout: 180_000,
}, () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'), 'use an isolated test database');
  const name = `morse_directory_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  runSql(parent, `CREATE DATABASE ${name}`);
  try {
    const env = { ...process.env, MESSENGER_DATABASE_URL: database.href, MESSENGER_TEST_DATABASE_URL: database.href,
      MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '5b'.repeat(32),
      MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b',
      MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    };
    execFileSync(process.execPath, [fileURLToPath(new URL('./migrate.mjs', import.meta.url))], { env });
    execFileSync(process.env.MESHC, ['test', fileURLToPath(new URL('../../services/directory-delivery/tests/devices.test.mpl', import.meta.url))], { env, timeout: 150_000, maxBuffer: 4 * 1024 * 1024 });
  } finally {
    runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`);
  }
});
