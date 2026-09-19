import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('database migrations can be applied twice without recreating tables', {
  skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, () => {
  const url = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(url).pathname.endsWith('_test'), 'use an isolated test database');
  const script = fileURLToPath(new URL('./migrate.mjs', import.meta.url));
  for (let attempt = 0; attempt < 2; attempt++) {
    const output = execFileSync(process.execPath, [script], { env: { ...process.env, MESSENGER_DATABASE_URL: url }, encoding: 'utf8' });
    assert.match(output, /Verified 9 database migrations/);
  }
});
