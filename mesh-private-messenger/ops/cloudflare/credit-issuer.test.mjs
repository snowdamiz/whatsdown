import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { creditIssuerContainerEnv, creditIssuerSecrets, issuerIngress } from './credit-issuer.mjs';
import { creditIssuerConfig, isolatedConfig } from './prepare-build.mjs';
import { issuerRequest } from './edge.mjs';
import { runSql } from './postgres.mjs';

const original = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
const token = 'e'.repeat(64);

// Everything the backend holds; none of it may reach the issuer's container.
const backendSecrets = {
  MESSENGER_DATABASE_URL: 'postgres://backend', MESSENGER_DELIVERY_SEALING_SEED_HEX: '1'.repeat(64),
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: '2'.repeat(64), MESSENGER_DELIVERY_INTERNAL_TOKEN: '3'.repeat(64),
  MESSENGER_PUSH_BROKER_SEED_HEX: '4'.repeat(64), PUSH_DATABASE_URL: 'postgres://push',
};

const issuerSecrets = {
  CREDIT_DATABASE_URL: 'postgres://credits', MORSE_CREDITS_MODE: 'live', MORSE_CREDIT_ISSUER_NAME: 'credits.morseapp.io',
  MORSE_CREDIT_KEY_WRAPPING_SEED_HEX: '5'.repeat(64), MORSE_CREDIT_DEPOSIT_SEED_HEX: '6'.repeat(128),
  MORSE_CREDIT_DIRECTORY_URL: 'https://api.morse.test', MORSE_CREDIT_ISSUER_INTERNAL_TOKEN: '7'.repeat(64),
  MORSE_CREDIT_EDGE_TOKEN: token, MORSE_CREDIT_SOLANA_RPC_URL: 'https://rpc.test', MORSE_CREDIT_ASSETS: 'usdc,sol',
};

test('credits: the issuer deploys alone, with its own container and no backend binding', () => {
  const config = creditIssuerConfig(original);
  assert.equal(config.name, 'morse-credit-issuer');
  assert.equal(config.main, 'isolated-credit-issuer.mjs');
  assert.deepEqual(config.containers.map(x => x.class_name), ['IsolatedCreditIssuer']);
  assert.deepEqual(config.durable_objects.bindings, [{ name: 'CREDIT_ISSUER', class_name: 'IsolatedCreditIssuer' }]);
  assert.equal(config.observability.enabled, false);
  assert.equal(config.r2_buckets, undefined);
  // The backend build carries no issuer container.
  const backend = isolatedConfig(original, { WITNESS_A_URL: 'https://a.test', WITNESS_B_URL: 'https://b.test', MORSE_PUSH_BROKER_URL: 'https://push.test' });
  assert.ok(!backend.containers.some(x => /Credit/.test(x.class_name)));
});

test('credits: the issuer container gets its own settings from an allowlist, and credits default to off', () => {
  const env = creditIssuerContainerEnv({ ...backendSecrets, ...issuerSecrets });
  for (const name of Object.keys(backendSecrets)) assert.equal(env[name], undefined, name);
  assert.equal(env.MORSE_CREDIT_EDGE_TOKEN, undefined, 'the edge bearer stays in the Worker');
  assert.equal(env.MORSE_CREDIT_DATABASE_URL, 'postgres://credits');
  assert.equal(env.MORSE_CREDITS_MODE, 'live');
  assert.equal(env.MORSE_CREDIT_DEPOSIT_SEED_HEX, '6'.repeat(128));
  assert.deepEqual(creditIssuerContainerEnv({ CREDIT_DATABASE_URL: 'postgres://credits' }),
    { MORSE_CREDITS_MODE: 'off', MORSE_CREDIT_DATABASE_URL: 'postgres://credits' });
  assert.throws(() => creditIssuerContainerEnv({ ...issuerSecrets, MORSE_CREDIT_ISSUER_NAME: '' }), /MORSE_CREDIT_ISSUER_NAME/);
  assert.throws(() => creditIssuerContainerEnv({ ...issuerSecrets, MORSE_CREDITS_MODE: 'on' }), /off, test or live/);
  assert.throws(() => creditIssuerContainerEnv({ MORSE_CREDITS_MODE: 'off' }), /CREDIT_DATABASE_URL/);
  assert.ok(creditIssuerSecrets.includes('MORSE_CREDIT_KEY_WRAPPING_SEED_HEX'));
});

test('credits: the issuer Worker admits only the edge, with the body alone', async () => {
  const quote = (headers = {}) => new Request('https://issuer.test/v1/credits/quote', {
    method: 'POST', body: new Uint8Array([1, 2]), headers: { 'CF-Connecting-IP': '203.0.113.9', ...headers } });
  assert.equal(issuerIngress(quote(), { MORSE_CREDIT_EDGE_TOKEN: token }).status, 401);
  assert.equal(issuerIngress(quote({ Authorization: `Bearer ${token}` }), {}).status, 503);
  const admitted = issuerIngress(quote({ Authorization: `Bearer ${token}` }), { MORSE_CREDIT_EDGE_TOKEN: token });
  assert.ok(admitted instanceof Request);
  assert.deepEqual([...admitted.headers.keys()], ['content-type']);
  assert.deepEqual(new Uint8Array(await admitted.arrayBuffer()), new Uint8Array([1, 2]));
  assert.ok(issuerIngress(new Request('https://issuer.test/health'), {}) instanceof Request);
  const fromEdge = issuerRequest(new Request('http://issuer.internal/v1/credits/issue', { method: 'POST', body: 'x' }),
    { MORSE_CREDIT_ISSUER_URL: 'https://issuer.test', MORSE_CREDIT_EDGE_TOKEN: token });
  assert.equal(fromEdge.headers.get('authorization'), `Bearer ${token}`);
  assert.ok(issuerIngress(fromEdge, { MORSE_CREDIT_EDGE_TOKEN: token }) instanceof Request);
  for (const [path, method] of [['/v1/credits/quote', 'GET'], ['/v1/credits/quote?x=1', 'POST'], ['/admin', 'POST'], ['/v1/credits/refund', 'POST']]) {
    assert.equal(issuerIngress(new Request(`https://issuer.test${path}`, { method }), { MORSE_CREDIT_EDGE_TOKEN: token }).status, 404, path);
  }
});

test('credits: the issuer database migrates from its own migrations, twice without change', {
  skip: !process.env.MESSENGER_STORAGE_TEST_DATABASE_URL,
}, () => {
  const parent = process.env.MESSENGER_STORAGE_TEST_DATABASE_URL;
  assert.ok(new URL(parent).pathname.endsWith('_test'), 'use an isolated test database');
  const name = `morse_credit_${randomBytes(6).toString('hex')}_test`;
  const database = new URL(parent); database.pathname = `/${name}`;
  runSql(parent, `CREATE DATABASE ${name}`);
  try {
    const count = readdirSync(new URL('../../services/credit-issuer/migrations/', import.meta.url)).filter(x => /^\d{3}_.+\.sql$/.test(x)).length;
    const script = fileURLToPath(new URL('./migrate.mjs', import.meta.url));
    for (let attempt = 0; attempt < 2; attempt++) {
      const output = execFileSync(process.execPath, [script, '--credit-issuer'], { env: { ...process.env, CREDIT_DATABASE_URL: database.href }, encoding: 'utf8' });
      assert.match(output, new RegExp(`Verified ${count} database migrations`));
    }
  } finally {
    runSql(parent, `DROP DATABASE ${name} WITH (FORCE)`);
  }
});
