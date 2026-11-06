import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
const require = createRequire(import.meta.url);
const creditPurpose = require('../plugins/credits-config.cjs');

test('Lightning network is an optional native pin bound to the credit purpose', () => {
  assert.equal(creditPurpose.lightningNetwork({}), undefined);
  assert.equal(creditPurpose.lightningNetwork({ MESSENGER_CREDIT_PURPOSE: 'live', MESSENGER_CREDIT_LIGHTNING_NETWORK: 'mainnet' }), 'mainnet');
  for (const network of ['testnet', 'regtest', 'signet', 'simnet']) {
    assert.equal(creditPurpose.lightningNetwork({ MESSENGER_CREDIT_PURPOSE: 'test', MESSENGER_CREDIT_LIGHTNING_NETWORK: network }), network);
    assert.throws(() => creditPurpose.lightningNetwork({ MESSENGER_CREDIT_PURPOSE: 'live', MESSENGER_CREDIT_LIGHTNING_NETWORK: network }));
  }
  for (const purpose of [undefined, 'test']) assert.throws(() => creditPurpose.lightningNetwork({ MESSENGER_CREDIT_PURPOSE: purpose, MESSENGER_CREDIT_LIGHTNING_NETWORK: 'mainnet' }));
  for (const value of ['', 'MAINNET', ' mainnet', 'mainnet ', 'bitcoin']) assert.throws(() => creditPurpose.lightningNetwork({ MESSENGER_CREDIT_PURPOSE: 'live', MESSENGER_CREDIT_LIGHTNING_NETWORK: value }));
});

test('native purpose stays explicit and any enabled issuer requires pinned RFC configuration', () => {
  assert.equal(creditPurpose({}), undefined);
  assert.equal(creditPurpose({ MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://edge.example' }), undefined);
  for (const purpose of ['live', 'test']) {
    const env = { MESSENGER_CREDIT_PURPOSE: purpose, MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://edge.example', MESSENGER_TRANSPARENCY_LOG_VERSION: '2' };
    assert.equal(creditPurpose(env), purpose);
    for (const origin of [undefined, '-']) assert.equal(creditPurpose({ ...env, MESSENGER_CREDIT_ISSUER_ORIGIN: origin }), purpose);
    for (const origin of ['', 'http://edge.example', 'https://user@edge.example', 'https://edge.example/path']) {
      assert.throws(() => creditPurpose({ ...env, MESSENGER_CREDIT_ISSUER_ORIGIN: origin }));
    }
    assert.throws(() => creditPurpose({ ...env, MESSENGER_TRANSPARENCY_LOG_VERSION: '1' }));
  }
  for (const purpose of ['', '0', '1', 'LIVE', ' live', 'test ']) assert.throws(() => creditPurpose({ MESSENGER_CREDIT_PURPOSE: purpose }));
});

test('wallet custody pins remain available while credit spending has no issuer', () => {
  for (const purpose of ['live', 'test']) for (const origin of [undefined, '-']) {
    const env = { MESSENGER_CREDIT_PURPOSE: purpose, MESSENGER_CREDIT_ISSUER_ORIGIN: origin,
      MESSENGER_CREDIT_USDC_MINT_ADDRESS: '1'.repeat(31) + '2' };
    assert.equal(creditPurpose(env), purpose);
    assert.equal(creditPurpose.walletMint(env), '00'.repeat(31) + '01');
  }
});

test('wallet mint is canonical native configuration and never defaults to a caller quote', () => {
  const env = { MESSENGER_CREDIT_PURPOSE: 'test', MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://edge.example', MESSENGER_TRANSPARENCY_LOG_VERSION: '2' };
  assert.equal(creditPurpose.walletMint(env), undefined);
  assert.equal(creditPurpose.walletMint({ ...env, MESSENGER_CREDIT_USDC_MINT_ADDRESS: '1'.repeat(31) + '2' }), '00'.repeat(31) + '01');
  for (const value of ['', '0'.repeat(32), '1'.repeat(32), ' 11111111111111111111111111111112', '1'.repeat(31), '1'.repeat(33)]) {
    assert.throws(() => creditPurpose.walletMint({ ...env, MESSENGER_CREDIT_USDC_MINT_ADDRESS: value }));
  }
  assert.throws(() => creditPurpose.walletMint({ MESSENGER_CREDIT_USDC_MINT_ADDRESS: '1'.repeat(31) + '2' }));
});
