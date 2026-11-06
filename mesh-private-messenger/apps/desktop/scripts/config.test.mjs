import assert from 'node:assert/strict';
import { createHash as suiteFloorHash } from 'node:crypto';
import test from 'node:test';
import { desktopConfig, checkMacSigning, windowsSigningConfig } from './config.mjs';

const ohttpSecurity = {
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: '22'.repeat(32),
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '33'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '44'.repeat(32),
  MESSENGER_ABUSE_DIFFICULTY: '8',
};

test('desktop bundles an explicit empty RPC TLS resource when no roots are configured', () => {
  const config = desktopConfig(ohttpSecurity, true);
  assert.equal(config.rpcTlsRoots, '');
  assert.equal(JSON.parse(JSON.stringify(config)).rpcTlsRoots, '');
});

test('desktop v4 security resources separate production and development log identities', () => {
  const pins = JSON.stringify([
    { id: 'a', publicKey: '01'.repeat(32), operator: 'Morse' },
    { id: 'b', publicKey: '02'.repeat(32), operator: 'Outside' },
  ]);
  const env = {
    EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://messenger.example.com',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example.com',
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '44'.repeat(32), MESSENGER_ABUSE_DIFFICULTY: '16',
    MESSENGER_WITNESS_SET_JSON: pins, MESSENGER_WITNESS_THRESHOLD: '2',
    MESSENGER_LEGACY_WITNESS_SET_JSON: pins, MESSENGER_LEGACY_WITNESS_THRESHOLD: '2',
    MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
    MESSENGER_ANCHOR_RING_ADDRESS: '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: '1'.repeat(32), MESSENGER_ANCHOR_LOG_NAME: 'morse-main',
    MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://two.example', 'https://three.example']),
  };
  assert.ok(desktopConfig(env).securityFrame.startsWith('4\n'));
  assert.ok(desktopConfig(env).securityFrame.endsWith('\nmorse-main'));
  assert.equal(desktopConfig(env).creditPurpose, '');
  for (const purpose of ['live', 'test']) {
    const credits = desktopConfig({ ...env, MESSENGER_CREDIT_PURPOSE: purpose, MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://credits.example' });
    assert.equal(credits.creditPurpose, purpose);
    assert.equal(credits.creditIssuerOrigin, 'https://credits.example');
    for (const origin of [undefined, '-']) {
      const walletOnly = desktopConfig({ ...env, MESSENGER_CREDIT_PURPOSE: purpose,
        MESSENGER_CREDIT_ISSUER_ORIGIN: origin, MESSENGER_CREDIT_USDC_MINT_ADDRESS: '1'.repeat(31) + '2' });
      assert.equal(walletOnly.creditPurpose, purpose);
      assert.equal(walletOnly.creditIssuerOrigin, '');
      assert.equal(walletOnly.creditUsdcMintHex, '00'.repeat(31) + '01');
      assert.ok(walletOnly.securityFrame.includes('\n-\n'));
    }
  }
  const relay = { ...env, MESSENGER_RELAY_URLS: JSON.stringify(['https://relay.example']),
    MESSENGER_SLASH_MINT_ADDRESS: 'cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN' };
  assert.ok(desktopConfig(relay).securityFrame.startsWith('5\n'));
  assert.ok(desktopConfig(relay).securityFrame.endsWith(`\n${relay.MESSENGER_SLASH_MINT_ADDRESS}\n1\nhttps://relay.example`));
  assert.throws(() => desktopConfig({ ...relay, MESSENGER_ANCHOR_LOG_NAME: 'morse-canary' }), /morse-main/);
  const canary = { ...env, MESSENGER_ANCHOR_LOG_NAME: 'morse-canary',
    MESSENGER_ANCHOR_RING_ADDRESS: 'D9mWiuuEDxC1CXJQMXgiB4zAj8yviMwwZQ3mvLUW5MD' };
  assert.throws(() => desktopConfig(canary), /morse-main/);
  assert.ok(desktopConfig(canary, true).securityFrame.endsWith('\nmorse-canary'));
});

test('C8 Windows releases require a signer command and the expected certificate', () => {
  const env = { WINDOWS_SIGN_COMMAND: 'issuer-sign-tool --file %1', WINDOWS_SIGNER_THUMBPRINT: 'A'.repeat(40) };
  assert.equal(windowsSigningConfig(env).bundle.windows.signCommand, env.WINDOWS_SIGN_COMMAND);
  for (const changes of [{ WINDOWS_SIGN_COMMAND: '' }, { WINDOWS_SIGN_COMMAND: 'echo signed' },
    { WINDOWS_SIGNER_THUMBPRINT: '' }, { WINDOWS_SIGNER_THUMBPRINT: 'not-a-certificate' }]) {
    assert.throws(() => windowsSigningConfig({ ...env, ...changes }));
  }
});

test('Mac releases cannot silently fall back to unsigned or unnotarized packages', () => {
  const env = {
    APPLE_CERTIFICATE: 'base64-p12', APPLE_CERTIFICATE_PASSWORD: 'export-password',
    APPLE_SIGNING_IDENTITY: 'Developer ID Application: Example (ABCDEFGHIJ)',
    APPLE_ID: 'developer@example.com', APPLE_PASSWORD: 'app-specific-password', APPLE_TEAM_ID: 'ABCDEFGHIJ',
  };
  assert.doesNotThrow(() => checkMacSigning(env));
  for (const name of Object.keys(env)) assert.throws(() => checkMacSigning({ ...env, [name]: '' }), new RegExp(name));
  assert.throws(() => checkMacSigning({ ...env, APPLE_SIGNING_IDENTITY: '-' }));
});

test('desktop releases require TLS and the same native security pins as mobile', () => {
  const env = {
    EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://messenger.example.com',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example.com',
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: '22'.repeat(32),
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '33'.repeat(32),
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '44'.repeat(32),
    MESSENGER_ABUSE_DIFFICULTY: '16',
  };
  assert.equal(desktopConfig(env).streamUrl, 'wss://messenger.example.com/v1/mailbox/stream');
  assert.equal(desktopConfig(env).securityFrame.split('\n').length, 6);
  // Production routes the object store on the messenger origin; a dedicated origin stays optional.
  assert.equal(desktopConfig(env).objectUrl, 'https://messenger.example.com');
  assert.equal(desktopConfig({ ...env, EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'https://objects.example.com/' }).objectUrl,
    'https://objects.example.com');
  for (const changes of [
    { EXPO_PUBLIC_MESSENGER_BASE_URL: 'http://localhost:18086' },
    { EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://user:password@example.com' },
    { EXPO_PUBLIC_MESSENGER_STREAM_URL: 'ws://example.com' },
    { EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'http://objects.example.com' },
    { MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: env.MESSENGER_WITNESS_A_PUBLIC_KEY_HEX },
    { MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '' },
  ]) assert.throws(() => desktopConfig({ ...env, ...changes }));
  assert.throws(() => desktopConfig({}));
  assert.equal(desktopConfig(ohttpSecurity, true).baseUrl, 'http://127.0.0.1:18086');
  assert.equal(desktopConfig(ohttpSecurity, true).streamUrl, 'ws://127.0.0.1:18090/v1/mailbox/stream');
  assert.equal(desktopConfig(ohttpSecurity, true).objectUrl, 'http://127.0.0.1:18089');
  assert.equal(desktopConfig(ohttpSecurity, true).networkFrame,
    '2\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream\n16');
  assert.equal(desktopConfig(env).networkFrame,
    '2\n0\nhttps://messenger.example.com\nhttps://edge.example.com\nhttps://messenger.example.com\nwss://messenger.example.com/v1/mailbox/stream\n16');
});


test('desktop pins object work difficulty into the native frame', () => {
  assert.equal(desktopConfig({ ...ohttpSecurity, EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: '7' }, true).networkFrame.split('\n').at(-1), '7');
  assert.throws(() => desktopConfig({ ...ohttpSecurity, EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: '25' }, true), /difficulty/i);
});



test('desktop bundles a bound OHTTP companion with native-only release authority', async () => {
  const { createHash } = await import('node:crypto');
  const digest = value => createHash('sha256').update(value).digest('hex');
  const off = desktopConfig(ohttpSecurity, true);
  assert.equal(off.ohttpFrame, ['1', digest(off.networkFrame), digest(off.securityFrame), '1', 'off', '0'].join('\n'));
  const pins = JSON.stringify({ schema_version: 1, mode: 'required', revision: '7', keys: [{ key_id: 37, public_key: '31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550', not_before_ms: '0', not_after_ms: '18446744073709551615' }] });
  const configured = desktopConfig({ ...ohttpSecurity, MESSENGER_OHTTP_CONFIG: pins }, true);
  assert.equal(configured.ohttpFrame.split('\n').slice(0, 6).join('\n'), ['1', digest(configured.networkFrame), digest(configured.securityFrame), '7', 'required', '1'].join('\n'));
  assert.equal(JSON.parse(JSON.stringify(configured)).ohttpFrame, configured.ohttpFrame);
  assert.equal(desktopConfig({ ...ohttpSecurity, EXPO_PUBLIC_MESSENGER_OHTTP_CONFIG: pins }, true).ohttpFrame, off.ohttpFrame);
});

test('desktop configuration never silently omits malformed OHTTP or partial parents', () => {
  assert.throws(() => desktopConfig({}, true), /OHTTP/);
  for (const input of ['{', ' '.repeat(4097), JSON.stringify({ schema_version: 1, mode: 'fallback', revision: '1', keys: [] })]) {
    assert.throws(() => desktopConfig({ ...ohttpSecurity, MESSENGER_OHTTP_CONFIG: input }, true));
  }
});


test('desktop release uses the explicit floor envelope without changing its embedded feature pins', () => {
  const env = { ...ohttpSecurity, EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example' };
  const previous = desktopConfig(env);
  const next = desktopConfig({ ...env, MESSENGER_MINIMUM_SESSION_SUITE: '2' });
  assert.equal(next.securityFrame, `6\n2\n${previous.securityFrame}`);
  assert.equal(next.baseUrl, previous.baseUrl);
  assert.equal(next.edgeUrl, previous.edgeUrl);
  assert.notEqual(next.ohttpFrame, previous.ohttpFrame);
  assert.equal(next.ohttpFrame.split('\n')[2], suiteFloorHash('sha256').update(next.securityFrame).digest('hex'));
});
