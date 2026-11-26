import assert from 'node:assert/strict';
import test from 'node:test';
import { desktopConfig, checkMacSigning, windowsSigningConfig } from './config.mjs';

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
    // Stateless requests go through the edge as OHTTP (protocol/ohttp-v1.md).
    MESSENGER_OHTTP_KEY: `1:${'31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155'}`,
    MESSENGER_OHTTP_RELAY: 'https://edge.example.com',
  };
  assert.equal(desktopConfig(env).streamUrl, 'wss://messenger.example.com/v1/mailbox/stream');
  assert.match(desktopConfig(env).securityFrame, /^2\n1{64}\n4{64}\n16\n2\n2\nwitness-a 2{64} Morse\n/);
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
    { MESSENGER_OHTTP_KEY: undefined, MESSENGER_OHTTP_RELAY: undefined },
    { MESSENGER_OHTTP_RELAY: 'https://other.example.com' },
  ]) assert.throws(() => desktopConfig({ ...env, ...changes }));
  assert.throws(() => desktopConfig({}));
  assert.equal(desktopConfig({}, true).baseUrl, 'http://127.0.0.1:18086');
  assert.equal(desktopConfig({}, true).streamUrl, 'ws://127.0.0.1:18090/v1/mailbox/stream');
  assert.equal(desktopConfig({}, true).objectUrl, 'http://127.0.0.1:18089');
});
