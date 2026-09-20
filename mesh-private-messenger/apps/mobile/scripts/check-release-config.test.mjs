import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPair, generateSelfSignedCodeSigningCertificate, convertCertificateToCertificatePEM } from '@expo/code-signing-certificates';

test('C8 release configuration requires signed updates, valid pins and secure service URLs', t => {
  const dir = mkdtempSync(join(tmpdir(), 'morse-ota-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const certificate = join(dir, 'certificate.pem');
  writeFileSync(certificate, convertCertificateToCertificatePEM(generateSelfSignedCodeSigningCertificate({
    keyPair: generateKeyPair(), commonName: 'Disposable Morse test certificate',
    validityNotBefore: new Date(Date.now() - 60_000), validityNotAfter: new Date(Date.now() + 86_400_000),
  })));
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(EXPO_|MESSENGER_)/.test(name))),
    EXPO_PROJECT_ID: '11111111-2222-3333-4444-555555555555',
    EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://messenger.example.com',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example.com',
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: '22'.repeat(32),
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '33'.repeat(32),
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '44'.repeat(32),
    MESSENGER_ABUSE_DIFFICULTY: '16',
    MORSE_OTA_CERTIFICATE: certificate,
  };
  const check = (overrides = {}) => spawnSync(process.execPath, ['scripts/check-release-config.mjs'], {
    cwd: new URL('..', import.meta.url), env: { ...env, ...overrides }, encoding: 'utf8',
  });
  const valid = check();
  assert.equal(valid.status, 0, valid.stderr);
  for (const overrides of [
    { MORSE_OTA_CERTIFICATE: '' },
    { MORSE_OTA_CERTIFICATE: join(dir, 'missing.pem') },
    { EXPO_PROJECT_ID: '' },
    { EXPO_PUBLIC_MESSENGER_BASE_URL: 'http://localhost:18086' },
    { EXPO_PUBLIC_MESSENGER_STREAM_URL: 'ws://messenger.example.com/stream' },
    { EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'http://objects.example.com' },
    { EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: '0' },
    { EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: '25' },
    { EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: '016' },
    { MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '' },
    { MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: env.MESSENGER_WITNESS_A_PUBLIC_KEY_HEX },
    { MESSENGER_EXPO_PROJECT_ID: env.EXPO_PROJECT_ID },
  ]) {
    assert.notEqual(check(overrides).status, 0, JSON.stringify(overrides));
  }
});
