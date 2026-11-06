import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { clientEnvironment } from './client-config.mjs';
import securityConfig from '../../apps/mobile/plugins/security-config.cjs';

const environment = {
  EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://directory.example',
  EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '22'.repeat(32),
  MESSENGER_ABUSE_DIFFICULTY: '8',
  MESSENGER_WITNESS_THRESHOLD: '2',
  MESSENGER_WITNESS_SET_JSON: JSON.stringify([
    { id: 'a', publicKey: '01'.repeat(32), operator: "Operator's $(echo injected)" },
    { id: 'b', publicKey: '02'.repeat(32), operator: 'Outside' },
    { id: 'c', publicKey: '03'.repeat(32), operator: 'Morse' },
  ]),
  MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: 'private-do-not-export',
  DATABASE_URL: 'postgres://user:secret@database',
};

test('client.env carries canonical native pins without copying secrets or executing labels', () => {
  const output = clientEnvironment(environment);
  assert.ok(!output.includes('private-do-not-export'));
  assert.ok(!output.includes('postgres://'));
  const restored = JSON.parse(execFileSync('/bin/sh', ['-c',
    `${output}\nexec "$NODE" -e 'process.stdout.write(JSON.stringify(process.env))'`],
  { env: { NODE: process.execPath }, encoding: 'utf8' }));
  assert.equal(restored.MESSENGER_SECURITY_CONFIG, securityConfig(environment));
  assert.equal(restored.MESSENGER_BASE_URL, 'https://directory.example');
  assert.equal(restored.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL, 'https://edge.example');
  assert.equal(securityConfig(restored), securityConfig(environment));
});

test('client.env refuses incomplete pins and non-production endpoints', () => {
  for (const updates of [
    { MESSENGER_WITNESS_THRESHOLD: '1' },
    { MESSENGER_WITNESS_SET_JSON: '' },
    { EXPO_PUBLIC_MESSENGER_BASE_URL: 'http://localhost:18086' },
    { EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://user:secret@directory.example' },
    { EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: undefined },
  ]) assert.throws(() => clientEnvironment({ ...environment, ...updates }));
  assert.throws(() => clientEnvironment({}));
});

test('client.env preserves RFC native selection and historical witness pins on export', () => {
  const config = { ...environment, MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
    MESSENGER_LEGACY_WITNESS_SET_JSON: environment.MESSENGER_WITNESS_SET_JSON,
    MESSENGER_LEGACY_WITNESS_THRESHOLD: '2' };
  const output = clientEnvironment(config);
  const restored = JSON.parse(execFileSync('/bin/sh', ['-c',
    `${output}\nexec "$NODE" -e 'process.stdout.write(JSON.stringify(process.env))'`],
  { env: { NODE: process.execPath }, encoding: 'utf8' }));
  assert.equal(restored.MESSENGER_TRANSPARENCY_LOG_VERSION, '2');
  assert.equal(restored.MESSENGER_LEGACY_WITNESS_SET_JSON, config.MESSENGER_LEGACY_WITNESS_SET_JSON);
  assert.equal(securityConfig(restored), securityConfig(config));
  assert.ok(restored.MESSENGER_SECURITY_CONFIG.startsWith('3\n'));
});

test('client.env preserves v4 anchor identities when rebuilding native resources', () => {
  const config = { ...environment, MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
    MESSENGER_LEGACY_WITNESS_SET_JSON: environment.MESSENGER_WITNESS_SET_JSON,
    MESSENGER_LEGACY_WITNESS_THRESHOLD: '2',
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: '1'.repeat(32), MESSENGER_ANCHOR_LOG_NAME: 'morse-main',
    MESSENGER_ANCHOR_RING_ADDRESS: '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
    MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://two.example', 'https://three.example']) };
  const output = clientEnvironment(config);
  const restored = JSON.parse(execFileSync('/bin/sh', ['-c',
    `${output}\nexec "$NODE" -e 'process.stdout.write(JSON.stringify(process.env))'`],
  { env: { NODE: process.execPath }, encoding: 'utf8' }));
  assert.equal(restored.MESSENGER_ANCHOR_PROGRAM_ADDRESS, config.MESSENGER_ANCHOR_PROGRAM_ADDRESS);
  assert.equal(restored.MESSENGER_ANCHOR_LOG_NAME, 'morse-main');
  assert.equal(securityConfig(restored), securityConfig(config));
  assert.ok(restored.MESSENGER_SECURITY_CONFIG.startsWith('4\n'));
});

test('public client export preserves relay pins when rebuilding native resources and excludes signer secrets', () => {
  const config = { ...environment, MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
    MESSENGER_LEGACY_WITNESS_SET_JSON: environment.MESSENGER_WITNESS_SET_JSON,
    MESSENGER_LEGACY_WITNESS_THRESHOLD: '2',
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: '1'.repeat(32), MESSENGER_ANCHOR_LOG_NAME: 'morse-main',
    MESSENGER_ANCHOR_RING_ADDRESS: '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
    MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://two.example', 'https://three.example']),
    MESSENGER_RELAY_URLS: JSON.stringify(['https://relay.example']),
    MESSENGER_SLASH_MINT_ADDRESS: 'cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN',
    MESSENGER_RELAY_WALLET: 'private-wallet-never-export' };
  const output = clientEnvironment(config);
  assert.ok(!output.includes('private-wallet-never-export'));
  const restored = JSON.parse(execFileSync('/bin/sh', ['-c',
    `${output}\nexec "$NODE" -e 'process.stdout.write(JSON.stringify(process.env))'`],
  { env: { NODE: process.execPath }, encoding: 'utf8' }));
  assert.equal(securityConfig(restored), securityConfig(config));
  assert.equal(restored.MESSENGER_RELAY_URLS, config.MESSENGER_RELAY_URLS);
  assert.equal(restored.MESSENGER_SLASH_MINT_ADDRESS, config.MESSENGER_SLASH_MINT_ADDRESS);
  assert.ok(restored.MESSENGER_SECURITY_CONFIG.startsWith('5\n'));
});


test('public client export preserves an explicit suite floor and exact canonical envelope on rebuild', () => {
  const config = { ...environment, MESSENGER_MINIMUM_SESSION_SUITE: '2' };
  const output = clientEnvironment(config);
  const restored = JSON.parse(execFileSync('/bin/sh', ['-c',
    `${output}\nexec "$NODE" -e 'process.stdout.write(JSON.stringify(process.env))'`],
  { env: { NODE: process.execPath }, encoding: 'utf8' }));
  assert.equal(restored.MESSENGER_MINIMUM_SESSION_SUITE, '2');
  assert.equal(restored.MESSENGER_SECURITY_CONFIG, `6\n2\n${securityConfig(environment)}`);
  assert.equal(securityConfig(restored), restored.MESSENGER_SECURITY_CONFIG);
  assert.ok(!output.includes('private-do-not-export'));
});
