import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const networkConfig = require('../plugins/network-config.cjs');
const environment = {
  EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
  EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
  EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'https://objects.example',
  EXPO_PUBLIC_MESSENGER_STREAM_URL: 'wss://stream.example/v1/mailbox/stream',
};

test('native transport configuration is absent by default and deterministic when pinned', () => {
  assert.equal(networkConfig({}), undefined);
  assert.equal(networkConfig(environment), '2\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16');
  assert.equal(networkConfig({ EXPO_PUBLIC_MESSENGER_BASE_URL: environment.EXPO_PUBLIC_MESSENGER_BASE_URL,
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: environment.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL }),
    '2\n0\nhttps://core.example\nhttps://edge.example\nhttps://core.example\nwss://core.example/v1/mailbox/stream\n16');
  assert.throws(() => networkConfig({ EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example' }), /edge/i);
});

test('native transport configuration refuses credential, URL normalization and cleartext ambiguity', () => {
  for (const value of ['https://user@core.example', 'https://core.example/', 'https://CORE.example',
    'https://core.example:443', 'https://core.example?secret=1', 'https://core.example#x',
    'https://core.example\\bad', 'http://127.0.0.1:18086', 'https://core.example\n']) {
    assert.throws(() => networkConfig({ ...environment, EXPO_PUBLIC_MESSENGER_BASE_URL: value }), value);
  }
  for (const value of ['wss://stream.example/wrong', 'wss://user@stream.example/v1/mailbox/stream',
    'wss://stream.example/v1/mailbox/stream?auth=x', 'wss://stream.example:443/v1/mailbox/stream']) {
    assert.throws(() => networkConfig({ ...environment, EXPO_PUBLIC_MESSENGER_STREAM_URL: value }), value);
  }
});

test('development cleartext is restricted to canonical loopback origins', () => {
  assert.equal(networkConfig({}, { development: true }),
    '2\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream\n16');
  for (const host of ['10.0.0.2', '192.168.1.2', '127.0.0.2', 'localhost.attacker.example']) {
    assert.throws(() => networkConfig({ ...environment, EXPO_PUBLIC_MESSENGER_BASE_URL: `http://${host}:18086` }, { development: true }));
  }
});


test('native object work difficulty is canonical, bounded and immutable build configuration', () => {
  for (const difficulty of ['1', '16', '24']) {
    assert.equal(networkConfig({ ...environment, EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: difficulty }).split('\n').at(-1), difficulty);
  }
  for (const difficulty of ['', '0', '25', '01', '1.0', '1e1', '-1', ' 16', '16\n']) {
    assert.throws(() => networkConfig({ ...environment, EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: difficulty }), /difficulty/i);
  }
});
