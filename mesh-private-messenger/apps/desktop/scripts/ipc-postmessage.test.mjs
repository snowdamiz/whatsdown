import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const script = readFileSync(new URL('../src-tauri/src/ipc-postmessage.js', import.meta.url), 'utf8');
function bridge() {
  const messages = [];
  const window = { __TAURI_INTERNALS__: {}, ipc: { postMessage: (value) => messages.push(JSON.parse(value)) } };
  const blocked = () => { throw new Error('network API must not be used for IPC'); };
  const context = vm.createContext({ window, fetch: blocked, Headers: blocked, XMLHttpRequest: blocked,
    ArrayBuffer, Uint8Array, Map });
  vm.runInContext(script.replace('__INVOKE_KEY__', JSON.stringify('runtime-private-key')), context);
  return { messages, send: window.__TAURI_INTERNALS__.postMessage };
}

test('IPC works using postMessage with fetch/XHR unavailable and preserves binary views', () => {
  const { messages, send } = bridge();
  const backing = Uint8Array.of(99, 1, 2, 255, 88);
  send({ cmd: 'mesh_invoke', callback: 7, error: 9, payload: backing.subarray(1, 4),
    options: { headers: { 'X-Mesh-Symbol': 'mesh_messenger_load_profile' } } });
  assert.deepEqual(messages, [{ cmd: 'mesh_invoke', callback: 7, error: 9,
    payload: [1, 2, 255], options: { headers: { 'X-Mesh-Symbol': 'mesh_messenger_load_profile' }, customProtocolIpcBlocked: true },
    __TAURI_INVOKE_KEY__: 'runtime-private-key' }]);
  assert.ok(!send.toString().includes('runtime-private-key'));
});

test('IPC preserves channels, maps and response callback identities without protocol fetch', () => {
  const { messages, send } = bridge();
  const channel = { __TAURI_TO_IPC_KEY__: () => '__CHANNEL__:42' };
  send({ cmd: 'subscribe', callback: 3, error: 4,
    payload: { channel, map: new Map([['binary', Uint8Array.of(10, 11).buffer]]) },
    options: { customProtocolIpcBlocked: false } });
  assert.deepEqual(messages[0], { cmd: 'subscribe', callback: 3, error: 4,
    payload: { channel: '__CHANNEL__:42', map: { binary: [10, 11] } },
    options: { customProtocolIpcBlocked: true }, __TAURI_INVOKE_KEY__: 'runtime-private-key' });
  send({ cmd: 'plugin:__TAURI_CHANNEL__|fetch', callback: 30, error: 40, payload: { id: 9 } });
  assert.equal(messages[1].cmd, 'plugin:__TAURI_CHANNEL__|fetch');
  assert.equal(messages[1].callback, 30);
});
