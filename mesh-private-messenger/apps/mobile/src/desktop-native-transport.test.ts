import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopOwnerTransport } from './desktop-native-transport.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { bindDesktopOwner } from './desktop-owner-client.ts';
import { parseDesktopLockSnapshot } from './desktop-lock-protocol.ts';

const ownerA = '41414141-4242-4343-4444-454545454545';
const ownerB = '61616161-6262-6363-6464-656565656565';
const boot = '51515151-5252-5353-5454-555555555555';
function snapshot(owner = ownerA, generation = '1', phase = 'activated') {
  return parseDesktopLockSnapshot({ version: 1, owner, revision: generation,
    state: { epoch: `${boot}/${generation}`, phase, policy: 'enabled', capability: 'available', foreground: true } });
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function deferred<T>() {
  let resolve: (value: T) => void = () => { throw Error('resolver_not_initialized'); };
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function host(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const callbacks = new Map<number, (payload: unknown) => void>();
  const calls: { name: string; body: unknown; options: unknown }[] = [];
  const removed: { event: string; id: number }[] = [];
  let callbackSequence = 0;
  const behavior: { invoke(name: string, body: unknown): Promise<unknown> } = {
    async invoke(name) {
      if (name === 'plugin:event|listen') return 71;
      if (name === 'app_lock_bind' || name === 'app_lock_state') return snapshot();
      if (name === 'mesh_invoke' || name === 'wallet_invoke') return new Uint8Array([3, 7]).buffer;
      return null;
    },
  };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __MORSE_DOCUMENT__: '00000000-0000-4000-8000-000000000001', __TAURI_INTERNALS__: {
      transformCallback(callback: (payload: unknown) => void) { const id = ++callbackSequence; callbacks.set(id, callback); return id; },
      invoke(name: string, body: unknown, options: unknown) { calls.push({ name, body, options }); return behavior.invoke(name, body); },
    },
    __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener(event: string, id: number) { removed.push({ event, id }); } },
  } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { calls, removed, behavior, emit(payload: unknown) {
    for (const callback of callbacks.values()) callback({ event: 'app-lock-changed', id: 71, payload });
  } };
}

test('real Tauri invoke preserves raw binary bodies and exact owner/epoch plus operation headers', async t => {
  const h = host(t); const transport = createDesktopOwnerTransport(); const state = snapshot();
  const port = transport.privatePort(state.owner, state.state.epoch); const request = new Uint8Array([1, 2]);
  assert.deepEqual(await port.invoke('mesh_messenger_load_profile', request), new Uint8Array([3, 7]));
  assert.deepEqual(await port.invokeWallet(5, request), new Uint8Array([3, 7]));
  const authority = { 'X-Morse-Lock-Owner': ownerA, 'X-Morse-Lock-Epoch': `${boot}/1` };
  assert.deepEqual(h.calls, [
    { name: 'mesh_invoke', body: request, options: { headers: { ...authority, 'X-Mesh-Symbol': 'mesh_messenger_load_profile' } } },
    { name: 'wallet_invoke', body: request, options: { headers: { ...authority, 'X-Wallet-Operation': '5' } } },
  ]);
  assert.equal(h.calls[0]?.body, request);
});

test('a new private port cannot retarget an older port or its check and native clipboard authority', async t => {
  const h = host(t); const transport = createDesktopOwnerTransport();
  const a = snapshot(), b = snapshot(ownerB, '2');
  const old = transport.privatePort(a.owner, a.state.epoch);
  const next = transport.privatePort(b.owner, b.state.epoch);
  await next.check(); await old.check(); await old.copyProtectedText('owned clipboard text');
  assert.deepEqual(h.calls.map(c => [c.name, c.options]), [
    ['app_lock_check', { headers: { 'X-Morse-Lock-Owner': ownerB, 'X-Morse-Lock-Epoch': `${boot}/2` } }],
    ['app_lock_check', { headers: { 'X-Morse-Lock-Owner': ownerA, 'X-Morse-Lock-Epoch': `${boot}/1` } }],
    ['app_lock_copy_text', { headers: { 'X-Morse-Lock-Owner': ownerA, 'X-Morse-Lock-Epoch': `${boot}/1` } }],
  ]);
  assert.deepEqual(h.calls[2]?.body, { text: 'owned clipboard text' });
});

test('native replies reject malformed binary values and require explicit void null', async t => {
  const h = host(t); const state = snapshot(); const port = createDesktopOwnerTransport().privatePort(state.owner, state.state.epoch);
  for (const reply of [undefined, true, 'data', [-1, 2], { data: [1, 2] }, new Uint8Array([1, 2])]) {
    h.behavior.invoke = async () => reply;
    await assert.rejects(port.invoke('mesh_messenger_load_profile', new Uint8Array()), /invalid_desktop_private_reply/);
    await assert.rejects(port.check(), /invalid_desktop_private_reply/);
    await assert.rejects(port.copyProtectedText('text'), /invalid_desktop_private_reply/);
  }
  const before = h.calls.length;
  for (const operation of [-1, 1.5, NaN, Infinity, 4294967296]) {
    await assert.rejects(port.invokeWallet(operation, new Uint8Array()), /invalid_wallet_operation/);
  }
  assert.equal(h.calls.length, before);
});

test('real Tauri event API forwards only payloads and exposes asynchronous unlisten failure', async t => {
  const h = host(t); const received: unknown[] = [];
  const remove = await createDesktopOwnerTransport().listen(payload => { received.push(payload); });
  const state = snapshot(); h.emit(state); assert.deepEqual(received, [state]);
  assert.deepEqual(h.calls[0], { name: 'plugin:event|listen', body: {
    event: 'app-lock-changed', target: { kind: 'Any' }, handler: 1,
  }, options: undefined });
  h.behavior.invoke = async () => { throw Error('native_unlisten_refused'); };
  await assert.rejects(async () => { await remove(); }, /native_unlisten_refused/);
  assert.deepEqual(h.removed, [{ event: 'app-lock-changed', id: 71 }]);
});

test('owner/session composition through real Tauri API wipes late bytes after native epoch change', async t => {
  const h = host(t); const reply = deferred<unknown>();
  const standard = h.behavior.invoke;
  h.behavior.invoke = async (name, body) => name === 'mesh_invoke' ? reply.promise : standard(name, body);
  const controller = new AbortController();
  const client = await bindDesktopOwner(createDesktopOwnerTransport(), {
    signal: controller.signal, onSnapshot() {}, onRetired() {},
  });
  const session = await client.makeSession();
  const reading = session.invoke('mesh_messenger_load_profile', new Uint8Array());
  const refused = assert.rejects(reading, /stale_epoch/); await tick();
  assert.equal(h.calls.filter(c => c.name === 'mesh_invoke').length, 1);
  h.emit(snapshot(ownerA, '2', 'locked'));
  const bytes = new Uint8Array([9, 8, 7]); reply.resolve(bytes.buffer); await refused;
  assert.deepEqual(bytes, new Uint8Array(3));
  assert.equal(await client.close(), true);
  assert.deepEqual(h.removed, [{ event: 'app-lock-changed', id: 71 }]);
  assert.equal(h.calls.filter(c => c.name === 'app_lock_release').length, 1);
});

test('abort during actual event registration waits for unsubscribe and never dispatches native bind', async t => {
  const h = host(t); const listening = deferred<unknown>();
  h.behavior.invoke = async name => name === 'plugin:event|listen' ? listening.promise : null;
  const controller = new AbortController();
  const pending = bindDesktopOwner(createDesktopOwnerTransport(), { signal: controller.signal, onSnapshot() {}, onRetired() {} });
  const rejected = assert.rejects(pending, /desktop_owner_closed/);
  controller.abort(); listening.resolve(71); await rejected;
  assert.deepEqual(h.calls.map(c => c.name), ['plugin:event|listen', 'plugin:event|unlisten']);
});

// Tauri 2.11.5 macOS postMessage serializes Raw(Vec<u8>) as JSON arrays.
test('macOS postMessage byte arrays are accepted without retaining the serialized plaintext', async t => {
  const h = host(t), state = snapshot();
  const port = createDesktopOwnerTransport().privatePort(state.owner, state.state.epoch);
  for (const operation of ['mesh', 'wallet']) {
    const raw = [0, 128, 255]; h.behavior.invoke = async () => raw;
    const result = operation === 'mesh' ? await port.invoke('mesh_messenger_load_profile', new Uint8Array()) :
      await port.invokeWallet(5, new Uint8Array());
    assert.deepEqual(result, Uint8Array.of(0, 128, 255));
    assert.deepEqual(raw, [0, 0, 0]);
  }
});

test('late macOS byte arrays and their normalized private result are both wiped', async t => {
  const h = host(t), state = snapshot(), raw = [9, 8, 7];
  const port = createDesktopOwnerTransport().privatePort(state.owner, state.state.epoch);
  let normalized: Uint8Array | undefined;
  const scope = createDesktopPrivateSession({ ...port,
    async invoke(symbol, request) { normalized = await port.invoke(symbol, request); return normalized; },
  });
  t.after(() => { scope.dispose(); });
  h.behavior.invoke = async name => {
    if (name === 'mesh_invoke') { scope.dispose(); return raw; }
    return null;
  };
  await assert.rejects(scope.invoke('mesh_messenger_load_profile', new Uint8Array()), /stale_epoch/);
  assert.deepEqual(raw, [0, 0, 0]);
  assert.deepEqual(normalized, new Uint8Array(3));
});
