import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { takeDesktopBytes } from './desktop-binary-reply.ts';
import { invokeMesh, invokeWallet } from './desktop.ts';

test('binary replies retain ArrayBuffer storage and transfer JSON array storage', () => {
  const raw = Uint8Array.of(0, 128, 255).buffer;
  const result = takeDesktopBytes(raw, 3, 'invalid_reply');
  assert.equal(result.buffer, raw);
  const array = [0, 128, 255];
  assert.deepEqual(takeDesktopBytes(array, 3, 'invalid_reply'), Uint8Array.of(0, 128, 255));
  assert.deepEqual(array, [0, 0, 0]);
  assert.deepEqual(takeDesktopBytes([], 3, 'invalid_reply'), new Uint8Array());
});

test('invalid or oversized owned byte containers are wiped without coercion', () => {
  for (const raw of [[-1, 2], [256, 2], [1.5, 2], [NaN, 2], [Infinity, 2], ['1', 2], [true, 2], [null, 2], [undefined, 2], new Array(2), [1, 2, 3, 4]]) {
    assert.throws(() => takeDesktopBytes(raw, 3, 'invalid_reply'), { message: 'invalid_reply' });
    assert.deepEqual(raw, new Array(raw.length).fill(0));
  }
  const buffer = Uint8Array.of(1, 2, 3, 4).buffer;
  assert.throws(() => takeDesktopBytes(buffer, 3, 'invalid_reply'), { message: 'invalid_reply' });
  assert.deepEqual(new Uint8Array(buffer), new Uint8Array(4));
  for (const raw of [undefined, null, true, '1', { data: [1] }, Uint8Array.of(1)]) {
    assert.throws(() => takeDesktopBytes(raw, 3, 'invalid_reply'), { message: 'invalid_reply' });
  }
});

function host(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const behavior: { invoke(): Promise<unknown> } = { async invoke() { return null; } };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { __TAURI_INTERNALS__: behavior } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return behavior;
}

test('existing desktop app transports accept and erase macOS JSON byte replies', async t => {
  const h = host(t);
  for (const operation of [() => invokeMesh('mesh_messenger_load_profile', new Uint8Array()), () => invokeWallet(5, new Uint8Array())]) {
    const raw = [0, 128, 255]; h.invoke = async () => raw;
    assert.deepEqual(await operation(), Uint8Array.of(0, 128, 255));
    assert.deepEqual(raw, [0, 0, 0]);
    for (const malformed of [[-1], [1.5], ['2']]) {
      h.invoke = async () => malformed;
      await assert.rejects(operation(), /invalid_desktop_private_reply/);
      assert.deepEqual(malformed, [0]);
    }
  }
});
