import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { bindDesktopSessionEvents } from './desktop-session-events.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function fixture(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const callbacks: ((event: { event: string; id: number; payload: unknown }) => void)[] = [];
  const calls: { name: string; body: unknown }[] = [];
  const registrations: Promise<number>[] = [];
  const behavior = { async remove(): Promise<void> {} };
  let nextId = 1;
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __TAURI_INTERNALS__: {
      transformCallback(callback: (event: { event: string; id: number; payload: unknown }) => void) { callbacks.push(callback); return callbacks.length; },
      async invoke(name: string, body: unknown) { calls.push({ name, body }); return name === 'plugin:event|listen' ? registrations.shift() ?? nextId++ : behavior.remove(); },
    },
    __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener() {} },
  } });
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ async check() {}, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  t.after(() => { scope.dispose(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { callbacks, calls, registrations, behavior, scope, emit(payload: unknown) { for (const callback of callbacks) callback({ event: 'native', id: 1, payload }); } };
}
test('captured native subscriptions wait for readiness and await real asynchronous unlisten', async t => {
  const f = fixture(t), registration = Promise.withResolvers<number>(), removal = Promise.withResolvers<void>();
  const received: unknown[] = []; f.registrations.push(registration.promise);
  let ready = false;
  const pending = bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-notice-pending', receive: payload => { received.push(payload); } }] }).then(value => { ready = true; return value; });
  await tick(); assert.equal(ready, false); registration.resolve(42); const binding = await pending;
  f.emit({ version: 1 }); assert.deepEqual(received, [{ version: 1 }]);
  f.behavior.remove = () => removal.promise;
  let closed = false; const closing = binding.close().then(result => { closed = true; return result; });
  await tick(); assert.equal(closed, false); removal.resolve(); assert.equal(await closing, true);
  assert.deepEqual(f.calls.at(-1), { name: 'plugin:event|unlisten', body: { event: 'app-lock-notice-pending', eventId: 42 } });
});
test('disposal during native registration retires its late listener before refusing setup', async t => {
  const f = fixture(t), registration = Promise.withResolvers<number>(); f.registrations.push(registration.promise);
  let received = 0; const pending = bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-files', receive() { received++; } }] });
  f.scope.dispose(); registration.resolve(42);
  const outcome = await pending.then(() => 'published', error => error instanceof Error ? error.message : 'other');
  f.emit({ version: 1 }); await tick();
  assert.equal(outcome, 'stale_epoch'); assert.equal(received, 0);
  assert.equal(f.calls.filter(call => call.name === 'plugin:event|unlisten').length, 1);
});
test('partial setup failure drains a second late registration', async t => {
  const f = fixture(t), late = Promise.withResolvers<number>();
  f.registrations.push(Promise.reject(Error('registration_refused')), late.promise);
  const pending = bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-notice-pending', receive() {} }, { name: 'app-lock-files', receive() {} }] });
  const outcome = pending.then(() => 'published', error => error instanceof Error ? error.message : 'other');
  await tick(); late.resolve(43); assert.equal(await outcome, 'registration_refused'); await tick();
  assert.deepEqual(f.calls.filter(call => call.name === 'plugin:event|unlisten'), [{ name: 'plugin:event|unlisten', body: { event: 'app-lock-files', eventId: 43 } }]);
});
test('scope disposal stops delivery immediately and performs each removal once', async t => {
  const f = fixture(t), remove = Promise.withResolvers<void>(); let received = 0;
  const binding = await bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-files', receive() { received++; } }] });
  f.behavior.remove = () => remove.promise; f.scope.dispose(); f.emit({ version: 1 });
  remove.resolve(); assert.equal(await binding.close(), true); assert.equal(await binding.close(), true);
  assert.equal(received, 0); assert.equal(f.calls.filter(call => call.name === 'plugin:event|unlisten').length, 1);
});
test('native removal failures remain visible as cleanup failure while delivery stays closed', async t => {
  const f = fixture(t); let received = 0;
  const binding = await bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-files', receive() { received++; } }] });
  f.behavior.remove = async () => { throw Error('remove_refused'); };
  const result = await binding.close().catch(() => 'threw'); f.emit({ version: 1 });
  assert.equal(result, false); assert.equal(received, 0);
});
test('already disposed scopes install no native listener', async t => {
  const f = fixture(t); f.scope.dispose();
  await assert.rejects(bindDesktopSessionEvents({ scope: f.scope, events: [{ name: 'app-lock-files', receive() {} }] }), /stale_epoch/);
  assert.equal(f.calls.length, 0);
});

test('a pending registration retains the original callback', async t => {
  const f = fixture(t), registration = Promise.withResolvers<number>(); f.registrations.push(registration.promise);
  let original = 0, replacement = 0;
  const event = { name: 'app-lock-files', receive() { original++; } } satisfies Parameters<typeof bindDesktopSessionEvents>[0]['events'][number];
  const pending = bindDesktopSessionEvents({ scope: f.scope, events: [event] });
  event.receive = () => { replacement++; };
  registration.resolve(44); const binding = await pending; f.emit({ version: 1 });
  await binding.close(); assert.equal(original, 1); assert.equal(replacement, 0);
});
