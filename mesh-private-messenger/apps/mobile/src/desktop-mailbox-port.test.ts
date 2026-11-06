import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopMailboxPort } from './desktop-mailbox-port.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { parseDesktopLockSnapshot } from './desktop-lock-protocol.ts';
import { openNativeMailboxSocket } from './native-mailbox.ts';
import { utf8, vectors, writeU32 } from './codec.ts';
const owner = '41414141-4242-4343-4444-454545454545', boot = '51515151-5252-5353-5454-555555555555';
const state = parseDesktopLockSnapshot({ version: 1, owner, revision: '1', state: { epoch: boot + '/1', policy: 'enabled', phase: 'activated', capability: 'available', foreground: true } });
const headers = { 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': boot + '/1' };
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function fixture(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const ticket = new Uint8Array(32).fill(7);
  const calls: { name: string; body: unknown; options: unknown; copy: unknown }[] = [];
  const behavior = { gate: Promise.resolve(), async invoke(name: string): Promise<unknown> { return name === 'mesh_invoke' ? ticket.buffer : null; } };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { __TAURI_INTERNALS__: {
    invoke(name: string, body: unknown, options: unknown) {
      calls.push({ name, body, options, copy: body instanceof Uint8Array ? body.slice() : body }); return behavior.invoke(name);
    },
  } } });
  const unused = async (): Promise<never> => { throw Error('unexpected_operation'); };
  const scope = createDesktopPrivateSession({ check: () => behavior.gate, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const port = createDesktopMailboxPort({ owner: state.owner, epoch: state.state.epoch, scope });
  t.after(() => { scope.dispose(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { ticket, behavior, calls, scope, port };
}
test('returned native socket closes its original ticket after local scope disposal', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(t), socket = await openNativeMailboxSocket('/owned/messages.db', f.port);
  f.calls.length = 0; f.scope.dispose(); socket.close(); socket.close(); await tick();
  assert.equal(f.calls.length, 1);
  assert.deepEqual(f.calls[0]?.copy, new Uint8Array(32).fill(7));
  assert.equal(f.calls[0]?.name, 'app_lock_close_mailbox');
  assert.deepEqual(f.calls[0]?.options, { headers });
});
test('unreturned open ticket is retired before its owned bytes are wiped', async t => {
  const f = fixture(t);
  f.behavior.invoke = async name => { if (name === 'mesh_invoke') { f.scope.dispose(); return f.ticket.buffer; } return null; };
  await assert.rejects(f.port.open(utf8('/owned/messages.db')), /stale_epoch/);
  const closes = f.calls.filter(call => call.name === 'app_lock_close_mailbox');
  assert.equal(closes.length, 1); assert.deepEqual(closes[0]?.copy, new Uint8Array(32).fill(7));
  assert.deepEqual(closes[0]?.options, { headers }); assert.deepEqual(f.ticket, new Uint8Array(32));
});
test('open captures raw request before admission and wipes only its own input storage', async t => {
  const f = fixture(t), gate = Promise.withResolvers<void>(); f.behavior.gate = gate.promise;
  const request = utf8('/owned/db'), expected = request.slice(), pending = f.port.open(request);
  request.fill(9); await tick(); assert.equal(f.calls.length, 0); gate.resolve(); await pending;
  const call = f.calls.find(call => call.name === 'mesh_invoke');
  assert.deepEqual(call?.copy, expected); assert.deepEqual(call?.body, new Uint8Array(request.length));
  assert.deepEqual(request, new Uint8Array(request.length).fill(9));
});
test('finite cleanup rejects malformed request shapes without native IPC', async t => {
  const f = fixture(t); f.scope.dispose();
  for (const input of [new Uint8Array(), new Uint8Array([...writeU32(1), ...vectors(utf8('/db'))]),
    new Uint8Array([...writeU32(2), ...vectors(utf8('/db'), new Uint8Array(31))])]) {
    await assert.rejects(f.port.close(input));
  }
  assert.equal(f.calls.length, 0);
});
test('closed scope cannot start or poll a mailbox', async t => {
  const f = fixture(t); f.scope.dispose();
  await assert.rejects(f.port.open(utf8('/db')), /stale_epoch/);
  await assert.rejects(f.port.poll(new Uint8Array()), /stale_epoch/); assert.equal(f.calls.length, 0);
});
