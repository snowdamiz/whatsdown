import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { openNativeMailboxSocket } from './native-mailbox.ts';
import { utf8 } from './codec.ts';

test('native mailbox exposes only ticket-bound events and closes exactly once', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const calls: Uint8Array[] = [];
  const responses = ['ready', 'encrypted-wakeup', ''];
  let closes = 0;
  const socket = await openNativeMailboxSocket('/native/morse.db', {
    open: async (input) => { assert.deepEqual(input, utf8('/native/morse.db')); return new Uint8Array(32).fill(7); },
    poll: async (input) => { calls.push(input); return utf8(responses.shift() ?? ''); },
    close: async (input) => { assert.deepEqual(input, calls[0]); closes++; return new Uint8Array(); },
  });
  const events: string[] = [];
  socket.onmessage = ({ data }) => events.push(data);
  t.mock.timers.tick(0); await setImmediate();
  t.mock.timers.tick(0); await setImmediate();
  assert.deepEqual(events, ['ready', 'encrypted-wakeup']);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], calls[1]);
  socket.close(); socket.close();
  t.mock.timers.tick(1000); await setImmediate();
  assert.equal(calls.length, 2);
  assert.equal(closes, 1);
});

test('unknown native events fail closed and late polls cannot wake a closed session', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let closes = 0;
  let errors = 0;
  const socket = await openNativeMailboxSocket('/native/morse.db', {
    open: async () => new Uint8Array(32).fill(3),
    poll: async () => utf8('arbitrary native payload'),
    close: async () => { closes++; return new Uint8Array(); },
  });
  socket.onerror = () => { errors++; };
  socket.onmessage = () => assert.fail('unknown event reached application');
  t.mock.timers.tick(0); await setImmediate();
  assert.equal(errors, 1); assert.equal(closes, 1);
  const late = Promise.withResolvers<Uint8Array>();
  const second = await openNativeMailboxSocket('/native/morse.db', {
    open: async () => new Uint8Array(32).fill(4), poll: () => late.promise,
    close: async () => { closes++; return new Uint8Array(); },
  });
  second.onmessage = () => assert.fail('late wakeup escaped close');
  t.mock.timers.tick(0); await setImmediate();
  second.close(); late.resolve(utf8('ready')); await setImmediate();
  assert.equal(closes, 2);
});

test('malformed native tickets never become an application socket', async () => {
  await assert.rejects(() => openNativeMailboxSocket('/native/morse.db', {
    open: async () => new Uint8Array(31), poll: async () => assert.fail(), close: async () => assert.fail(),
  }), /invalid_mailbox_stream_ticket/);
});
