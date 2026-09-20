import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { createMailboxSync, type MailboxSocket } from './mailbox-sync.ts';

class Socket implements MailboxSocket {
  onmessage: MailboxSocket['onmessage'] = null;
  onerror: MailboxSocket['onerror'] = null;
  onclose: MailboxSocket['onclose'] = null;
  closed = false;
  close() { this.closed = true; }
  receive(data: string) { this.onmessage?.({ data } as MessageEvent); }
  disconnect() { this.onclose?.({} as CloseEvent); }
}

test('catches up after subscription and coalesces wakeups without polling the mailbox', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const socket = new Socket();
  const gate = Promise.withResolvers<void>();
  let syncs = 0;
  const client = createMailboxSync(async () => socket, async () => {
    syncs += 1;
    if (syncs === 1) await gate.promise;
  }, assert.ifError);
  t.after(() => client.dispose());

  client.setActive(true);
  await setImmediate();
  assert.equal(syncs, 0);
  socket.receive('ready');
  await setImmediate();
  assert.equal(syncs, 1);
  socket.receive('encrypted-wakeup');
  socket.receive('encrypted-wakeup');
  assert.equal(syncs, 1);
  gate.resolve();
  await setImmediate();
  assert.equal(syncs, 2);
  t.mock.timers.tick(60_000);
  await setImmediate();
  assert.equal(syncs, 2);
  socket.receive('encrypted-wakeup');
  await setImmediate();
  assert.equal(syncs, 3);
});

test('reconnects with catch-up, pauses in background, and ignores late connections', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(Math, 'random', () => 0);
  const sockets: Socket[] = [];
  const delayed = Promise.withResolvers<Socket>();
  let syncs = 0;
  const errors: unknown[] = [];
  const client = createMailboxSync(async () => {
    const socket = new Socket();
    sockets.push(socket);
    return sockets.length === 3 ? delayed.promise : socket;
  }, async () => { syncs += 1; }, (error) => errors.push(error));
  t.after(() => client.dispose());
  client.setActive(true);
  await setImmediate();
  sockets[0]!.receive('ready');
  await setImmediate();
  sockets[0]!.disconnect();
  t.mock.timers.tick(1_000);
  await setImmediate();
  assert.equal(sockets.length, 2);
  sockets[1]!.receive('ready');
  await setImmediate();
  assert.equal(syncs, 2);
  client.setActive(false);
  assert.equal(sockets[1]!.closed, true);
  sockets[1]!.receive('encrypted-wakeup');
  client.invalidate();
  t.mock.timers.tick(60_000);
  await setImmediate();
  assert.equal(syncs, 2);
  assert.equal(sockets.length, 2);
  client.setActive(true);
  await setImmediate();
  client.dispose();
  delayed.resolve(sockets[2]!);
  await setImmediate();
  assert.equal(sockets[2]!.closed, true);
  assert.equal(sockets[2]!.onmessage, null);
});

test('retries failed catch-up and times out a connection that never becomes ready', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(Math, 'random', () => 0);
  const sockets: Socket[] = [];
  const errors: unknown[] = [];
  let syncs = 0;
  const client = createMailboxSync(async () => {
    const socket = new Socket();
    sockets.push(socket);
    return socket;
  }, async () => {
    if (++syncs === 1) throw new Error('offline');
  }, (error) => errors.push(error));
  t.after(() => client.dispose());
  client.setActive(true);
  await setImmediate();
  sockets[0]!.receive('ready');
  await setImmediate();
  assert.match(String(errors.at(-1)), /offline/);
  t.mock.timers.tick(1_000);
  await setImmediate();
  assert.equal(sockets.length, 2);
  t.mock.timers.tick(10_000);
  await setImmediate();
  assert.equal(sockets[1]!.closed, true);
  t.mock.timers.tick(2_000);
  await setImmediate();
  sockets[2]!.receive('ready');
  await setImmediate();
  assert.equal(syncs, 2);
  assert.equal(errors.at(-1), null);
});
