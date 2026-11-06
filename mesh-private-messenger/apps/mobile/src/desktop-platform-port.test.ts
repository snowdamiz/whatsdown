import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopPlatformPort } from './desktop-platform-port.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { parseDesktopLockSnapshot } from './desktop-lock-protocol.ts';

const owner = '41414141-4242-4343-4444-454545454545', boot = '51515151-5252-5353-5454-555555555555';
const parsed = parseDesktopLockSnapshot({ version: 1, owner, revision: '1',
  state: { epoch: boot + '/1', policy: 'enabled', phase: 'activated', capability: 'available', foreground: true } });
const headers = { 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': boot + '/1' };
function fixture(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const calls: { command: string; body: unknown; options: unknown; snapshot: unknown }[] = [];
  const behavior: { invoke(command: string): Promise<unknown>; gate: Promise<void> } = {
    gate: Promise.resolve(), async invoke(command) {
      if (command === 'database_path') return '/owned/messages.db';
      if (command === 'app_lock_notification_binding') return 'enabled';
      if (command === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
      return null;
    },
  };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { __TAURI_INTERNALS__: {
    invoke(command: string, body: unknown, options: unknown) {
      calls.push({ command, body, options, snapshot: body instanceof Uint8Array ? body.slice() : structuredClone(body) });
      return behavior.invoke(command);
    },
  } } });
  const unused = async (): Promise<never> => { throw Error('unexpected_operation'); };
  const scope = createDesktopPrivateSession({ check: () => behavior.gate, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const port = createDesktopPlatformPort({ owner: parsed.owner, epoch: parsed.state.epoch, scope });
  t.after(() => { scope.dispose(); if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { behavior, calls, scope, port };
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

test('actual Tauri private platform calls carry captured authority and finite operation metadata', async t => {
  const f = fixture(t), profile = Uint8Array.of(1, 2);
  assert.equal(await f.port.databasePath(), '/owned/messages.db');
  await f.port.readLegacyPreference(profile, 'read-state');
  await f.port.removeLegacyPreference(profile, 'notification-preview');
  const beforeCleanup = f.calls.length;
  await f.port.forgetLegacyPreferences('a'.repeat(64));
  assert.equal(f.calls.length, beforeCleanup, 'erasure cleanup belongs to the captured native Core worker');
  await f.port.openNativeCreditPayment(profile);
  const notice = { version: 1, id: 'message', scope: 'chat/' + 'a'.repeat(32), title: 'Morse', body: 'New message', mention: false } satisfies Parameters<typeof f.port.publishMessageNotice>[0];
  await f.port.publishMessageNotice(notice);
  assert.deepEqual(await f.port.takeNotificationIntent(), { kind: 'none' });
  assert.equal(await f.port.notificationBinding('enable', profile), 'enabled');
  await f.port.windowAction('minimize');
  assert.deepEqual(f.calls.map(call => call.options), [
    { headers }, { headers: { ...headers, 'X-Morse-Legacy-Operation': 'read', 'X-Morse-Legacy-Kind': 'read-state' } },
    { headers: { ...headers, 'X-Morse-Legacy-Operation': 'remove', 'X-Morse-Legacy-Kind': 'notification-preview' } },
    { headers }, { headers }, { headers },
    { headers: { ...headers, 'X-Morse-Notification-Operation': 'enable' } }, { headers },
  ]);
  assert.deepEqual(f.calls[4]?.snapshot, notice);
  assert.deepEqual(f.calls[7]?.snapshot, { action: 'minimize' });
});

test('every private platform operation waits for native admission and stops after disposal', async t => {
  const f = fixture(t), gate = Promise.withResolvers<void>(); f.behavior.gate = gate.promise;
  const pending = f.port.databasePath(); await tick();
  assert.equal(f.calls.length, 0);
  gate.resolve(); assert.equal(await pending, '/owned/messages.db');
  f.scope.dispose(); f.calls.length = 0;
  const operations = [
    () => f.port.databasePath(), () => f.port.readLegacyPreference(Uint8Array.of(1), 'read-state'),
    () => f.port.removeLegacyPreference(Uint8Array.of(1), 'read-state'), () => f.port.forgetLegacyPreferences('a'.repeat(64)),
    () => f.port.openNativeCreditPayment(Uint8Array.of(1)), () => f.port.takeNotificationIntent(),
    () => f.port.publishMessageNotice({ version: 1, id: 'n', scope: 'chat/' + 'a'.repeat(32), title: 'Morse', body: 'New message', mention: false }),
    () => f.port.notificationBinding('status', Uint8Array.of(1)), () => f.port.windowAction('close'),
  ];
  for (const operation of operations) await assert.rejects(async () => operation(), /stale_epoch/);
  assert.equal(f.calls.length, 0);
});

test('late private results and errors cannot cross a disposed scope', async t => {
  const f = fixture(t);
  f.behavior.invoke = async () => { f.scope.dispose(); return '/private/account.db'; };
  await assert.rejects(f.port.databasePath(), { message: 'stale_epoch' });
});
test('a late native error is replaced by the public stale refusal', async t => {
  const f = fixture(t);
  f.behavior.invoke = async () => { f.scope.dispose(); throw Error('private account detail'); };
  await assert.rejects(f.port.databasePath(), { message: 'stale_epoch' });
});

test('raw private inputs are captured before async admission and wiped after completion without wiping caller input', async t => {
  const f = fixture(t), gate = Promise.withResolvers<void>(); f.behavior.gate = gate.promise;
  const input = Uint8Array.of(3, 7), pending = f.port.notificationBinding('enable', input);
  input[0] = 9; gate.resolve(); assert.equal(await pending, 'enabled');
  assert.deepEqual(input, Uint8Array.of(9, 7));
  assert.deepEqual(f.calls[0]?.snapshot, Uint8Array.of(3, 7));
  assert.deepEqual(f.calls[0]?.body, new Uint8Array(2));
});

test('malformed replies cannot become private values or successful mutations', async t => {
  const f = fixture(t);
  for (const reply of [undefined, {}, 1, true]) {
    f.behavior.invoke = async () => reply;
    await assert.rejects(f.port.databasePath(), /invalid_desktop_private_reply/);
    await assert.rejects(f.port.readLegacyPreference(Uint8Array.of(1), 'read-state'), /invalid_desktop_private_reply/);
    await assert.rejects(f.port.notificationBinding('status', Uint8Array.of(1)), /invalid_desktop_private_reply/);
    await assert.rejects(f.port.windowAction('close'), /invalid_desktop_private_reply/);
  }
  for (const reply of [{ version: 1, kind: 'scope', scope: 'chat/' + 'a'.repeat(32), extra: 1 }, { kind: 'inbox' },
    { version: 1, kind: 'scope', scope: 'file:///private' }]) {
    f.behavior.invoke = async () => reply;
    await assert.rejects(f.port.takeNotificationIntent(), /invalid_desktop_private_reply/);
  }
  f.behavior.invoke = async () => ({ kind: 'scope', scope: 'chat/' + 'a'.repeat(32), version: 1 });
  assert.deepEqual(await f.port.takeNotificationIntent(), { kind: 'scope', scope: 'chat/' + 'a'.repeat(32) });
});

test('legacy selectors refuse unknown kinds and noncanonical account identities without IPC', async t => {
  const f = fixture(t);
  await assert.rejects(f.port.readLegacyPreference(Uint8Array.of(1), '../../other'), /invalid_legacy_kind/);
  await assert.rejects(f.port.forgetLegacyPreferences('A'.repeat(64)), /invalid_account/);
  assert.equal(f.calls.length, 0);
});


test('notice metadata is captured before asynchronous admission', async t => {
  const f = fixture(t), gate = Promise.withResolvers<void>(); f.behavior.gate = gate.promise;
  const notice = { version: 1, id: 'n', scope: 'chat/' + 'a'.repeat(32), title: 'Morse', body: 'Original', mention: false } satisfies Parameters<typeof f.port.publishMessageNotice>[0];
  const pending = f.port.publishMessageNotice(notice);
  notice.body = 'Changed while waiting'; gate.resolve(); await pending;
  assert.deepEqual(f.calls[0]?.snapshot, { ...notice, body: 'Original' });
});
