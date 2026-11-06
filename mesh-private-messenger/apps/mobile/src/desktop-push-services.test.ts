import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopPushServices } from './desktop-push-services.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import type { DesktopNotificationIntent } from './desktop-platform-port.ts';
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const target = 'chat/' + 'a'.repeat(32);
function fixture(t: TestContext) {
  const calls: { operation: string; profile: Uint8Array }[] = [], loads: Uint8Array[] = [];
  const state = {
    async check(): Promise<void> {},
    async take(): Promise<DesktopNotificationIntent> { return { kind: 'none' }; },
    async bind(_operation: 'status' | 'enable' | 'disable', _profile: Uint8Array): Promise<'enabled' | 'disabled'> { return 'enabled'; },
    profile: Uint8Array.of(1, 2, 3), takes: 0,
  };
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ check: () => state.check(), invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const manager = createDesktopPushServices({ databasePath: '/captured/db', scope,
    loadProfile: async request => { loads.push(request); return state.profile; },
    port: { async notificationBinding(operation, profile) { calls.push({ operation, profile }); return state.bind(operation, profile); },
      async takeNotificationIntent() { state.takes++; return state.take(); } },
  });
  const opened: string[] = []; let inboxes = 0;
  const listen = () => manager.services.listenForNotificationOpens(value => opened.push(value), () => { inboxes++; });
  t.after(async () => { scope.dispose(); await manager.close(); });
  return { state, scope, manager, calls, loads, opened, listen, inboxes: () => inboxes };
}
test('native notification intents stay pending until a UI listener exists', async t => {
  const f = fixture(t); f.state.take = async () => ({ kind: 'scope', scope: target });
  f.manager.receive({ version: 1 }); await tick(); assert.equal(f.state.takes, 0);
  f.listen(); await tick(); assert.deepEqual(f.opened, [target]);
  f.state.take = async () => ({ kind: 'inbox' }); f.manager.receive({ version: 1 }); await tick(); assert.equal(f.inboxes(), 1);
});
test('only the exact public pending hint triggers a private native pull', async t => {
  const f = fixture(t); f.listen(); await tick(); assert.equal(f.state.takes, 1);
  for (const payload of [null, {}, { version: 2 }, { version: 1, scope: target }, { version: 1, kind: 'inbox' }]) f.manager.receive(payload);
  await tick(); assert.equal(f.state.takes, 1);
  f.manager.receive({ version: 1 }); await tick(); assert.equal(f.state.takes, 2);
});
test('a late intent belongs to the original listener and never replays into its replacement', async t => {
  const f = fixture(t), first = Promise.withResolvers<DesktopNotificationIntent>();
  f.state.take = () => f.state.takes === 1 ? first.promise : Promise.resolve({ kind: 'none' });
  const stop = f.listen(); await tick(); stop(); f.listen(); await tick();
  first.resolve({ kind: 'scope', scope: target }); await tick();
  assert.deepEqual(f.opened, []); assert.equal(f.state.takes, 2);
});
test('session disposal suppresses a private intent already in flight and close drains it', async t => {
  const f = fixture(t), pending = Promise.withResolvers<DesktopNotificationIntent>(); f.state.take = () => pending.promise;
  f.listen(); await tick(); f.scope.dispose(); let closed = false;
  const closing = f.manager.close().then(value => { closed = true; return value; });
  await tick(); assert.equal(closed, false); pending.resolve({ kind: 'scope', scope: target });
  assert.equal(await closing, true); assert.deepEqual(f.opened, []); assert.throws(f.listen, /stale_epoch/);
});
test('push binding refuses another database before accessing native profile or permission state', async t => {
  const f = fixture(t);
  await assert.rejects(f.manager.services.getPushStatus('/other/db'), /account_state_changed/);
  assert.equal(f.calls.length, 0); assert.equal(f.loads.length, 0);
});
test('binding captures profile bytes before admission and wipes only its owned copy', async t => {
  const f = fixture(t), admission = Promise.withResolvers<void>(); f.state.check = () => admission.promise;
  const profile = Uint8Array.of(7, 8, 9), seen: number[][] = [];
  f.state.bind = async (_operation, bytes) => { seen.push([...bytes]); return 'enabled'; };
  const pending = f.manager.services.enablePushBinding('/captured/db', profile);
  profile.fill(6); admission.resolve(); assert.equal(await pending, 'enabled');
  assert.deepEqual(seen, [[7, 8, 9]]); assert.deepEqual(profile, Uint8Array.of(6, 6, 6));
  assert.deepEqual(f.calls[0]?.profile, new Uint8Array(3));
});
test('status without a profile loads through the captured binding and erases the returned bytes', async t => {
  const f = fixture(t); assert.equal(await f.manager.services.getPushStatus('/captured/db'), 'enabled');
  assert.equal(new TextDecoder().decode(f.loads[0]), '/captured/db');
  assert.deepEqual(f.state.profile, new Uint8Array(3));
});
test('late binding completion refuses publication and does not notify retired listeners', async t => {
  const f = fixture(t); let changed = 0;
  f.manager.services.listenForPushRegistrationChanges(() => { changed++; });
  f.state.bind = async () => { f.scope.dispose(); return 'enabled'; };
  await assert.rejects(f.manager.services.enablePushBinding('/captured/db', Uint8Array.of(1)), /stale_epoch/);
  assert.equal(changed, 0); assert.deepEqual(f.calls[0]?.profile, new Uint8Array(1));
});
test('notification preference changes notify only current registration listeners', async t => {
  const f = fixture(t); let changed = 0;
  const stop = f.manager.services.listenForPushRegistrationChanges(() => { changed++; });
  await f.manager.services.enablePushBinding('/captured/db', Uint8Array.of(1)); assert.equal(changed, 1);
  stop(); await f.manager.services.disablePushBinding('/captured/db', Uint8Array.of(1)); assert.equal(changed, 1);
});
