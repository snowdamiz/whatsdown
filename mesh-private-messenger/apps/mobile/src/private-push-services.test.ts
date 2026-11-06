import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import { bindAppLockFunctions } from './app-lock.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import * as codec from './codec.ts';
import * as executor from './push-action-executor.ts';
import * as policy from './push-policy.ts';
import * as queue from './single-flight.ts';
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
const notification = (data: Record<string, unknown>) => ({ request: { trigger: { type: 'push' }, content: { body: null, data } } });
async function fixture() {
  let resolve: () => void = () => { throw Error('uninitialized'); };
  const gate = new Promise<void>(done => { resolve = done; });
  let checks = 0;
  const scope = createDesktopPrivateSession({ check: async () => { if (++checks === 1) await gate; }, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  let received: (event: unknown) => void = () => {};
  let response: (event: unknown) => void = () => {};
  let cleared = 0, nativeCalls = 0;
  const requests: Uint8Array[] = [];
  const context = vm.createContext({ Uint8Array, Error, Object, Promise, Set, Map, JSON, TextEncoder, TextDecoder });
  const nativeNames = ['clearPushToken','onPushRegistrationChanged','primePushToken','push_flow_complete_export','push_flow_begin_export','push_status_export','push_flow_send_export'];
  const imports: Record<string, Record<string, unknown>> = {
    './app-lock': { bindAppLockFunctions },
    '../modules/mesh-messenger': { isLegacyDesktopBridge: false, ...Object.fromEntries(nativeNames.map(name => [name, unused])) },
    'react-native': { Platform: { OS: 'web' } },
    'expo-notifications': {
      setNotificationHandler() {}, getLastNotificationResponse: () => null,
      clearLastNotificationResponseAsync: async () => { cleared++; },
      addNotificationReceivedListener: (listener: typeof received) => { received = listener; return { remove() {} }; },
      addNotificationResponseReceivedListener: (listener: typeof response) => { response = listener; return { remove() {} }; },
      registerTaskAsync: async () => {}, unregisterTaskAsync: async () => {},
    },
    './codec': codec, './i18n': { t: (value: string) => value }, './push-action-executor': executor, './push-policy': policy, './single-flight': queue,
  };
  const source = readFileSync(new URL('./push.ts', import.meta.url), 'utf8');
  const module = new vm.SourceTextModule(stripTypeScriptTypes(source), { context });
  await module.link(name => { const values = imports[name]; assert.ok(values, name);
    return new vm.SyntheticModule(Object.keys(values), function() { for (const [key, value] of Object.entries(values)) this.setExport(key, value); }, { context }); });
  await module.evaluate();
  const create: typeof import('./push.ts').createPushServices = Reflect.get(module.namespace, 'createPushServices');
  const service = create({ ...scope, appLockEnabled: false,
    clearPushToken: unused, primePushToken: unused, push_flow_complete_export: unused, push_flow_send_export: unused,
    onPushRegistrationChanged: () => () => {}, onInboxOpen: () => () => {}, onNotificationOpen: () => () => {},
    async push_status_export() { nativeCalls++; return codec.utf8('disabled'); },
    async push_flow_begin_export(request: Uint8Array) {
      nativeCalls++; requests.push(request); const frame = new Uint8Array(19);
      frame.set([2, 80, 70, 65]); new DataView(frame.buffer).setUint32(14, 1); frame[18] = 1; return frame;
    },
  });
  return { scope, service, resolve, received: () => received(notification({ kind: 'encrypted-wakeup' })),
    response: () => response({ notification: notification({ kind: 'message', scope: 'chat/' + 'a'.repeat(32) }) }),
    counts: () => ({ cleared, nativeCalls }), requests };
}
test('push status waits for asynchronous native admission', async () => {
  const f = await fixture(); const pending = f.service.getPushStatus('/captured/db');
  await tick(); const early = f.counts().nativeCalls; f.resolve(); assert.equal(await pending, 'disabled');
  f.scope.dispose(); assert.equal(early, 0); assert.equal(f.counts().nativeCalls, 1);
});
test('generic wakeup cannot publish before native admission or after unsubscribe during admission', async () => {
  const f = await fixture(); let wakes = 0;
  const close = f.service.listenForGenericWakeups(() => { wakes++; });
  f.received(); await tick(); const early = wakes; close(); f.resolve(); await tick(); f.received(); await tick();
  f.scope.dispose(); assert.equal(early, 0); assert.equal(wakes, 0);
});
test('desktop private notification open and cached-response cleanup stop on unsubscribe during admission', async () => {
  const f = await fixture(); const opened: string[] = [];
  const close = f.service.listenForNotificationOpens(value => opened.push(value));
  f.response(); await tick(); const early = opened.length; close(); f.resolve(); await tick();
  f.scope.dispose(); assert.equal(early, 0); assert.deepEqual(opened, []); assert.equal(f.counts().cleared, 0);
});
test('push intent captures its rendered profile before asynchronous admission', async () => {
  const f = await fixture(); const profile = Uint8Array.of(3, 4);
  const pending = f.service.enablePushBinding('/captured/db', profile); profile.fill(99);
  f.resolve(); assert.equal(await pending, 'enabled'); f.scope.dispose();
  assert.deepEqual(f.requests, [codec.vectors(codec.utf8('/captured/db'), Uint8Array.of(3, 4), Uint8Array.of(1))]);
});
