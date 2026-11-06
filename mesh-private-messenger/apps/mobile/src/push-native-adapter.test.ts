import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { utf8, vectors } from './codec.ts';

type NativeCall = (bytes: Uint8Array) => Promise<Uint8Array>;
const calls: { symbol: string; bytes?: Uint8Array }[] = [];
const native = new Map<string, NativeCall>();
const host = {
  invoke: async (symbol: string, bytes?: Uint8Array) => {
    calls.push({ symbol, bytes });
    const handler = native.get(symbol);
    if (handler) return handler(bytes!);
    if (symbol === 'requestPermissionsAsync') return { granted: true };
    if (['primePushToken', 'clearPushToken', 'registerTaskAsync', 'unregisterTaskAsync', 'setNotificationHandler'].includes(symbol)) return;
    throw Error(`Unexpected push host call: ${symbol}`);
  },
};
(globalThis as typeof globalThis & { __pushAdapter: typeof host }).__pushAdapter = host;
const moduleSource = (names: string[]) => names.map(name =>
  `export const ${name} = (input) => globalThis.__pushAdapter.invoke('${name}',input);`).join('\n');
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (!context.parentURL?.endsWith('/src/push.ts') && !context.parentURL?.endsWith('/src/push-native-adapter.test.ts')) return nextResolve(specifier, context);
    let source: string | undefined;
    if (specifier === '../modules/mesh-messenger') source = 'export const isLegacyDesktopBridge=false;' + moduleSource([
      'primePushToken', 'clearPushToken', 'onPushRegistrationChanged', 'push_flow_intent_export', 'push_flow_begin_export',
      'push_flow_complete_export', 'push_flow_send_export', 'push_status_export',
    ]);
    else if (specifier === 'expo-notifications') source = moduleSource([
      'setNotificationHandler', 'requestPermissionsAsync', 'registerTaskAsync', 'unregisterTaskAsync',
    ]);
    else if (specifier === 'react-native') source = 'export const Platform = {OS:"ios"};';
    else if (specifier === './i18n') source = 'export const t = value => value;';
    else if (['./codec', './push-action-executor', './push-policy', './single-flight'].includes(specifier)) {
      return nextResolve(`${specifier}.ts`, context);
    }
    if (source !== undefined) return { shortCircuit: true, url: `data:text/javascript,${encodeURIComponent(source)}` };
    return nextResolve(specifier, context);
  },
});
const pushModule = await import('./push.ts');
const { scope } = scopeFixture({
  primePushTokenScoped: request => host.invoke('primePushToken', request),
  clearPushTokenScoped: request => host.invoke('clearPushToken', request),
});
const push = { ...pushModule, ...pushModule.createPushServices({ ...await import('../modules/mesh-messenger'), ...scope, appLockEnabled: false }) };
function frame(kind: number, epoch: number, status = 0): Uint8Array {
  const value = new Uint8Array(kind ? 50 : 19);
  value.set([2, 80, 70, 65, kind, 0]);
  const view = new DataView(value.buffer);
  view.setBigUint64(6, BigInt(epoch)); view.setUint32(14, kind ? 32 : 1);
  if (kind) value.fill(epoch,18); else value[18] = status;
  return value;
}

test('mobile push adapter sends only opaque tickets to native transport and retries unknown sends', async t => {
  const database = '/native/push-adapter.db';
  const profile = Uint8Array.of(10,20,30);
  const permission = frame(1,1), prime = frame(2,2), bind = frame(3,3), done = frame(0,4,1);
  let pending = permission;
  let failed = false;
  calls.length = 0;
  native.set('push_flow_begin_export', async input => {
    assert.deepEqual(input,vectors(utf8(database),profile,Uint8Array.of(failed ? 0 : 1)));
    return pending;
  });
  native.set('push_flow_complete_export', async input => {
    assert.deepEqual(input,vectors(utf8(database),pending,Uint8Array.of(0)));
    assert.ok(pending === permission || pending === prime, 'UI must never acknowledge a network action');
    pending = pending === permission ? prime : bind;
    return pending;
  });
  native.set('push_flow_send_export', async input => {
    assert.deepEqual(input,vectors(utf8(database),bind));
    if (!failed) { failed = true; throw Error('push_transport_unavailable'); }
    pending = done; return done;
  });
  t.mock.method(globalThis,'fetch',async()=>assert.fail('push HTTP belongs to Mesh'));
  await assert.rejects(push.enablePushBinding(database,profile),/push_transport_unavailable/);
  assert.equal(await push.recoverPushBinding(database,profile),'enabled');
  assert.deepEqual(calls.filter(call=>call.symbol==='primePushToken').map(call=>call.bytes),[vectors(utf8(database),prime)]);
  assert.equal(calls.filter(call=>call.symbol==='push_flow_complete_export').length,2);
  assert.equal(calls.filter(call=>call.symbol==='push_flow_send_export').length,2);
  native.clear();
});


test('queued intent owns a copy of its rendered profile and platform clear owns its ticket', async () => {
  calls.length=0; native.clear();
  const database='/native/queued-push.db';
  const oldProfile=Uint8Array.of(1,2), newProfile=Uint8Array.of(3,4);
  let release!: () => void;
  const wait = new Promise<void>(resolve=> { release=resolve; });
  let entered!: () => void;
  const started = new Promise<void>(resolve=> { entered=resolve; });
  let count=0;
  const clear=frame(5,8);
  native.set('push_flow_begin_export',async input=> {
    count++;
    if(count===1) {
      assert.deepEqual(input,vectors(utf8(database),Uint8Array.of(1,2),Uint8Array.of(1)));
      entered();await wait;return frame(0,1,1);
    }
    assert.deepEqual(input,vectors(utf8(database),Uint8Array.of(3,4),Uint8Array.of(2)));
    return clear;
  });
  native.set('push_flow_complete_export',async input=> {
    assert.deepEqual(input,vectors(utf8(database),clear,Uint8Array.of(0)));
    return frame(0,9,0);
  });
  const first=push.enablePushBinding(database,oldProfile);
  await started;
  const second=push.disablePushBinding(database,newProfile);
  oldProfile.fill(99);newProfile.fill(99);
  release();
  assert.equal(await first,'enabled');assert.equal(await second,'disabled');
  assert.deepEqual(calls.filter(call=>call.symbol==='clearPushToken').map(call=>call.bytes),[vectors(utf8(database),clear)]);
  native.clear();
});
