import assert from 'node:assert/strict';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { runPrivateOwned } from './private-resource.ts';
function defer(depth: number, body: () => void) { queueMicrotask(() => depth > 1 ? defer(depth - 1, body) : body()); }
for (const resource of ['handle', 'bytes'] as const) for (const outcome of ['value', 'error'] as const) for (const depth of [2, 3]) {
  test(`owned ${resource} ${outcome} at completion microtask ${depth} stays private after disposal`, async t => {
    let checks = 0, discards = 0;
    const bytes = new Uint8Array(32).fill(7);
    const unused = async (): Promise<never> => { throw Error('unexpected'); };
    const scope = createDesktopPrivateSession({ async check() { if (++checks === 2) defer(depth, () => { scope.dispose(); }); }, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
    t.after(() => { scope.dispose(); });
    const operation = () => runPrivateOwned({ scope, async operation() {
      if (outcome === 'error') throw Error('private-native-detail');
      return resource === 'bytes' ? bytes : { handle: 'owned' };
    }, discard() { discards++; } });
    await assert.rejects(operation, { message: 'stale_epoch' });
    assert.equal(discards, outcome === 'value' ? 1 : 0);
    if (resource === 'bytes' && outcome === 'value') assert.deepEqual(bytes, new Uint8Array(32));
  });
}

for (const depth of [2, 3]) test(`unreturned bytes are erased before deferred resource cleanup at microtask ${depth}`, async t => {
  let checks = 0;
  const bytes = Uint8Array.of(7, 8), entered = Promise.withResolvers<void>(), cleanup = Promise.withResolvers<void>();
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ async check() { if (++checks === 2) defer(depth, () => { scope.dispose(); }); }, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  t.after(() => { cleanup.resolve(); scope.dispose(); });
  const pending = runPrivateOwned({ scope, async operation() { return bytes; }, async discard() { entered.resolve(); await cleanup.promise; } });
  await entered.promise;
  const beforeCleanupSettles = bytes.slice();
  cleanup.resolve(); await assert.rejects(pending, { message: 'stale_epoch' });
  assert.deepEqual(beforeCleanupSettles, new Uint8Array(2));
  assert.deepEqual(bytes, new Uint8Array(2));
});
