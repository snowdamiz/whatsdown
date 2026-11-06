import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopFilePort } from './desktop-file-port.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { parseDesktopLockSnapshot } from './desktop-lock-protocol.ts';

const owner = '41414141-4242-4343-4444-454545454545';
const boot = '51515151-5252-5353-5454-555555555555';
const handle = '61616161-6262-6363-6464-656565656565';
const secondHandle = '71717171-7272-7373-7474-757575757575';
function credentials(generation = '1') {
  const state = parseDesktopLockSnapshot({ version: 1, owner, revision: generation,
    state: { epoch: `${boot}/${generation}`, phase: 'activated', policy: 'enabled', capability: 'available', foreground: true } });
  return { owner: state.owner, epoch: state.state.epoch };
}
function host(t: TestContext) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const calls: { name: string; body: unknown; options: unknown; snapshot: unknown }[] = [];
  const behavior: { invoke(name: string): Promise<unknown> } = { async invoke() { return null; } };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    __TAURI_INTERNALS__: { invoke(name: string, body: unknown, options: unknown) {
      calls.push({ name, body, options, snapshot: body instanceof Uint8Array ? body.slice() : structuredClone(body) }); return behavior.invoke(name);
    } },
  } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'window', previous); else Reflect.deleteProperty(globalThis, 'window'); });
  return { calls, behavior };
}
function fixture(t: TestContext, generation = '1') {
  const unused = async (): Promise<never> => { throw Error('unexpected_operation'); };
  const scope = createDesktopPrivateSession({ async check() {}, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  t.after(() => { scope.dispose(); });
  return { scope, port: createDesktopFilePort({ ...credentials(generation), scope }) };
}
const authority = { 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': `${boot}/1` };

test('file transport uses actual Tauri raw IPC and captured owner with UTF8 metadata', async t => {
  const h = host(t), f = fixture(t), bytes = Uint8Array.of(4, 9);
  const context = { version: 1, key: '图', mimeType: 'image/png' };
  h.behavior.invoke = async () => ({ version: 1, handle, uri: `morse-private://preview/${handle}` });
  assert.equal(await f.port.protectedFile('writePreview', context, bytes), JSON.stringify({ version: 1, handle, uri: `morse-private://preview/${handle}` }));
  assert.deepEqual(h.calls, [{ name: 'app_lock_file', body: new Uint8Array(bytes.length), snapshot: bytes, options: { headers: { ...authority,
    'X-Morse-File-Operation': 'writePreview',
    'X-Morse-File-Metadata': Buffer.from(JSON.stringify(context)).toString('base64'),
  } } }]);
  assert.notEqual(h.calls[0]?.body, bytes);
});

test('each resource minted during local disposal is discarded using its original captured owner', async t => {
  const h = host(t);
  for (const [operation, cleanup, extra] of [
    ['claimSource', 'closeSource', { size: 9 }],
    ['beginExport', 'abortExport', {}],
    ['writePreview', 'releasePreview', { uri: `morse-private://preview/${handle}` }],
    ['subscribeIncoming', 'unsubscribeIncoming', {}],
  ] satisfies [string, string, object][]) {
    const f = fixture(t); fixture(t, '2'); h.calls.length = 0;
    h.behavior.invoke = async name => {
      if (name === 'app_lock_file_cleanup') return null;
      f.scope.dispose(); return { version: 1, handle, ...extra };
    };
    await assert.rejects(f.port.protectedFile(operation, { version: 1 }), /stale_epoch/);
    assert.deepEqual(h.calls.filter(call => call.name === 'app_lock_file_cleanup'), [{
      name: 'app_lock_file_cleanup', body: { operation: cleanup, context: { version: 1, handle } }, snapshot: { operation: cleanup, context: { version: 1, handle } }, options: { headers: authority },
    }], operation);
  }
});

test('late read bytes are wiped in the actual raw IPC buffer', async t => {
  const h = host(t), f = fixture(t), raw = Uint8Array.of(5, 6).buffer;
  h.behavior.invoke = async () => { f.scope.dispose(); return raw; };
  await assert.rejects(f.port.protectedFile('readSource', { version: 1, handle, offset: 0, length: 2 }), /stale_epoch/);
  assert.deepEqual(new Uint8Array(raw), Uint8Array.of(0, 0));
  assert.equal(h.calls.length, 1);
});

test('resource cleanup failure preserves the stale failure and never forwards native detail', async t => {
  const h = host(t), f = fixture(t);
  h.behavior.invoke = async name => {
    if (name === 'app_lock_file_cleanup') throw Error('private native detail');
    f.scope.dispose(); return { version: 1, handle };
  };
  await assert.rejects(f.port.protectedFile('beginExport', { version: 1 }), { message: 'stale_epoch' });
  assert.equal(h.calls.filter(call => call.name === 'app_lock_file_cleanup').length, 1);
});

test('discard previews releases only that adapter handles and remains usable after disposal', async t => {
  const h = host(t), first = fixture(t), next = fixture(t, '2');
  let issued = handle;
  h.behavior.invoke = async name => name === 'app_lock_file_cleanup' ? null :
    ({ version: 1, handle: issued, uri: `morse-private://preview/${issued}` });
  await first.port.protectedFile('writePreview', { version: 1 }, Uint8Array.of(1));
  issued = secondHandle;
  await next.port.protectedFile('writePreview', { version: 1 }, Uint8Array.of(2));
  first.scope.dispose(); h.calls.length = 0;
  await first.port.cleanupProtectedFile('discardPreviews', { version: 1 });
  await first.port.cleanupProtectedFile('discardPreviews', { version: 1 });
  assert.deepEqual(h.calls, [{ name: 'app_lock_file_cleanup',
    body: { operation: 'releasePreview', context: { version: 1, handle } }, snapshot: { operation: 'releasePreview', context: { version: 1, handle } }, options: { headers: authority } }]);
  await next.port.cleanupProtectedFile('discardPreviews', { version: 1 });
  assert.deepEqual(h.calls[1], { name: 'app_lock_file_cleanup',
    body: { operation: 'releasePreview', context: { version: 1, handle: secondHandle } },
    snapshot: { operation: 'releasePreview', context: { version: 1, handle: secondHandle } },
    options: { headers: { ...authority, 'X-Morse-Lock-Epoch': `${boot}/2` } } });
});

test('malformed native metadata cannot nominate cleanup context or become a published result', async t => {
  const h = host(t), f = fixture(t);
  for (const reply of [undefined, [], { version: 2, handle }, { version: 1, handle, operation: 'closeSource' },
    { version: 1, handle, uri: 'file:///private/path' }]) {
    h.behavior.invoke = async () => reply;
    await assert.rejects(f.port.protectedFile('beginExport', { version: 1 }), /invalid_file_response/);
  }
  assert.equal(h.calls.filter(call => call.name === 'app_lock_file_cleanup').length, 0);
});

test('preview replies require their exact opaque resource URI and discard rejected owned handles', async t => {
  const h = host(t), f = fixture(t);
  for (const uri of ['file:///private/path', `morse-private://preview/${secondHandle}`,
    `morse-private://preview/${handle}?copy=1`, `morse-private://preview/${handle}#image`, 'https://example.test/image']) {
    h.calls.length = 0;
    h.behavior.invoke = async name => name === 'app_lock_file_cleanup' ? null : { version: 1, handle, uri };
    await assert.rejects(f.port.protectedFile('writePreview', { version: 1 }), /invalid_file_response/);
    assert.deepEqual(h.calls.filter(call => call.name === 'app_lock_file_cleanup'), [{ name: 'app_lock_file_cleanup',
      body: { operation: 'releasePreview', context: { version: 1, handle } }, snapshot: { operation: 'releasePreview', context: { version: 1, handle } }, options: { headers: authority } }]);
  }
});


test('file reads accept the actual macOS postMessage JSON byte array', async t => {
  const h = host(t), f = fixture(t), raw = [0, 128, 255];
  h.behavior.invoke = async () => raw;
  assert.deepEqual(await f.port.protectedFile('readSource', { version: 1, handle, offset: 0, length: 3 }), Uint8Array.of(0, 128, 255));
  assert.deepEqual(raw, [0, 0, 0]);
});

test('late macOS file bytes wipe both serialized and normalized owned storage', async t => {
  const h = host(t), f = fixture(t), raw = [5, 6];
  let normalized: unknown;
  const port = createDesktopFilePort({ ...credentials(), scope: {
    assertCurrent: f.scope.assertCurrent,
    runPrivate<T>(operation: () => Promise<T>): Promise<T> {
      return f.scope.runPrivate(async () => { const result = await operation(); normalized = result; return result; });
    },
  } });
  h.behavior.invoke = async () => { f.scope.dispose(); return raw; };
  await assert.rejects(port.protectedFile('readSource', { version: 1, handle, offset: 0, length: 2 }), /stale_epoch/);
  assert.deepEqual(raw, [0, 0]);
  assert.deepEqual(normalized, new Uint8Array(2));
});

test('file reads reject oversized owned binary replies and wipe them', async t => {
  const h = host(t), f = fixture(t), raw = new Uint8Array(65_537).fill(5);
  h.behavior.invoke = async () => raw.buffer;
  await assert.rejects(f.port.protectedFile('readSource', { version: 1, handle, offset: 0, length: 65_536 }), { message: 'invalid_file_response' });
  assert.ok(raw.every(byte => byte === 0));
});


test('file payload and metadata are captured before asynchronous native admission', async t => {
  const h = host(t), gate = Promise.withResolvers<void>();
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ check: () => gate.promise, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  t.after(() => { gate.resolve(); scope.dispose(); });
  const port = createDesktopFilePort({ ...credentials(), scope });
  const body = Uint8Array.of(4, 9), context = { version: 1, handle, offset: 0 };
  const expected = structuredClone(context);
  const pending = port.protectedFile('writeExport', context, body);
  body.fill(7); context.offset = 65536;
  await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(h.calls.length, 0);
  gate.resolve(); await pending;
  assert.deepEqual(h.calls[0]?.snapshot, Uint8Array.of(4, 9));
  assert.deepEqual(h.calls[0]?.options, { headers: { ...authority, 'X-Morse-File-Operation': 'writeExport', 'X-Morse-File-Metadata': Buffer.from(JSON.stringify(expected)).toString('base64') } });
  assert.deepEqual(h.calls[0]?.body, new Uint8Array(2)); assert.deepEqual(body, Uint8Array.of(7, 7));
});
