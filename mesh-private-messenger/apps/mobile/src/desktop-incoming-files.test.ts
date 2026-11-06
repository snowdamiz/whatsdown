import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createDesktopIncomingFiles } from './desktop-incoming-files.ts';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { isDesktopOwner, isDesktopEpoch } from './desktop-lock-protocol.ts';
import type { AttachmentSelection } from './attachment-selections.ts';
import type { IncomingFileHandlers } from './attachment-io.ts';
const owner = '00000000-0000-4000-8000-000000000001';
const epoch = owner + '/1';
const handle = '00000000-0000-4000-8000-000000000002';
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function selection() {
  const bytes = Uint8Array.of(4, 5, 6);
  return { kind: 'small', filename: 'private.bin', mimeType: 'application/octet-stream', size: 3, bytes, dispose() { bytes.fill(0); } } satisfies AttachmentSelection;
}
function fixture(t: TestContext) {
  if (!isDesktopOwner(owner) || !isDesktopEpoch(epoch)) throw Error('invalid_fixture');
  const calls: { operation: string; context: unknown }[] = [];
  const state = {
    async register(): Promise<unknown> { return JSON.stringify({ version: 1, handle }); },
    async remove(): Promise<void> {},
    async read(_subscription: string): Promise<AttachmentSelection[]> { return []; },
    async check(): Promise<void> {},
  };
  const unused = async (): Promise<never> => { throw Error('unexpected'); };
  const scope = createDesktopPrivateSession({ check: () => state.check(), invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const manager = createDesktopIncomingFiles({ owner, epoch, scope, files: {
    async protectedFile(operation, context) { calls.push({ operation, context }); return state.register(); },
    async cleanupProtectedFile(operation, context) { calls.push({ operation, context }); await state.remove(); },
  } });
  const delivered: AttachmentSelection[][] = [], errors: string[] = [], dragging: boolean[] = [];
  const handlers: IncomingFileHandlers = { onFiles() { throw Error('unexpected_legacy_handler'); }, onSelections(files) { delivered.push(files); }, onDragging(value) { dragging.push(value); }, onError(message) { errors.push(message); } };
  const listen = () => manager.listen(handlers, subscription => state.read(subscription));
  const emit = (fields: object = {}) => manager.receive({ version: 1, owner, epoch, subscription: handle, kind: 'sources', ...fields });
  t.after(async () => { scope.dispose(); await manager.close(); for (const files of delivered) for (const file of files) file.dispose(); });
  return { state, scope, manager, calls, delivered, errors, dragging, handlers, listen, emit };
}
test('native intake catches a choice queued before subscription registration completes', async t => {
  const f = fixture(t), file = selection(); let reads = 0;
  f.state.read = async subscription => { assert.equal(subscription, handle); reads++; return reads === 1 ? [file] : []; };
  const stop = f.listen(); await tick();
  assert.deepEqual(f.delivered, [[file]]); assert.deepEqual(f.calls[0], { operation: 'subscribeIncoming', context: { version: 1 } });
  stop(); assert.equal(await f.manager.close(), true);
  assert.deepEqual(f.calls.at(-1), { operation: 'unsubscribeIncoming', context: { version: 1, handle } });
});
test('unsubscribe before registration settles cleans its late handle and reads no files', async t => {
  const f = fixture(t), registration = Promise.withResolvers<unknown>(); let reads = 0;
  f.state.register = () => registration.promise; f.state.read = async () => { reads++; return []; };
  const stop = f.listen(); await tick(); stop();
  let closed = false; const closing = f.manager.close().then(value => { closed = true; return value; });
  await tick(); assert.equal(closed, false);
  registration.resolve(JSON.stringify({ version: 1, handle })); assert.equal(await closing, true);
  assert.equal(reads, 0); assert.equal(f.calls.filter(call => call.operation === 'unsubscribeIncoming').length, 1);
});
test('a closed subscription erases a late result without delivering to its former composer', async t => {
  const f = fixture(t), read = Promise.withResolvers<AttachmentSelection[]>(), file = selection();
  f.state.read = () => read.promise; const stop = f.listen(); await tick(); stop();
  read.resolve([file]); await f.manager.close(); await tick();
  assert.equal(f.delivered.length, 0); assert.deepEqual(file.bytes, new Uint8Array(3)); assert.equal(f.errors.length, 0);
});
test('native hints must match the exact captured owner epoch and subscription', async t => {
  const f = fixture(t); let reads = 0;
  f.state.read = async () => { reads++; return []; }; f.listen(); await tick(); assert.equal(reads, 1);
  for (const fields of [{ owner: handle }, { epoch: owner + '/2' }, { subscription: owner }, { extra: true }, { version: 2 }]) f.emit(fields);
  await tick(); assert.equal(reads, 1);
  f.emit(); await tick(); assert.equal(reads, 2);
  f.emit({ kind: 'dragging', dragging: true }); await tick(); assert.deepEqual(f.dragging, [true]);
});
test('overlapping source hints serialize reads and retain one followup drain', async t => {
  const f = fixture(t), read = Promise.withResolvers<AttachmentSelection[]>(); let reads = 0;
  f.state.read = () => { reads++; return reads === 1 ? read.promise : Promise.resolve([]); };
  f.listen(); await tick(); f.emit(); f.emit(); f.emit(); await tick(); assert.equal(reads, 1);
  read.resolve([]); await tick(); assert.equal(reads, 2); assert.equal(f.delivered.length, 0);
});
test('session disposal suppresses pending native drag callbacks and private failure details', async t => {
  const f = fixture(t), read = Promise.withResolvers<AttachmentSelection[]>(), admission = Promise.withResolvers<void>();
  f.state.read = () => read.promise; f.listen(); await tick();
  f.state.check = () => admission.promise; f.emit({ kind: 'dragging', dragging: true }); await tick();
  f.scope.dispose(); admission.resolve(); read.reject(Error('private filename')); await f.manager.close(); await tick();
  assert.deepEqual(f.dragging, []); assert.deepEqual(f.errors, []); assert.deepEqual(f.delivered, []);
});
test('a throwing composer cannot retain untransferred file bytes and sees only a generic error', async t => {
  const f = fixture(t), file = selection(); f.state.read = async () => [file];
  f.handlers.onSelections = () => { throw Error('private filename'); };
  f.listen(); await tick(); assert.deepEqual(file.bytes, new Uint8Array(3)); assert.deepEqual(f.errors, ['Those files could not be read.']);
});
test('close waits for native cleanup and reports its failure without reopening listeners', async t => {
  const f = fixture(t), remove = Promise.withResolvers<void>(); f.state.remove = () => remove.promise;
  f.listen(); await tick(); let closed = false;
  const closing = f.manager.close().then(value => { closed = true; return value; });
  await tick(); assert.equal(closed, false); remove.reject(Error('cleanup_refused')); assert.equal(await closing, false);
  f.emit(); await tick(); assert.deepEqual(f.delivered, []);
  assert.throws(f.listen, /stale_epoch/);
});

test('untransferred bytes are erased before an error callback waits for native admission', async t => {
  const f = fixture(t), file = selection(), admission = Promise.withResolvers<void>();
  f.state.read = async () => [file];
  f.handlers.onSelections = () => { f.state.check = () => admission.promise; throw Error('private filename'); };
  f.listen(); await tick();
  try { assert.deepEqual(file.bytes, new Uint8Array(3)); assert.deepEqual(f.errors, []); }
  finally { admission.resolve(); }
});
