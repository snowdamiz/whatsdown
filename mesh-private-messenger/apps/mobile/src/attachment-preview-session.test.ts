import assert from 'node:assert/strict';
import test from 'node:test';
import { AttachmentPreviewSession } from './attachment-preview-session.ts';

test('close zeros owned bytes, releases previews, aborts work and refuses late completion; another session is intact', () => {
  const released: string[] = []; let changes = 0;
  const a = new AttachmentPreviewSession('chat/a', uri => released.push(uri), () => { changes++; });
  const b = new AttachmentPreviewSession('group/b', uri => released.push(uri), () => {});
  const bytes = Uint8Array.of(11,12), other = Uint8Array.of(21,22);
  a.remember('same-object', bytes); a.setState('same-object', {status:'ready',previewUri:'file:///a'});
  b.remember('same-object', other); b.setState('same-object', {status:'ready',previewUri:'file:///b'});
  assert.equal(a.begin('pending'), true); assert.equal(a.begin('pending'), false);
  a.close(); a.close();
  assert.deepEqual(bytes, new Uint8Array(2)); assert.equal(a.signal.aborted, true);
  assert.deepEqual(released, ['file:///a']); assert.equal(a.state('same-object'), undefined);
  assert.equal(a.bytes('same-object'), undefined); assert.equal(a.begin('pending'), false);
  const before = changes;
  a.setState('pending', {status:'error',message:'late'});
  const late = Uint8Array.of(31,32); a.remember('pending', late);
  assert.deepEqual(late, new Uint8Array(2)); assert.equal(changes, before);
  assert.deepEqual(other, Uint8Array.of(21,22)); assert.equal(b.state('same-object')?.previewUri, 'file:///b');
  const reopened = new AttachmentPreviewSession('chat/a', uri => released.push(uri), () => {});
  assert.equal(reopened.begin('pending'), true); a.finish('pending');
  assert.equal(reopened.begin('pending'), false, 'Old completion cannot unlock new in-flight work');
  b.close(); reopened.close();
});

test('bounded cache erases evicted bytes while retaining separately owned previews until close', () => {
  const released: string[] = [];
  const session = new AttachmentPreviewSession('chat/a', uri => released.push(uri), () => {}, 4);
  const first = Uint8Array.of(1,2), second = Uint8Array.of(3,4), third = Uint8Array.of(5,6);
  session.remember('1', first); session.setState('1', {status:'ready',previewUri:'blob:1'});
  session.remember('2', second); session.remember('3', third);
  assert.deepEqual(first, new Uint8Array(2)); assert.equal(session.bytes('1'), undefined);
  assert.equal(session.state('1')?.previewUri, 'blob:1'); assert.deepEqual(released, []);
  session.close(); assert.deepEqual(second, new Uint8Array(2)); assert.deepEqual(third, new Uint8Array(2));
  assert.deepEqual(released, ['blob:1']);
});

test('a save picker retains exact bytes across cache pressure, but close still clears them', () => {
  const session = new AttachmentPreviewSession('chat/a', () => {}, () => {}, 4);
  const bytes = Uint8Array.of(1,2,3,4); session.remember('saving', bytes);
  const held = session.retain('saving'); assert.ok(held);
  session.remember('next', Uint8Array.of(5,6,7,8));
  assert.deepEqual(held.bytes, Uint8Array.of(1,2,3,4));
  held.release(); assert.deepEqual(bytes, new Uint8Array(4));
  const other = session.retain('next'); assert.ok(other);
  session.close(); assert.deepEqual(other.bytes, new Uint8Array(4)); other.release();
});

test('expiry erases only removed message previews, aborts their work and refuses late repopulation', () => {
  const released: string[] = [];
  const session = new AttachmentPreviewSession('group/a', uri => released.push(uri), () => {});
  const expired = Uint8Array.of(1,2), kept = Uint8Array.of(3,4);
  session.remember('expired', expired); session.setState('expired', {status:'ready', previewUri:'blob:expired'});
  session.remember('kept', kept); session.setState('kept', {status:'ready', previewUri:'blob:kept'});
  const held = session.retain('expired'); assert.ok(held);
  assert.equal(session.begin('expired'), true);
  const signal = session.requestSignal('expired');
  session.restrictTo(['kept']);
  assert.equal(signal.aborted, true);
  assert.deepEqual(expired, new Uint8Array(2)); assert.deepEqual(held.bytes, new Uint8Array(2));
  assert.equal(session.bytes('expired'), undefined); assert.equal(session.state('expired'), undefined);
  assert.equal(session.begin('expired'), false);
  assert.deepEqual(kept, Uint8Array.of(3,4)); assert.equal(session.state('kept')?.previewUri, 'blob:kept');
  const late = Uint8Array.of(5,6); session.remember('expired', late);
  session.setState('expired', {status:'ready', previewUri:'blob:late'});
  assert.deepEqual(late, new Uint8Array(2)); assert.deepEqual(released, ['blob:expired', 'blob:late']);
  held.release(); session.finish('expired', signal); session.close();
});

test('an obsolete expired request cannot unlock a fresh request for a visible object', () => {
  const session = new AttachmentPreviewSession('chat/a', () => {}, () => {});
  session.restrictTo(['object']); assert.equal(session.begin('object'), true);
  const old = session.requestSignal('object');
  session.restrictTo([]); session.restrictTo(['object']);
  assert.equal(session.begin('object'), true);
  const next = session.requestSignal('object'); assert.notEqual(next, old);
  const late = Uint8Array.of(8,9); session.remember('object', late, old);
  assert.deepEqual(late, new Uint8Array(2)); assert.equal(session.bytes('object'), undefined);
  session.finish('object', old);
  assert.equal(session.begin('object'), false);
  session.finish('object', next); assert.equal(session.begin('object'), true);
  session.close();
});

test('expired old save lease cannot release readded same-object bytes under cache pressure', () => {
  const session = new AttachmentPreviewSession('group/a', () => {}, () => {}, 4);
  const old = Uint8Array.of(1,2,3,4); session.remember('same', old);
  const oldLease = session.retain('same'); assert.ok(oldLease);
  session.restrictTo([]); session.restrictTo(['same', 'pressure']);
  const fresh = Uint8Array.of(5,6,7,8); session.remember('same', fresh);
  const freshLease = session.retain('same'); assert.ok(freshLease);
  oldLease.release();
  session.remember('pressure', Uint8Array.of(9,10,11,12));
  assert.deepEqual(old, new Uint8Array(4));
  assert.deepEqual(freshLease.bytes, Uint8Array.of(5,6,7,8));
  freshLease.release(); assert.deepEqual(fresh, new Uint8Array(4));
  session.close();
});
