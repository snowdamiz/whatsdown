import assert from 'node:assert/strict';
import test from 'node:test';
import { nativeFanoutRequest, parseNativeFanoutStatus } from './native-fanout.ts';
import { vectors, utf8 } from './codec.ts';

test('fanout captures the initiating profile and exact bounded intent before queueing', () => {
  const profile = Uint8Array.of(1, 2, 3);
  const payload = utf8('hello');
  const peer = new Uint8Array(32).fill(7);
  const packet = nativeFanoutRequest('/native/morse.db', profile, 'bob', 1, payload, peer);
  const expected = vectors(utf8('/native/morse.db'), profile, utf8('bob'), Uint8Array.of(1), payload, peer, new Uint8Array());
  profile.fill(9); payload.fill(9); peer.fill(9);
  assert.deepEqual(packet, expected);
  assert.equal(new TextDecoder().decode(packet).includes('http'), false);
});

test('fanout distinguishes message, invitation and acceptance without caller device sets or origin', () => {
  for (const kind of [2, 3] as const) {
    assert.deepEqual(nativeFanoutRequest('/native/db', Uint8Array.of(1), '@' + '01'.repeat(32), kind, new Uint8Array(32)),
      vectors(utf8('/native/db'), Uint8Array.of(1), utf8('@' + '01'.repeat(32)), Uint8Array.of(kind), new Uint8Array(32), new Uint8Array(), new Uint8Array()));
  }
  for (const create of [
    () => nativeFanoutRequest('', Uint8Array.of(1), 'bob', 1, utf8('x')),
    () => nativeFanoutRequest('/db\0other', Uint8Array.of(1), 'bob', 1, utf8('x')),
    () => nativeFanoutRequest('/db', new Uint8Array(), 'bob', 1, utf8('x')),
    () => nativeFanoutRequest('/db', new Uint8Array(36135), 'bob', 1, utf8('x')),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), 'https://evil', 1, utf8('x')),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), '@' + 'a'.repeat(63), 1, utf8('x')),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), 'bob', 1, new Uint8Array(32001)),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), 'bob', 1, utf8('x'), new Uint8Array(31)),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), 'bob', 2, new Uint8Array(31)),
    () => nativeFanoutRequest('/db', Uint8Array.of(1), 'bob', 3, new Uint8Array(32), undefined, Uint8Array.of(1)),
  ]) assert.throws(create, /invalid_fanout_action/);
});

test('only exact native version and boolean status can report contact changes', () => {
  assert.equal(parseNativeFanoutStatus(Uint8Array.of(1,70,78,79,0)), false);
  assert.equal(parseNativeFanoutStatus(Uint8Array.of(1,70,78,79,1)), true);
  for (const bad of [Uint8Array.of(1,70,78,79), Uint8Array.of(1,70,78,79,0,0), Uint8Array.of(2,70,78,79,0), Uint8Array.of(1,70,78,79,2)]) {
    assert.throws(() => parseNativeFanoutStatus(bad), /invalid_native_fanout_status/);
  }
});

test('attachment preflight carries only the intended recipients and never a message', () => {
  const identity = Uint8Array.of(1);
  assert.deepEqual(nativeFanoutRequest('/db', identity, 'bob', 4, new Uint8Array()),
    vectors(utf8('/db'), identity, utf8('bob'), Uint8Array.of(4), new Uint8Array(), new Uint8Array(), new Uint8Array()));
  const groups = new Uint8Array(64).fill(9);
  const captured = nativeFanoutRequest('/db', identity, 'alice', 5, groups);
  const expected = vectors(utf8('/db'), identity, utf8('alice'), Uint8Array.of(5), groups, new Uint8Array(), new Uint8Array());
  groups.fill(7); assert.deepEqual(captured, expected);
  for (const make of [
    () => nativeFanoutRequest('/db', identity, 'bob', 4, utf8('body')),
    () => nativeFanoutRequest('/db', identity, 'bob', 4, new Uint8Array(), undefined, Uint8Array.of(1)),
    () => nativeFanoutRequest('/db', identity, 'alice', 5, new Uint8Array(31)),
    () => nativeFanoutRequest('/db', identity, 'alice', 5, new Uint8Array(2080)),
    () => nativeFanoutRequest('/db', identity, 'alice', 5, new Uint8Array(32), new Uint8Array(32)),
  ]) assert.throws(make, /invalid_fanout_action/);
});
