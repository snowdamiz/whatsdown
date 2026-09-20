import assert from 'node:assert/strict';
import test from 'node:test';
import { describeSafety } from './safety.ts';

const number = 'a3f91c2e77b00d4f9e215a6cb3d844100f7ac2e18b936d052c4ea917f30b5e68';
const conversation = { username: 'priya', safetyNumber: number, verified: false, keyChanged: false };

test('an unverified safety number asks to be compared and can be marked verified', () => {
  const state = describeSafety(conversation);
  assert.equal(state.tone, 'muted');
  assert.equal(state.status, 'Not verified');
  assert.match(state.note, /@priya/);
  assert.equal(state.verifiable, true);
});

test('a verified safety number promises a warning if it changes and needs nothing more', () => {
  const state = describeSafety({ ...conversation, verified: true });
  assert.equal(state.tone, 'success');
  assert.equal(state.status, 'Verified on this device');
  assert.match(state.note, /warned/);
  assert.equal(state.verifiable, false);
});

test('a key change is a warning that outranks whatever the record still says', () => {
  const state = describeSafety({ ...conversation, verified: true, keyChanged: true });
  assert.equal(state.tone, 'warning');
  assert.equal(state.status, 'Changed');
  assert.match(state.note, /compare/i);
  assert.equal(state.verifiable, true);
});

test('without a number there is nothing to compare or verify, even after a key change', () => {
  for (const keyChanged of [false, true]) {
    const state = describeSafety({ ...conversation, safetyNumber: '', keyChanged });
    assert.equal(state.tone, keyChanged ? 'warning' : 'muted');
    assert.equal(state.status, keyChanged ? 'Changed' : 'Not ready');
    assert.match(state.note, /exchanged a message/);
    assert.equal(state.verifiable, false);
  }
});
