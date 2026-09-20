import assert from 'node:assert/strict';
import { test } from 'node:test';

import { describeMember, describeMembers, summarizeMembers } from './group-members.ts';

const id = (value: number, length = 32) => new Uint8Array(length).fill(value);
const device = (leaf: number, account: number, local = false) => ({
  leaf,
  accountId: id(account),
  deviceId: id(leaf + 100, 16),
  local,
});

test('folds a group’s devices into the people they belong to, in joining order', () => {
  const summary = summarizeMembers([device(0, 1), device(1, 2), device(2, 1), device(3, 3)]);
  assert.equal(summary.devices, 4);
  assert.deepEqual(
    summary.people.map((person) => [person.accountId[0], person.devices]),
    [[1, 2], [2, 1], [3, 1]],
  );
  // Each person keeps their devices, so removing them can remove every one.
  assert.deepEqual(
    summary.people[0]!.deviceIds.map((deviceId) => deviceId[0]),
    [100, 102],
  );
});

test('a person is you when any of their devices is this one', () => {
  const summary = summarizeMembers([device(0, 1), device(1, 2, true), device(2, 2)]);
  assert.deepEqual(summary.people.map((person) => person.local), [false, true]);
});

test('an empty group has nobody in it', () => {
  assert.deepEqual(summarizeMembers([]), { people: [], devices: 0 });
});

test('describes the people, and the devices only when someone has more than one', () => {
  assert.equal(describeMembers(summarizeMembers([device(0, 1)])), '1 member');
  assert.equal(describeMembers(summarizeMembers([device(0, 1), device(1, 2)])), '2 members');
  assert.equal(
    describeMembers(summarizeMembers([device(0, 1), device(1, 2), device(2, 1)])),
    '2 members · 3 devices',
  );
});

test('says what a member is to you: their role, then your private thread with them', () => {
  const thread = { verified: false, blocked: false };
  assert.equal(describeMember({ local: true, creator: false }), undefined);
  assert.equal(describeMember({ local: true, creator: true }), 'Created the group');
  assert.equal(describeMember({ local: false, creator: false }), 'Not in your chats yet');
  assert.equal(describeMember({ local: false, creator: false, conversation: thread }), 'In your chats');
  assert.equal(
    describeMember({ local: false, creator: false, conversation: { ...thread, verified: true } }),
    'Verified contact',
  );
  assert.equal(
    describeMember({ local: false, creator: false, conversation: { ...thread, blocked: true, verified: true } }),
    'Blocked',
  );
  assert.equal(
    describeMember({ local: false, creator: true, conversation: { ...thread, verified: true } }),
    'Created the group · Verified contact',
  );
});
