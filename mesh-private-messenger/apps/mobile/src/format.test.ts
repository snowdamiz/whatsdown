import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  formatDayLabel,
  formatInboxTime,
  friendlyError,
  groupDigits,
  sameDay,
} from './format.ts';

const day = 86_400_000;
// A Wednesday at 15:04 local time keeps every relative label on a known weekday.
const now = new Date(2026, 8, 16, 15, 4).getTime();

test('sameDay compares calendar days, not 24-hour windows', () => {
  const lateEvening = new Date(2026, 8, 16, 23, 30).getTime();
  const earlyMorning = new Date(2026, 8, 17, 0, 15).getTime();
  assert.equal(sameDay(now, lateEvening), true);
  assert.equal(sameDay(lateEvening, earlyMorning), false);
});

test('formatDayLabel names today and yesterday, then weekdays, then dates', () => {
  assert.equal(formatDayLabel(now - 60_000, now), 'Today');
  assert.equal(formatDayLabel(now - day, now), 'Yesterday');
  assert.equal(formatDayLabel(now - 2 * day, now), 'Monday');
  assert.equal(formatDayLabel(now - 6 * day, now), 'Thursday');
  assert.match(formatDayLabel(now - 7 * day, now), /September 9/);
  assert.match(formatDayLabel(new Date(2025, 0, 3).getTime(), now), /January 3, 2025/);
});

test('formatInboxTime is a clock today and shortens older activity', () => {
  assert.match(formatInboxTime(now - 5 * 60_000, now), /\d:\d\d/);
  assert.equal(formatInboxTime(now - day, now), 'Yesterday');
  assert.equal(formatInboxTime(now - 3 * day, now), 'Sun');
  assert.match(formatInboxTime(now - 10 * day, now), /Sep 6/);
  assert.match(formatInboxTime(new Date(2024, 11, 24).getTime(), now), /Dec 24, 2024/);
});

test('groupDigits splits a safety number into fixed-width groups', () => {
  assert.deepEqual(groupDigits('123456789012', 5), ['12345', '67890', '12']);
  assert.deepEqual(groupDigits('', 5), []);
});

test('friendlyError maps known protocol and network failures to plain language', () => {
  assert.equal(
    friendlyError(new Error('Mesh library call failed (status=7): peer_keys_changed')),
    'Their security keys changed. Verify before sending.',
  );
  assert.equal(
    friendlyError(new Error('message_request_pending')),
    'Accept this message request before replying.',
  );
  assert.equal(
    friendlyError(new Error('conversation_blocked')),
    'Unblock this conversation before sending.',
  );
  assert.equal(friendlyError(new Error('Server returned 404')), 'No exact username match was found.');
  assert.equal(
    friendlyError(new Error('AbortError: request timed out')),
    'The server did not respond. Try again when connected.',
  );
  assert.equal(
    friendlyError(
      new Error(
        'fetch failed: UnexpectedException: Could not connect to the server. (at ExpoModulesCore/Promise.swift:56)',
      ),
    ),
    'Can’t reach the server. Check your connection and try again.',
  );
  assert.equal(
    friendlyError(new Error('Server returned 500')),
    'The server hit a problem. Try again in a moment.',
  );
  assert.equal(friendlyError(new Error('username_taken')), 'That username is taken. Try another.');
  assert.equal(
    friendlyError(new Error('account_deletion_unsupported')),
    'This server can’t delete accounts yet. Nothing was erased.',
  );
  assert.equal(
    friendlyError(new Error('unproven_removal')),
    'The server says this device is no longer in its account but can’t prove it. Nothing was erased.',
  );
  assert.equal(
    friendlyError(new Error('account_deletion_refused')),
    'The server refused to delete the account. Check this device’s date and time, then try again.',
  );
  assert.equal(
    friendlyError(new Error('removed_from_account')),
    'This device is no longer part of its account. Erase it in You to start again.',
  );
  assert.equal(
    friendlyError(new Error('registration_refused')),
    'The server won’t register this device. If it was removed from your account, erase it in You to start again.',
  );
});

test('friendlyError strips native noise from unknown failures and keeps app copy intact', () => {
  assert.equal(
    friendlyError(
      new Error(
        'UnexpectedException: Mesh library call failed (status=9): transparency_verification_failed (at ExpoModulesCore/AsyncFunctionDefinition.swift:126)',
      ),
    ),
    'Transparency verification failed.',
  );
  // Android wraps the same failure in Expo's call-site notice and a Java class name.
  assert.equal(
    friendlyError(
      new Error(
        "Call to function 'MeshMessenger.invoke' has been rejected.\n→ Caused by: java.lang.IllegalStateException: Mesh library call failed (status=9): transparency_verification_failed",
      ),
    ),
    'Transparency verification failed.',
  );
  assert.equal(
    friendlyError('Use 3–32 lowercase letters, numbers, or underscores.'),
    'Use 3–32 lowercase letters, numbers, or underscores.',
  );
  assert.equal(friendlyError(''), 'Something went wrong.');
  assert.equal(friendlyError(undefined), 'Something went wrong.');
});

test('stale authorization explains how to refresh before sending', () => {
  assert.equal(friendlyError('transparency_stale'), 'Security information is out of date. Reconnect and refresh before sending.');
});
