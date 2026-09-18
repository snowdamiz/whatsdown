import assert from 'node:assert/strict';
import { test } from 'node:test';

import { formatDayLabel, formatInboxTime, groupDigits, sameDay } from './format.ts';

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
