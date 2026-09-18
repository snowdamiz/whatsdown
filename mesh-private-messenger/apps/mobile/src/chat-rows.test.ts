import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildChatRows } from './chat-rows.ts';

const now = new Date(2026, 8, 16, 15, 0).getTime();
const at = (daysAgo: number, minute: number) =>
  new Date(2026, 8, 16 - daysAgo, 12, minute).getTime();

const message = (direction: 'sent' | 'received', timestamp: number, body: string) => ({
  direction,
  timestamp,
  body,
});

test('inserts a day divider whenever the calendar day changes', () => {
  const rows = buildChatRows(
    [
      message('received', at(1, 0), 'yesterday'),
      message('sent', at(0, 1), 'today'),
    ],
    (item) => item.body,
    now,
  );
  assert.deepEqual(
    rows.map((row) => (row.kind === 'day' ? `day:${row.label}` : row.message.body)),
    ['day:Yesterday', 'yesterday', 'day:Today', 'today'],
  );
});

test('groups consecutive messages from one side and tails only the last', () => {
  const rows = buildChatRows(
    [
      message('received', at(0, 0), 'a'),
      message('received', at(0, 1), 'b'),
      message('sent', at(0, 2), 'c'),
    ],
    (item) => item.body,
    now,
  );
  const messages = rows.flatMap((row) => (row.kind === 'message' ? [row] : []));
  assert.deepEqual(
    messages.map((row) => [row.message.body, row.spaced, row.tail]),
    [
      ['a', true, false],
      ['b', false, true],
      ['c', true, true],
    ],
  );
});

test('returns no rows for an empty history', () => {
  assert.deepEqual(buildChatRows([], () => 'x', now), []);
});
