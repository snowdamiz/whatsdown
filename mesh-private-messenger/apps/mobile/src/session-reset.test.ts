import assert from 'node:assert/strict';
import test from 'node:test';
import { sessionResetNotice } from './session-reset.ts';

const day = 86_400_000;
const now = 1_800_000_000_000;

test('a reset secure session is shown for a week, then no more', () => {
  assert.equal(
    sessionResetNotice({ username: 'alice', sessionResetAt: now - day }, now),
    'Secure session with @alice was reset. Messages sent while it was broken were sent again where they could be.',
  );
  assert.equal(sessionResetNotice({ username: 'alice', sessionResetAt: now - 8 * day }, now), undefined);
  assert.equal(sessionResetNotice({ username: 'alice', sessionResetAt: 0 }, now), undefined);
});
