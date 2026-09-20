import assert from 'node:assert/strict';
import test from 'node:test';

import { GENERIC_PUSH_BODY, isGenericWakeupContent } from './push-policy.ts';

test('accepts only the metadata-free encrypted wakeup payload', () => {
  assert.equal(isGenericWakeupContent(GENERIC_PUSH_BODY, { kind: 'encrypted-wakeup' }), true);
  assert.equal(
    isGenericWakeupContent(GENERIC_PUSH_BODY, {
      kind: 'encrypted-wakeup',
      sender: 'alice',
    }),
    false,
  );
  assert.equal(isGenericWakeupContent('Message from Alice', { kind: 'encrypted-wakeup' }), false);
  assert.equal(isGenericWakeupContent(GENERIC_PUSH_BODY, undefined), false);
});

test('recognizes headless wakeups and validates notification routes before navigation', async () => {
  const { notificationScope, backgroundWakeup } = await import('./push-policy.ts');
  assert.equal(isGenericWakeupContent(null, { kind: 'encrypted-wakeup' }), true);
  assert.equal(backgroundWakeup({ dataString: '{"kind":"encrypted-wakeup"}' }), true);
  assert.equal(backgroundWakeup({ dataString: '{broken' }), false);
  assert.equal(notificationScope({ kind: 'message', scope: `group/${'a'.repeat(64)}` }), `group/${'a'.repeat(64)}`);
  assert.equal(notificationScope({ kind: 'message', scope: 'group/invalid' }), null);
});
