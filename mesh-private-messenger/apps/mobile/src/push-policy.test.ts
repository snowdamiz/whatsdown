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
