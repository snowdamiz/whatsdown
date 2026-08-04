import assert from 'node:assert/strict';
import test from 'node:test';

import {
  coordinatePush,
  type PushFlowOperations,
  type PushStatus,
} from './push-coordinator.ts';

test('orders durable push recovery and explicit privacy actions', async () => {
  const events: string[] = [];
  const wire = Uint8Array.of(1);
  const operations: PushFlowOperations = {
    requestPermission: async () => { events.push('permission'); },
    prime: async () => { events.push('prime'); },
    clear: async () => { events.push('clear'); },
    prepareBind: async () => { events.push('prepare-bind'); return wire; },
    prepareUnbind: async () => { events.push('prepare-unbind'); return wire; },
    sendBind: async () => { events.push('send-bind'); },
    sendUnbind: async () => { events.push('send-unbind'); },
    commit: async () => { events.push('commit'); },
  };
  const run = async (status: PushStatus, intent: 'recover' | 'enable' | 'disable') => {
    events.length = 0;
    await coordinatePush(status, intent, operations);
    return [...events];
  };

  assert.deepEqual(await run('disabled', 'recover'), []);
  assert.deepEqual(await run('enabled', 'recover'), [
    'prime', 'prepare-bind', 'send-bind', 'commit',
  ]);
  assert.deepEqual(await run('pending-bind', 'recover'), [
    'prepare-bind', 'send-bind', 'commit',
  ]);
  assert.deepEqual(await run('pending-unbind', 'recover'), [
    'prepare-unbind', 'clear', 'send-unbind', 'commit',
  ]);
  assert.deepEqual(await run('disabled', 'enable'), [
    'permission', 'prime', 'prepare-bind', 'send-bind', 'commit',
  ]);
  assert.deepEqual(await run('enabled', 'disable'), [
    'prepare-unbind', 'clear', 'send-unbind', 'commit',
  ]);

  const clearError = new Error('native token cleanup failed');
  events.length = 0;
  await assert.rejects(
    coordinatePush('enabled', 'disable', {
      ...operations,
      clear: async () => {
        events.push('clear');
        throw clearError;
      },
    }),
    clearError,
  );
  assert.deepEqual(events, ['prepare-unbind', 'clear', 'send-unbind', 'commit']);
});
