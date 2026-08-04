import assert from 'node:assert/strict';
import test from 'node:test';

import { createKeyedSerialQueue, createKeyedSingleFlight } from './single-flight.ts';

test('coalesces a deferred publish and reconcile flow for one database', async () => {
  let deliverResponse: (response: string) => void = () => {
    throw new Error('Deferred response was not initialized');
  };
  const response = new Promise<string>((resolve) => {
    deliverResponse = resolve;
  });
  const events: string[] = [];
  const singleFlight = createKeyedSingleFlight<string, void>();
  const synchronize = () =>
    singleFlight('mobile.db', async () => {
      events.push('replenish');
      const acknowledgement = await response;
      events.push(`reconcile:${acknowledgement}`);
    });

  const first = synchronize();
  const concurrent = synchronize();
  await Promise.resolve();
  assert.deepEqual(events, ['replenish']);

  deliverResponse('latest-ota');
  await Promise.all([first, concurrent]);
  assert.deepEqual(events, ['replenish', 'reconcile:latest-ota']);
});

test('serializes later work after an earlier operation rejects', async () => {
  let rejectFirst: (error: Error) => void = () => {
    throw new Error('Deferred rejection was not initialized');
  };
  const firstGate = new Promise<never>((_, reject) => {
    rejectFirst = reject;
  });
  const events: string[] = [];
  const serialQueue = createKeyedSerialQueue<string>();

  const first = serialQueue('mobile.db', async () => {
    events.push('recover:start');
    await firstGate;
  });
  const second = serialQueue('mobile.db', async () => {
    events.push('disable');
    return 'disabled';
  });

  await Promise.resolve();
  assert.deepEqual(events, ['recover:start']);
  rejectFirst(new Error('recovery failed'));
  await assert.rejects(first, /recovery failed/);
  assert.equal(await second, 'disabled');
  assert.deepEqual(events, ['recover:start', 'disable']);
});
