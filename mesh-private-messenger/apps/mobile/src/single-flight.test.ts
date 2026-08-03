import assert from 'node:assert/strict';
import test from 'node:test';

import { createKeyedSingleFlight } from './single-flight.ts';

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
