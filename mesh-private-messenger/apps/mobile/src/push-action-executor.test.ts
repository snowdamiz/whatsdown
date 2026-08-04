import assert from 'node:assert/strict';
import test from 'node:test';

import {
  executePushActions,
  type PushActionOperations,
} from './push-action-executor.ts';

const action = (
  kind: number,
  payload: Uint8Array = new Uint8Array(),
  flags = 0,
  epoch = 1,
): Uint8Array => {
  const frame = new Uint8Array(18 + payload.length);
  frame.set([1, 0x50, 0x46, 0x41, kind, flags], 0);
  new DataView(frame.buffer).setBigUint64(6, BigInt(epoch));
  new DataView(frame.buffer).setUint32(14, payload.length);
  frame.set(payload, 18);
  return frame;
};

test('executes only the capabilities selected by Mesh and completes the exact actions', async () => {
  const bind = Uint8Array.of(9, 8, 7);
  const actions = [action(1), action(2), action(3, bind), action(0, Uint8Array.of(1))];
  const completed: Array<{ action: Uint8Array; outcome: number }> = [];
  const events: string[] = [];
  let index = 0;
  const operations: PushActionOperations = {
    poll: async () => actions[index],
    complete: async (exactAction, outcome) => {
      completed.push({ action: exactAction, outcome });
      index += 1;
      return actions[index];
    },
    requestPermission: async () => { events.push('permission'); },
    prime: async () => { events.push('prime'); },
    clear: async () => { events.push('clear'); },
    sendBind: async (wire) => { events.push(`bind:${Array.from(wire).join(',')}`); },
    sendUnbind: async () => { events.push('unbind'); },
  };

  assert.equal(await executePushActions(operations), 'enabled');
  assert.deepEqual(events, ['permission', 'prime', 'bind:9,8,7']);
  assert.deepEqual(completed.map(({ outcome }) => outcome), [0, 0, 0]);
  assert.strictEqual(completed[0].action, actions[0]);
  assert.strictEqual(completed[1].action, actions[1]);
  assert.strictEqual(completed[2].action, actions[2]);
});

test('records a failed capability and surfaces the original error only when Mesh directs it', async () => {
  const clear = action(5);
  const done = action(0, Uint8Array.of(3), 1);
  const clearError = new Error('native clear failed');
  let completion: { action: Uint8Array; outcome: number } | undefined;

  await assert.rejects(
    executePushActions({
      poll: async () => clear,
      complete: async (exactAction, outcome) => {
        completion = { action: exactAction, outcome };
        return done;
      },
      requestPermission: async () => {},
      prime: async () => {},
      clear: async () => { throw clearError; },
      sendBind: async () => {},
      sendUnbind: async () => {},
    }),
    clearError,
  );
  assert.deepEqual(completion, { action: clear, outcome: 1 });
});

test('does not report a Mesh completion failure as a platform action failure', async () => {
  const prime = action(2);
  let completions = 0;
  await assert.rejects(
    executePushActions({
      poll: async () => prime,
      complete: async () => {
        completions += 1;
        throw new Error('Mesh completion failed');
      },
      requestPermission: async () => {},
      prime: async () => {},
      clear: async () => {},
      sendBind: async () => {},
      sendUnbind: async () => {},
    }),
    /Mesh completion failed/,
  );
  assert.equal(completions, 1);
});

test('continues from a failed first clear through unbind and the final clear selected by Mesh', async () => {
  const clearError = new Error('stale clear failure');
  const unbind = Uint8Array.of(4, 5, 6);
  const frames = [
    action(5),
    action(4, unbind, 0, 2),
    action(5, new Uint8Array(), 0, 3),
    action(0, Uint8Array.of(0), 0, 4),
  ];
  let completion = 0;
  let clears = 0;
  const events: string[] = [];

  assert.equal(await executePushActions({
    poll: async () => frames[0],
    complete: async (_exactAction, outcome) => {
      events.push(`outcome:${outcome}`);
      completion += 1;
      return frames[completion];
    },
    requestPermission: async () => {},
    prime: async () => {},
    clear: async () => {
      clears += 1;
      events.push(`clear:${clears}`);
      if (clears === 1) throw clearError;
    },
    sendBind: async () => {},
    sendUnbind: async (wire) => { events.push(`unbind:${Array.from(wire).join(',')}`); },
  }), 'disabled');
  assert.deepEqual(events, [
    'clear:1',
    'outcome:1',
    'unbind:4,5,6',
    'outcome:0',
    'clear:2',
    'outcome:0',
  ]);
});

test('stops a non-converging Mesh action stream', async () => {
  const permission = action(1);
  let completions = 0;

  await assert.rejects(
    executePushActions({
      poll: async () => permission,
      complete: async () => {
        completions += 1;
        return permission;
      },
      requestPermission: async () => {},
      prime: async () => {},
      clear: async () => {},
      sendBind: async () => {},
      sendUnbind: async () => {},
    }),
    /did not converge/,
  );
  assert.equal(completions, 16);
});

test('rejects malformed or over-permissive Mesh action frames', async () => {
  const invalid = [
    action(1, Uint8Array.of(1)),
    action(2, new Uint8Array(), 1),
    action(3),
    action(0, Uint8Array.of(9)),
    action(6),
    Uint8Array.of(1, 0x50, 0x46, 0x41),
  ];

  for (const frame of invalid) {
    await assert.rejects(
      executePushActions({
        poll: async () => frame,
        complete: async () => { throw new Error('must not complete malformed action'); },
        requestPermission: async () => {},
        prime: async () => {},
        clear: async () => {},
        sendBind: async () => {},
        sendUnbind: async () => {},
      }),
      /invalid push action/i,
    );
  }
});
