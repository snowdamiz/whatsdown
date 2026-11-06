import assert from 'node:assert/strict';
import test from 'node:test';
import { executePushActions, type PushActionOperations } from './push-action-executor.ts';

function action(kind: number, status = 0, failure = 0, epoch = 1): Uint8Array {
  const bytes = new Uint8Array(kind === 0 ? 19 : 50);
  bytes.set([2, 0x50, 0x46, 0x41, kind, failure]);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(6, BigInt(epoch));
  view.setUint32(14, kind === 0 ? 1 : 32);
  bytes.fill(kind === 0 ? status : 42, 18);
  return bytes;
}

function operations(poll: Uint8Array, overrides: Partial<PushActionOperations> = {}): PushActionOperations {
  return {
    poll: async () => poll,
    complete: async () => { throw new Error('unexpected UI completion'); },
    send: async () => { throw new Error('unexpected native network action'); },
    requestPermission: async () => {}, prime: async () => {}, clear: async () => {},
    ...overrides,
  };
}

test('only native Mesh sends and settles a network action; UI receives opaque tickets', async () => {
  const permission = action(1), prime = action(2, 0, 0, 2), bind = action(3, 0, 0, 3);
  const events: string[] = [];
  assert.equal(await executePushActions(operations(permission, {
    requestPermission: async () => { events.push('permission'); },
    prime: async () => { events.push('prime'); },
    complete: async (frame, outcome) => {
      assert.equal(outcome, 0);
      events.push('UI completion');
      if (frame === permission) return prime;
      assert.strictEqual(frame, prime);
      return bind;
    },
    send: async frame => { assert.strictEqual(frame, bind); events.push('native send'); return action(0, 1); },
  })), 'enabled');
  assert.deepEqual(events, ['permission', 'UI completion', 'prime', 'UI completion', 'native send']);
});

test('a native transport error is never converted into a JavaScript acknowledgment', async () => {
  const error = new Error('push_transport_unavailable');
  let completed = 0;
  await assert.rejects(executePushActions(operations(action(3), {
    send: async () => { throw error; },
    complete: async () => { completed++; return action(0, 1); },
  })), error);
  assert.equal(completed, 0);
});

test('failed platform clear still follows Mesh through native unbind and final clear', async () => {
  const first = action(5), unbind = action(4, 0, 0, 2), last = action(5, 0, 0, 3);
  let clears = 0;
  const outcomes: number[] = [];
  assert.equal(await executePushActions(operations(first, {
    clear: async () => { if (++clears === 1) throw new Error('first clear failed'); },
    complete: async (frame, outcome) => {
      outcomes.push(outcome);
      if (frame === first) return unbind;
      assert.strictEqual(frame, last);
      return action(0, 0);
    },
    send: async frame => { assert.strictEqual(frame, unbind); return last; },
  })), 'disabled');
  assert.deepEqual(outcomes, [1, 0]);
  assert.equal(clears, 2);
});

test('surfaces the original platform error only when Mesh selects failure', async () => {
  const error = new Error('permission refused');
  await assert.rejects(executePushActions(operations(action(1), {
    requestPermission: async () => { throw error; },
    complete: async (_frame, outcome) => { assert.equal(outcome, 1); return action(0, 2, 1); },
  })), error);
});

test('rejects legacy wires and malformed tickets before any capability runs', async () => {
  const legacy = action(3); legacy[0] = 1;
  const short = action(3).slice(0, 49);
  const trailing = new Uint8Array(51); trailing.set(action(3));
  const invalidStatus = action(0, 9);
  const emptyEpoch = action(1, 0, 0, 0);
  for (const frame of [legacy, short, trailing, invalidStatus, emptyEpoch, action(6), action(2, 0, 1)]) {
    let calls = 0;
    await assert.rejects(executePushActions(operations(frame, {
      send: async () => { calls++; return action(0); },
      complete: async () => { calls++; return action(0); },
      requestPermission: async () => { calls++; }, prime: async () => { calls++; }, clear: async () => { calls++; },
    })), /invalid push action/i);
    assert.equal(calls, 0);
  }
});

test('bounds nonconverging action loops and preserves native completion errors', async () => {
  let completions = 0;
  await assert.rejects(executePushActions(operations(action(1), {
    complete: async () => { completions++; return action(1); },
  })), /did not converge/);
  assert.equal(completions, 16);
  const error = new Error('push_state_changed');
  await assert.rejects(executePushActions(operations(action(2), { complete: async () => { throw error; } })), error);
});
