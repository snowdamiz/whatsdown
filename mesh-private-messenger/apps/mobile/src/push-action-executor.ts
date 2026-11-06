export type PushStatus = 'disabled' | 'enabled' | 'pending-bind' | 'pending-unbind';

export type PushActionOperations = {
  poll: () => Promise<Uint8Array>;
  complete: (action: Uint8Array, outcome: 0 | 1) => Promise<Uint8Array>;
  requestPermission: () => Promise<void>;
  prime: (action: Uint8Array) => Promise<void>;
  clear: (action: Uint8Array) => Promise<void>;
  send: (action: Uint8Array) => Promise<Uint8Array>;
};

type PushAction =
  | { kind: 0; status: PushStatus; surfaceError: boolean }
  | { kind: 1 | 2 | 3 | 4 | 5 };

const HEADER_LENGTH = 18;
const TICKET_LENGTH = 32;
const MAX_STEPS = 16;
const STATUS: readonly PushStatus[] = [
  'disabled',
  'enabled',
  'pending-bind',
  'pending-unbind',
];

function invalidPushAction(): never {
  throw new Error('Mesh returned an invalid push action');
}

function parsePushAction(frame: Uint8Array): PushAction {
  if (
    frame.length < HEADER_LENGTH ||
    frame.length > HEADER_LENGTH + TICKET_LENGTH ||
    frame[0] !== 2 ||
    frame[1] !== 0x50 ||
    frame[2] !== 0x46 ||
    frame[3] !== 0x41
  ) {
    return invalidPushAction();
  }
  const kind = frame[4];
  const flags = frame[5];
  if (kind === undefined || flags === undefined) return invalidPushAction();
  const payloadLength = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(14);
  if (frame.length !== HEADER_LENGTH + payloadLength) return invalidPushAction();
  const payload = frame.slice(HEADER_LENGTH);

  if (kind === 0) {
    const statusCode = payload[0];
    if (payload.length !== 1 || flags > 1 || statusCode === undefined) {
      return invalidPushAction();
    }
    const status = STATUS[statusCode];
    if (status === undefined) return invalidPushAction();
    return { kind, status, surfaceError: flags === 1 };
  }
  if (flags !== 0) return invalidPushAction();
  if (kind >= 1 && kind <= 5) {
    if (payload.length !== TICKET_LENGTH || !frame.subarray(6, 14).some(byte => byte !== 0)) {
      return invalidPushAction();
    }
    return { kind: kind as 1 | 2 | 3 | 4 | 5 };
  }
  return invalidPushAction();
}

async function performPushAction(
  action: { kind: 1 | 2 | 5 },
  operations: PushActionOperations,
  frame: Uint8Array,
): Promise<void> {
  if (action.kind === 1) return operations.requestPermission();
  if (action.kind === 2) return operations.prime(frame);
  return operations.clear(frame);
}

export async function executePushActions(operations: PushActionOperations): Promise<PushStatus> {
  let frame = await operations.poll();
  let latestError: unknown;

  for (let step = 0; step < MAX_STEPS; step += 1) {
    const action = parsePushAction(frame);
    if (action.kind === 0) {
      if (action.surfaceError) {
        throw latestError ?? new Error('Mesh push action failed');
      }
      return action.status;
    }
    latestError = undefined;
    if (action.kind === 3 || action.kind === 4) {
      frame = await operations.send(frame);
      continue;
    }
    let outcome: 0 | 1 = 0;
    try {
      await performPushAction({ kind: action.kind }, operations, frame);
    } catch (error) {
      latestError = error;
      outcome = 1;
    }
    frame = await operations.complete(frame, outcome);
  }
  throw new Error('Mesh push actions did not converge');
}
