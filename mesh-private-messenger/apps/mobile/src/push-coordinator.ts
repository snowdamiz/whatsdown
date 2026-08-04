export type PushStatus = 'disabled' | 'enabled' | 'pending-bind' | 'pending-unbind';
export type PushIntent = 'recover' | 'enable' | 'disable';

export type PushFlowOperations = {
  requestPermission: () => Promise<void>;
  prime: () => Promise<void>;
  clear: () => Promise<void>;
  prepareBind: () => Promise<Uint8Array>;
  prepareUnbind: () => Promise<Uint8Array>;
  sendBind: (wire: Uint8Array) => Promise<void>;
  sendUnbind: (wire: Uint8Array) => Promise<void>;
  commit: (wire: Uint8Array) => Promise<void>;
};

async function publish(
  wire: Uint8Array,
  send: (wire: Uint8Array) => Promise<void>,
  commit: (wire: Uint8Array) => Promise<void>,
): Promise<void> {
  if (wire.length === 0) return;
  await send(wire);
  await commit(wire);
}

async function bind(operations: PushFlowOperations, prime: boolean): Promise<void> {
  if (prime) await operations.prime();
  await publish(await operations.prepareBind(), operations.sendBind, operations.commit);
}

async function unbind(operations: PushFlowOperations): Promise<void> {
  const wire = await operations.prepareUnbind();
  let clearFailed = false;
  let clearError: unknown;
  try {
    await operations.clear();
  } catch (error) {
    clearFailed = true;
    clearError = error;
  }
  await publish(wire, operations.sendUnbind, operations.commit);
  if (clearFailed) throw clearError;
}

export async function coordinatePush(
  status: PushStatus,
  intent: PushIntent,
  operations: PushFlowOperations,
): Promise<void> {
  if (intent === 'disable') return unbind(operations);
  if (intent === 'enable') {
    await operations.requestPermission();
    if (status === 'pending-unbind') await unbind(operations);
    return bind(operations, status !== 'pending-bind');
  }
  if (status === 'pending-bind') return bind(operations, false);
  if (status === 'pending-unbind') return unbind(operations);
  if (status === 'enabled') return bind(operations, true);
}
