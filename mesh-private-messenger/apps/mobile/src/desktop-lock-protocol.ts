export type DesktopOwner = string & { readonly __brand: 'DesktopOwner' };
export type DesktopEpoch = string & { readonly __brand: 'DesktopEpoch' };
export type DesktopRequest = string & { readonly __brand: 'DesktopRequest' };
export type DesktopSequence = string & { readonly __brand: 'DesktopSequence' };
export type DesktopLockSnapshot = Readonly<{
  version: 1;
  owner: DesktopOwner;
  revision: DesktopSequence;
  state: Readonly<{
    epoch: DesktopEpoch;
    policy: 'unknown' | 'disabled' | 'enable_pending' | 'enabled' | 'disable_pending';
    phase: 'booting' | 'disabled' | 'locked' | 'authenticating' | 'awaiting_activation' | 'activated' | 'error';
    capability: 'unknown' | 'unavailable' | 'available';
    foreground: boolean;
    request?: DesktopRequest;
  }>;
}>;

const invalid = () => Error('invalid_desktop_lock_state');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function isDesktopOwner(value: unknown): value is DesktopOwner {
  return typeof value === 'string' && value.length === 36 && uuid.test(value);
}
function isSequence(value: unknown): value is DesktopSequence {
  if (typeof value !== 'string' || value.length < 1 || value.length > 20 || !/^[0-9]+$/.test(value)) return false;
  const number = BigInt(value);
  return number <= 18446744073709551615n && number.toString() === value;
}
function isNativeStamp(value: unknown): boolean {
  return typeof value === 'string' && value.length >= 38 && value.length <= 57 && value[36] === '/' &&
    isDesktopOwner(value.slice(0, 36)) && isSequence(value.slice(37));
}
export function isDesktopEpoch(value: unknown): value is DesktopEpoch { return isNativeStamp(value); }
export function isDesktopRequest(value: unknown): value is DesktopRequest { return isNativeStamp(value); }
function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) {
  if (required.some(key => !Object.hasOwn(value, key)) ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || (!required.includes(key) && !optional.includes(key)))) throw invalid();
}
function policy(value: unknown): DesktopLockSnapshot['state']['policy'] {
  switch (value) {
    case 'unknown': case 'disabled': case 'enable_pending': case 'enabled': case 'disable_pending': return value;
    default: throw invalid();
  }
}
function phase(value: unknown): DesktopLockSnapshot['state']['phase'] {
  switch (value) {
    case 'booting': case 'disabled': case 'locked': case 'authenticating': case 'awaiting_activation': case 'activated': case 'error': return value;
    default: throw invalid();
  }
}
function capability(value: unknown): DesktopLockSnapshot['state']['capability'] {
  switch (value) {
    case 'unknown': case 'unavailable': case 'available': return value;
    default: throw invalid();
  }
}

export function parseDesktopLockSnapshot(input: unknown): DesktopLockSnapshot {
  if (!isRecord(input)) throw invalid();
  exactKeys(input, ['version', 'owner', 'revision', 'state']);
  const { version, owner, revision, state } = input;
  if (version !== 1 || !isDesktopOwner(owner) || !isSequence(revision) || !isRecord(state)) throw invalid();
  exactKeys(state, ['epoch', 'policy', 'phase', 'capability', 'foreground'], ['request']);
  const { epoch, foreground } = state;
  if (!isDesktopEpoch(epoch) || typeof foreground !== 'boolean') throw invalid();
  let request: DesktopRequest | undefined;
  if (Object.hasOwn(state, 'request')) {
    const candidate = state.request;
    if (!isDesktopRequest(candidate)) throw invalid();
    request = candidate;
  }
  const result: DesktopLockSnapshot = {
    version: 1, owner, revision,
    state: Object.freeze({ epoch, policy: policy(state.policy), phase: phase(state.phase),
      capability: capability(state.capability), foreground, ...(request === undefined ? {} : { request }) }),
  };
  return Object.freeze(result);
}
