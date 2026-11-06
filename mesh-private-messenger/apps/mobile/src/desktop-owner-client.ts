import { isDesktopOwner, parseDesktopLockSnapshot, type DesktopEpoch, type DesktopLockSnapshot, type DesktopOwner, type DesktopRequest } from './desktop-lock-protocol.ts';
import { createDesktopPrivateSession, type DesktopPrivatePort, type DesktopPrivateSession } from './desktop-private-session.ts';

export type DesktopLockCommand = 'app_lock_bind' | 'app_lock_state' | 'app_lock_activate' |
  'app_lock_lock' | 'app_lock_set_enabled' | 'app_lock_cancel' | 'app_lock_release';
export type DesktopLockHeaders = Readonly<Record<string, string>>;
export type DesktopOwnerTransport = Readonly<{
  listen(receive: (payload: unknown) => void): Promise<() => void | Promise<void>>;
  command(name: DesktopLockCommand, body: Readonly<Record<string, unknown>>, headers: DesktopLockHeaders): Promise<unknown>;
  privatePort(owner: DesktopOwner, epoch: DesktopEpoch): DesktopPrivatePort;
}>;
export type DesktopOwnerOptions = Readonly<{
  signal: AbortSignal;
  onSnapshot(snapshot: DesktopLockSnapshot): void;
  onRetired(): void;
}>;
export type DesktopOwnerClient = Readonly<{
  snapshot(): DesktopLockSnapshot;
  refresh(): Promise<DesktopLockSnapshot>;
  activate(epoch: DesktopEpoch): Promise<DesktopLockSnapshot>;
  lock(epoch: DesktopEpoch): Promise<void>;
  setEnabled(enabled: boolean, epoch: DesktopEpoch): Promise<void>;
  cancel(request: DesktopRequest): Promise<void>;
  makeSession(): Promise<DesktopPrivateSession>;
  close(): Promise<boolean>;
}>;

function ownerOf(input: unknown): DesktopOwner | undefined {
  return input !== null && typeof input === 'object' && 'owner' in input && isDesktopOwner(input.owner)
    ? input.owner : undefined;
}
function sameState(a: DesktopLockSnapshot['state'], b: DesktopLockSnapshot['state']): boolean {
  return a.epoch === b.epoch && a.policy === b.policy && a.phase === b.phase &&
    a.capability === b.capability && a.foreground === b.foreground && a.request === b.request;
}
function started(input: unknown): boolean {
  return input !== null && typeof input === 'object' && !Array.isArray(input) &&
    Reflect.ownKeys(input).length === 1 && Object.hasOwn(input, 'kind') && 'kind' in input && input.kind === 'started';
}

export async function bindDesktopOwner(transport: DesktopOwnerTransport, options: DesktopOwnerOptions): Promise<DesktopOwnerClient> {
  const command = transport.command.bind(transport);
  const listen = transport.listen.bind(transport);
  const privatePort = transport.privatePort.bind(transport);
  const { signal, onSnapshot, onRetired } = options;
  let open = true;
  let clean = true;
  let ready = false;
  let owner: DesktopOwner | undefined;
  let current: DesktopLockSnapshot | undefined;
  let unsubscribe: (() => void | Promise<void>) | undefined;
  let closing: Promise<boolean> | undefined;
  let setupFinished = () => {};
  const setup = new Promise<void>(resolve => { setupFinished = resolve; });
  const sessions = new Set<DesktopPrivateSession>();

  function requireOpen() { if (!open) throw Error('desktop_owner_closed'); }
  function snapshot() {
    requireOpen();
    if (!current) throw Error('desktop_owner_not_ready');
    return current;
  }
  function requireEpoch(epoch: DesktopEpoch) {
    const state = snapshot();
    if (state.state.epoch !== epoch) throw Error('stale_epoch');
    return state;
  }
  function active(epoch?: DesktopEpoch) {
    const state = epoch === undefined ? snapshot() : requireEpoch(epoch);
    if (state.state.phase !== 'activated') throw Error('desktop_owner_inactive');
    return state;
  }
  function headers(epoch?: DesktopEpoch): DesktopLockHeaders {
    if (!owner) throw Error('desktop_owner_not_ready');
    return Object.freeze({ 'X-Morse-Lock-Owner': owner,
      ...(epoch === undefined ? {} : { 'X-Morse-Lock-Epoch': epoch }) });
  }
  function retireSessions() {
    const previous = [...sessions]; sessions.clear();
    for (const session of previous) if (!session.dispose()) clean = false;
  }
  function retire() {
    if (!open) return;
    open = false;
    signal.removeEventListener('abort', abort);
    retireSessions();
    try { onRetired(); } catch { clean = false; }
  }
  async function cleanup() {
    // A late bind reply still owns a native resource. Wait for setup to capture
    // that exact binding even when local authority was already retired.
    await setup;
    const remove = unsubscribe; unsubscribe = undefined;
    const pending: Promise<unknown>[] = [];
    if (remove) { try { pending.push(Promise.resolve(remove())); } catch { clean = false; } }
    if (owner) {
      try {
        pending.push(command('app_lock_release', {}, headers()).then(reply => { if (reply !== null) clean = false; }));
      } catch { clean = false; }
    }
    // Start both disposals before awaiting either one. A delayed or failed
    // listener removal must not retain the native page binding.
    for (const outcome of await Promise.allSettled(pending)) if (outcome.status === 'rejected') clean = false;
    return clean;
  }
  function close() {
    retire();
    closing ??= cleanup();
    return closing;
  }
  function abort() { void close(); }
  function invalidReply(): never {
    void close();
    throw Error('invalid_desktop_lock_reply');
  }
  function publish() {
    if (!ready || !open || !current) return;
    try { onSnapshot(current); } catch { void close(); }
  }
  function accept(input: unknown) {
    const next = parseDesktopLockSnapshot(input);
    if (next.owner !== owner) throw Error('invalid_desktop_lock_state');
    if (current) {
      const before = BigInt(current.revision), after = BigInt(next.revision);
      if (after < before) return;
      if (after === before) {
        if (!sameState(current.state, next.state)) throw Error('invalid_desktop_lock_state');
        return;
      }
    }
    const previous = current; current = next;
    if (previous && (previous.state.epoch !== next.state.epoch || next.state.phase !== 'activated')) retireSessions();
    publish();
  }
  function receive(input: unknown) {
    if (!open || !owner) return;
    try {
      if (ownerOf(input) !== owner) return;
      accept(input);
    } catch { void close(); }
  }
  async function refresh() {
    requireOpen();
    try {
      const input = await command('app_lock_state', {}, headers());
      requireOpen();
      accept(input);
      return snapshot();
    } catch (error) { void close(); throw error; }
  }
  async function unit(name: 'app_lock_activate' | 'app_lock_lock' | 'app_lock_cancel', body: Readonly<Record<string, unknown>>, epoch?: DesktopEpoch) {
    requireOpen();
    if (epoch !== undefined) requireEpoch(epoch);
    const reply = await command(name, body, headers(epoch));
    requireOpen();
    if (reply !== null) invalidReply();
  }
  const client: DesktopOwnerClient = Object.freeze({
    snapshot, refresh, close,
    async activate(epoch: DesktopEpoch) {
      await unit('app_lock_activate', {}, epoch);
      requireEpoch(epoch);
      await refresh();
      return active(epoch);
    },
    lock: (epoch: DesktopEpoch) => unit('app_lock_lock', {}, epoch),
    async setEnabled(enabled: boolean, epoch: DesktopEpoch) {
      requireEpoch(epoch);
      const reply = await command('app_lock_set_enabled', { enabled }, headers(epoch));
      requireOpen();
      if (!started(reply)) invalidReply();
    },
    cancel: (request: DesktopRequest) => unit('app_lock_cancel', { request }),
    async makeSession() {
      const captured = active();
      const session = createDesktopPrivateSession(privatePort(captured.owner, captured.state.epoch));
      sessions.add(session);
      session.onDispose(() => { sessions.delete(session); });
      try {
        active(captured.state.epoch);
        await session.assertActive();
        // This check is in the caller's continuation: a nested microtask can
        // retire between assertActive's last check and this await resuming.
        active(captured.state.epoch);
        return session;
      } catch (error) {
        if (!session.dispose()) clean = false;
        throw error;
      }
    },
  });

  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  let failure: { error: unknown } | undefined;
  try {
    requireOpen();
    unsubscribe = await listen(receive);
    requireOpen();
    const bound = await command('app_lock_bind', {}, {});
    // Capture the only cleanup identity before testing for local cancellation.
    owner = ownerOf(bound);
    requireOpen();
    accept(bound);
    await refresh();
    requireOpen();
    ready = true;
    publish();
    requireOpen();
  } catch (error) { failure = { error }; }
  finally { setupFinished(); }
  if (failure) { await close(); throw failure.error; }
  return client;
}
