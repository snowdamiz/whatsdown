import { utf8 } from './codec.ts';
import type { AppPlatformServices } from './app-services.ts';
import type { createDesktopPlatformPort } from './desktop-platform-port.ts';
import type { DesktopPrivateSession } from './desktop-private-session.ts';
import type { ScopedBindings } from '../modules/mesh-messenger/scoped.ts';
type Options = {
  databasePath: string;
  scope: Pick<DesktopPrivateSession, 'runPrivate' | 'assertCurrent' | 'onDispose'>;
  port: Pick<ReturnType<typeof createDesktopPlatformPort>, 'notificationBinding' | 'takeNotificationIntent'>;
  loadProfile: ScopedBindings['load_profile_export'];
};
export function createDesktopPushServices({ databasePath, port, loadProfile, scope }: Options) {
  scope.assertCurrent();
  const listeners = new Set<{ active: boolean; open(scope: string): void; inbox(): void }>();
  const changes = new Set<() => void>(), jobs = new Set<Promise<unknown>>();
  let open = true, dirty = false, draining = false;
  let closing: Promise<boolean> | undefined;
  let removeDispose = () => {};
  function requireOpen() { scope.assertCurrent(); if (!open) throw Error('stale_epoch'); }
  function track<T>(job: Promise<T>) {
    jobs.add(job);
    void job.then(() => { jobs.delete(job); }, () => { jobs.delete(job); });
    return job;
  }
  function binding(operation: 'status' | 'enable' | 'disable', path: string, profile?: Uint8Array) {
    const captured = profile?.slice();
    return track((async () => {
      let held: Uint8Array | undefined = captured;
      try {
        requireOpen();
        if (path !== databasePath) throw Error('account_state_changed');
        const result = await scope.runPrivate(async () => {
          held ??= await loadProfile(utf8(databasePath));
          requireOpen();
          return port.notificationBinding(operation, held);
        });
        requireOpen();
        if (operation !== 'status') {
          for (const listener of [...changes]) {
            requireOpen();
            if (changes.has(listener)) { try { listener(); } catch { /* Observer errors do not undo a native preference change. */ } }
          }
        }
        requireOpen();
        return result;
      } catch (error) { requireOpen(); throw error; }
      finally { held?.fill(0); }
    })());
  }
  function drain() {
    dirty = true;
    if (!open || !listeners.size || draining) return;
    draining = true;
    track((async () => {
      try {
        while (open && listeners.size && dirty) {
          dirty = false;
          const captured = [...listeners];
          const intent = await scope.runPrivate(() => port.takeNotificationIntent());
          requireOpen();
          for (const listener of captured) {
            requireOpen();
            if (!listener.active) continue;
            try {
              if (intent.kind === 'scope') listener.open(intent.scope);
              else if (intent.kind === 'inbox') listener.inbox();
            } catch { /* A closed or failed observer cannot redirect this intent. */ }
          }
        }
      } catch { /* Native retains authority; private failures are not public hints. */ }
      finally { draining = false; }
    })());
  }
  function close() {
    open = false;
    removeDispose();
    for (const listener of listeners) listener.active = false;
    listeners.clear(); changes.clear();
    closing ??= (async () => { while (jobs.size) await Promise.allSettled([...jobs]); return true; })();
    return closing;
  }
  removeDispose = scope.onDispose(() => { void close(); });
  const services = Object.freeze({
    getPushStatus: (path: string, profile?: Uint8Array) => binding('status', path, profile),
    recoverPushBinding: (path: string, profile: Uint8Array) => binding('status', path, profile),
    enablePushBinding: (path: string, profile: Uint8Array) => binding('enable', path, profile),
    disablePushBinding: (path: string, profile: Uint8Array) => binding('disable', path, profile),
    // Desktop uses local OS notifications and has no remote wake registration.
    listenForGenericWakeups: (_listener: () => void) => { requireOpen(); return () => {}; },
    listenForPushRegistrationChanges(listener: () => void) {
      requireOpen(); changes.add(listener); return () => { changes.delete(listener); };
    },
    listenForNotificationOpens(open: (scope: string) => void, inbox: () => void = () => {}) {
      requireOpen();
      const listener = { active: true, open, inbox };
      listeners.add(listener); drain();
      return () => { listener.active = false; listeners.delete(listener); };
    },
  } satisfies AppPlatformServices['push']);
  return Object.freeze({ services, receive(payload: unknown) {
    if (payload && typeof payload === 'object' && !Array.isArray(payload) && Object.hasOwn(payload, 'version') &&
        'version' in payload && payload.version === 1 && Reflect.ownKeys(payload).length === 1) drain();
  }, close });
}
