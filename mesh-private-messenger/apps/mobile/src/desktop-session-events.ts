import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DesktopPrivateSession } from './desktop-private-session.ts';

export type DesktopSessionEvent = 'app-lock-notice-pending' | 'app-lock-files';
export async function bindDesktopSessionEvents({ scope, events }: {
  scope: Pick<DesktopPrivateSession, 'assertCurrent' | 'onDispose'>;
  events: readonly { name: DesktopSessionEvent; receive(payload: unknown): void }[];
}) {
  scope.assertCurrent();
  let open = true;
  let closing: Promise<boolean> | undefined;
  let finishSetup = () => {};
  const setup = new Promise<void>(resolve => { finishSetup = resolve; });
  const pending: Promise<UnlistenFn>[] = [];
  let removeDispose = () => {};
  async function cleanup() {
    await setup;
    const installed = await Promise.allSettled(pending);
    const removed = await Promise.allSettled(installed.flatMap(result => result.status === 'fulfilled'
      ? [(async () => { await result.value(); })()] : []));
    return removed.every(result => result.status === 'fulfilled');
  }
  function close() {
    open = false;
    removeDispose();
    closing ??= cleanup();
    return closing;
  }
  let failure: { error: unknown } | undefined;
  try {
    removeDispose = scope.onDispose(() => { void close(); });
    for (const { name, receive } of events) {
      pending.push(listen<unknown>(name, value => {
        if (!open) return;
        try { scope.assertCurrent(); receive(value.payload); }
        catch { void close(); }
      }));
    }
    await Promise.all(pending);
    scope.assertCurrent();
    if (!open) throw Error('stale_epoch');
  } catch (error) { failure = { error }; }
  finally { finishSetup(); }
  if (failure) {
    await close();
    scope.assertCurrent();
    throw failure.error;
  }
  return Object.freeze({ close });
}
