import { t } from './i18n.ts';
import { protectedHandle, protectedMetadata } from './app-lock.ts';
import type { IncomingAttachmentReader, IncomingFileHandlers } from './attachment-io.ts';
import type { AttachmentSelection } from './attachment-selections.ts';
import type { createDesktopFilePort } from './desktop-file-port.ts';
import type { DesktopOwner, DesktopEpoch } from './desktop-lock-protocol.ts';
import type { DesktopPrivateSession } from './desktop-private-session.ts';

type Subscription = {
  active: boolean;
  handle?: string;
  dirty: boolean;
  draining: boolean;
  handlers: IncomingFileHandlers;
  read: IncomingAttachmentReader;
};
type FileHint = { subscription: string } & ({ kind: 'sources' } | { kind: 'dragging'; dragging: boolean });
function fileHint(payload: unknown, owner: DesktopOwner, epoch: DesktopEpoch): FileHint | undefined {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      !('version' in payload) || payload.version !== 1 || !('owner' in payload) || payload.owner !== owner ||
      !('epoch' in payload) || payload.epoch !== epoch || !('subscription' in payload) ||
      typeof payload.subscription !== 'string' || !('kind' in payload)) return;
  const keys = ['version', 'owner', 'epoch', 'subscription', 'kind'];
  if (payload.kind === 'dragging') keys.push('dragging');
  if (Reflect.ownKeys(payload).length !== keys.length || keys.some(key => !Object.hasOwn(payload, key))) return;
  if (payload.kind === 'sources') return { subscription: payload.subscription, kind: 'sources' };
  if (payload.kind === 'dragging' && 'dragging' in payload && typeof payload.dragging === 'boolean') {
    return { subscription: payload.subscription, kind: 'dragging', dragging: payload.dragging };
  }
}
export function createDesktopIncomingFiles({ owner, epoch, scope, files }: {
  owner: DesktopOwner; epoch: DesktopEpoch;
  scope: Pick<DesktopPrivateSession, 'runPrivate' | 'assertCurrent' | 'onDispose'>;
  files: ReturnType<typeof createDesktopFilePort>;
}) {
  scope.assertCurrent();
  const subscriptions = new Set<Subscription>(), jobs = new Set<Promise<void>>();
  let open = true, clean = true;
  let closing: Promise<boolean> | undefined;
  let removeDispose = () => {};
  function current(subscription: Subscription) {
    if (!open || !subscription.active) return false;
    try { scope.assertCurrent(); return true; } catch { return false; }
  }
  function start(operation: () => Promise<void>) {
    const job = Promise.resolve().then(operation).catch(() => { clean = false; });
    jobs.add(job);
    void job.then(() => { jobs.delete(job); });
  }
  function release(handle: string) {
    start(() => files.cleanupProtectedFile('unsubscribeIncoming', { version: 1, handle }));
  }
  function stop(subscription: Subscription) {
    if (!subscription.active) return;
    subscription.active = false;
    subscriptions.delete(subscription);
    if (subscription.handle) release(subscription.handle);
  }
  async function error(subscription: Subscription) {
    if (!current(subscription)) return;
    try {
      await scope.runPrivate(async () => {});
      if (current(subscription)) subscription.handlers.onError(t('Those files could not be read.'));
    } catch { /* A retired composer receives neither file data nor errors. */ }
  }
  function drain(subscription: Subscription) {
    subscription.dirty = true;
    if (!current(subscription) || !subscription.handle || subscription.draining) return;
    subscription.draining = true;
    const handle = subscription.handle;
    start(async () => {
      try {
        while (subscription.dirty && current(subscription)) {
          subscription.dirty = false;
          let selected: AttachmentSelection[] = [];
          try {
            selected = await subscription.read(handle);
            if (!selected.length || !current(subscription)) continue;
            await scope.runPrivate(async () => {});
            if (!current(subscription)) continue;
            if (subscription.handlers.onSelections) subscription.handlers.onSelections(selected);
            else subscription.handlers.onFiles(selected.map(file => {
              if (file.kind !== 'small') throw Error('attachment_too_large');
              return { filename: file.filename, mimeType: file.mimeType, bytes: file.bytes };
            }));
            selected = [];
          } catch {
            for (const selection of selected) selection.dispose();
            selected = [];
            await error(subscription);
          } finally { for (const selection of selected) selection.dispose(); }
        }
      } finally { subscription.draining = false; }
    });
  }
  function close() {
    open = false;
    removeDispose();
    for (const subscription of subscriptions) stop(subscription);
    closing ??= (async () => { while (jobs.size) await Promise.all([...jobs]); return clean; })();
    return closing;
  }
  removeDispose = scope.onDispose(() => { void close(); });
  return Object.freeze({
    listen({ onSelections, onFiles, onDragging, onError }: IncomingFileHandlers, read: IncomingAttachmentReader) {
      scope.assertCurrent();
      if (!open) throw Error('stale_epoch');
      const subscription: Subscription = { active: true, dirty: false, draining: false,
        handlers: { onSelections, onFiles, onDragging, onError }, read };
      subscriptions.add(subscription);
      start(async () => {
        if (!current(subscription)) return;
        try {
          const reply = await files.protectedFile('subscribeIncoming', { version: 1 });
          const handle = protectedHandle(protectedMetadata(reply, ['handle']).handle);
          if (!current(subscription)) { release(handle); return; }
          subscription.handle = handle;
          // Native can queue the first drop before its registration reply arrives.
          drain(subscription);
        } catch { await error(subscription); stop(subscription); }
      });
      return () => { stop(subscription); };
    },
    receive(payload: unknown) {
      if (!open) return;
      const hint = fileHint(payload, owner, epoch);
      if (!hint) return;
      for (const subscription of subscriptions) {
        if (subscription.handle !== hint.subscription || !current(subscription)) continue;
        if (hint.kind === 'sources') drain(subscription);
        else start(async () => {
          try {
            await scope.runPrivate(async () => {});
            if (current(subscription)) subscription.handlers.onDragging(hint.dragging);
          } catch { /* Ignore a retired native drag hint. */ }
        });
      }
    },
    close,
  });
}
