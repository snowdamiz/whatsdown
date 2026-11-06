import { createDesktopBackupCapability } from './desktop-backup-capability.ts';
import { assembleAppServices, type AppServiceScope, type AppLockControls } from './app-services.ts';
import type { DesktopOwnerClient } from './desktop-owner-client.ts';
import { createDesktopFilePort } from './desktop-file-port.ts';
import { createDesktopMailboxPort } from './desktop-mailbox-port.ts';
import { createDesktopPlatformPort } from './desktop-platform-port.ts';
import { createDesktopIncomingFiles } from './desktop-incoming-files.ts';
import { createDesktopPushServices } from './desktop-push-services.ts';
import { bindDesktopSessionEvents } from './desktop-session-events.ts';
import { createAttachmentRangeServices } from './attachment-range-io.ts';
import { createAttachmentFileServices } from './attachment-io.ts';
import { createAvatarServices } from './avatar-picker.ts';
import { createCreditPaymentServices } from './credit-payment-link.ts';
import { createNotificationServices } from './notification-delivery.ts';

export async function createScopedDesktopAppServices(client: DesktopOwnerClient) {
  const captured = client.snapshot();
  if (captured.state.phase !== 'activated') throw Error('desktop_services_unavailable');
  const session = await client.makeSession();
  const owner = captured.owner, epoch = captured.state.epoch;
  const cleanup: (() => Promise<boolean>)[] = [];
  let closing: Promise<boolean> | undefined;
  function requireCaptured() {
    session.assertCurrent();
    const current = client.snapshot();
    if (current.owner !== owner || current.state.epoch !== epoch || current.state.phase !== 'activated' ||
        current.state.policy !== captured.state.policy || current.state.capability !== captured.state.capability || !current.state.foreground) {
      throw Error('stale_epoch');
    }
  }
  function close() {
    const clean = session.dispose();
    closing ??= Promise.allSettled(cleanup.map(release => release())).then(results =>
      clean && results.every(result => result.status === 'fulfilled' && result.value));
    return closing;
  }
  try {
    requireCaptured();
    const files = createDesktopFilePort({ owner, epoch, scope: session });
    const platform = createDesktopPlatformPort({ owner, epoch, scope: session });
    const mailbox = createDesktopMailboxPort({ owner, epoch, scope: session });
    const scope: AppServiceScope = {
      runPrivate: session.runPrivate, assertCurrent: session.assertCurrent, onDispose: session.onDispose,
      invokeWallet: session.invokeWallet, copyProtectedText: session.copyProtectedText,
      invoke(symbol, request) {
        switch (symbol) {
          case 'mesh_messenger_mailbox_stream_open': return mailbox.open(request);
          case 'mesh_messenger_mailbox_stream_poll': return mailbox.poll(request);
          case 'mesh_messenger_mailbox_stream_close': return mailbox.close(request);
          default: return session.invoke(symbol, request);
        }
      },
    };
    const databasePath = await platform.databasePath();
    requireCaptured();
    const intake = createDesktopIncomingFiles({ owner, epoch, scope: session, files });
    cleanup.push(intake.close);
    let push: ReturnType<typeof createDesktopPushServices> | undefined;
    const controls: AppLockControls = captured.state.capability === 'available'
      ? { supportsAppLock: true, appLockEnabled: captured.state.policy === 'enabled',
        async lockApp() { requireCaptured(); await client.lock(epoch); },
        async setAppLockEnabled(enabled) { requireCaptured(); await client.setEnabled(enabled, epoch); } }
      : { supportsAppLock: false, appLockEnabled: false };
    const services = assembleAppServices({ scope, databasePath, backups: createDesktopBackupCapability(session, epoch, files), controls,
      createPlatform(bindings) {
        const ranges = createAttachmentRangeServices({ ...scope, ...files });
        push = createDesktopPushServices({ databasePath, scope: session, port: platform, loadProfile: bindings.load_profile_export });
        cleanup.push(push.close);
        return { ranges, files: createAttachmentFileServices({ ...scope, ...files, ...ranges }, { previewTransport: 'desktop', incoming: intake }),
          avatar: createAvatarServices({ ...scope, ...files }), payments: createCreditPaymentServices({ ...scope, ...platform }),
          notifications: createNotificationServices({ ...scope, ...platform }), push: push.services, legacyPreferences: platform };
      },
    });
    if (!push) throw Error('desktop_services_unavailable');
    const events = await bindDesktopSessionEvents({ scope: session, events: [
      { name: 'app-lock-files', receive: intake.receive }, { name: 'app-lock-notice-pending', receive: push.receive },
    ] });
    cleanup.push(events.close);
    requireCaptured();
    return Object.freeze({ services, windowAction: platform.windowAction, close });
  } catch {
    await close();
    throw Error('desktop_services_unavailable');
  }
}
