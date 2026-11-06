import type { BackupCapability } from './backup-capability';
import { createBackupServices } from './backup-services';
import { createBackupFileServices } from './backup-file-io';
import type { DesktopPrivateSession } from './desktop-private-session';
import type { createDesktopFilePort } from './desktop-file-port';

export function createDesktopBackupCapability(session: DesktopPrivateSession, epoch: string,
  files: ReturnType<typeof createDesktopFilePort>): BackupCapability {
  // Synchronous UI checks only retire local work. All data/OS operations still
  // use the immutable native owner/epoch through session.invoke and files.
  const scope = Object.freeze({ epoch, assertActive: session.assertCurrent,
    onDispose: session.onDispose, copyProtectedText: session.copyProtectedText });
  scope.assertActive();
  return Object.freeze({ kind: 'available', scope,
    operations: Object.freeze(createBackupServices({ ...scope, invoke: session.invoke })),
    files: Object.freeze(createBackupFileServices({ ...scope, ...files })),
  });
}
