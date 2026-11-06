import type { AppLockSession } from './app-lock';
import { createBackupServices, type BackupServices } from './backup-services';
import { createBackupFileServices, type BackupFileServices } from './backup-file-io';

export type AvailableBackups = Readonly<{
  kind: 'available'; scope: AppLockSession; operations: BackupServices; files: BackupFileServices;
}>;
export type BackupCapability = AvailableBackups | Readonly<{ kind: 'unavailable' }>;

export function createBackupCapability(scope: AppLockSession): BackupCapability {
  scope.assertActive();
  const available: AvailableBackups = {
    kind: 'available', scope,
    operations: Object.freeze(createBackupServices(scope)),
    files: Object.freeze(createBackupFileServices(scope)),
  };
  return Object.freeze(available);
}
