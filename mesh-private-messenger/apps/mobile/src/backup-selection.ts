import type { BackupAttachmentPolicy, BackupScope, BackupSelection } from './backup-native-codec';

export type BackupCreationChoice =
  | Readonly<{ kind: 'text' }>
  | Readonly<{ kind: 'content'; policy: BackupAttachmentPolicy }>;

function dayBound(value: string, end: boolean): number | null {
  const text = value.trim();
  if (text === '') return null;
  const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!parts) throw new Error('invalid_backup_date');
  const year = Number(parts[1]), month = Number(parts[2]), day = Number(parts[3]);
  const start = new Date(year, month - 1, day);
  if (year < 1970 || start.getFullYear() !== year || start.getMonth() !== month - 1 || start.getDate() !== day) {
    throw new Error('invalid_backup_date');
  }
  const time = end ? new Date(year, month - 1, day + 1).getTime() - 1 : start.getTime();
  return Math.max(0, time);
}

export function backupSelections({ scopes, fromDay, throughDay }: {
  scopes: readonly BackupScope[];
  fromDay: string;
  throughDay: string;
}): BackupSelection[] {
  if (scopes.length < 1 || scopes.length > 32) throw new Error('invalid_backup_selection');
  const from = dayBound(fromDay, false), through = dayBound(throughDay, true);
  if (from !== null && through !== null && from > through) throw new Error('invalid_backup_date_range');
  return scopes.map(scope => ({ scope: { ...scope, id: new Uint8Array(scope.id) },
    fromTime: from === null ? null : String(from), throughTime: through === null ? null : String(through) }));
}
