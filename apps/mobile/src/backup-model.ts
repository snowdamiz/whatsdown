// What the app knows about encrypted backups (protocol/backup-wire-v1.md,
// version 2) without touching the network or the device's stores.

import { parseAppearance, type Appearance } from './appearance.ts';
import { Reader, decodeUtf8 } from './codec.ts';
import { parseDeclined } from './community-requests.ts';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy.ts';
import { parseReadState, type ReadState } from './read-state.ts';
import { parseReceiptMarks, type ReceiptMarks } from './receipts.ts';

export type BackupStatus = { on: boolean; lastBackupAt: number };
export type RestoredBackup = { conversations: number; groups: number; createdAt: number; appState: Uint8Array };

const readU64 = (value: Uint8Array): number => {
  if (value.length !== 8) throw new Error('Invalid u64');
  return Number(new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0));
};
const readU32 = (value: Uint8Array): number => {
  if (value.length !== 4) throw new Error('Invalid u32');
  return new DataView(value.buffer, value.byteOffset, 4).getUint32(0);
};

export function parseBackupStatus(input: Uint8Array): BackupStatus {
  const reader = new Reader(input);
  const state = reader.vector(1);
  const last = reader.vector(8);
  reader.finish();
  return { on: state[0] === 2, lastBackupAt: readU64(last) };
}

export function parseRestored(input: Uint8Array): RestoredBackup {
  const reader = new Reader(input);
  const conversations = readU32(reader.vector(4));
  const groups = readU32(reader.vector(4));
  const createdAt = readU64(reader.vector(8));
  const appState = reader.vector(4_194_304);
  reader.vector(4);
  reader.finish();
  return { conversations, groups, createdAt, appState };
}

// The core names objects by UTC day, so a day here is one too.
const utcDay = (at: number): number => Math.floor(at / 86_400_000);

export const backupDue = (status: BackupStatus, now: number): boolean =>
  status.on && (status.lastBackupAt === 0 || utcDay(status.lastBackupAt) < utcDay(now));

export function backupLine(status: BackupStatus, now: number): string {
  if (!status.on) return 'Off';
  if (!status.lastBackupAt) return 'On · No backup yet';
  const at = new Date(status.lastBackupAt);
  const when = utcDay(status.lastBackupAt) === utcDay(now)
    ? `today at ${at.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`
    : at.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  return `On · Last backup ${when}`;
}

// What the app keeps for itself rides in the backup as one opaque record: its
// settings, and which messages were read, acknowledged, or declined.
export type AppState = {
  v: 1;
  readState: ReadState;
  receiptMarks: Record<string, ReceiptMarks>;
  declined: Record<string, string[]>;
  readReceipts: boolean;
  notificationPreview: NotificationPreview;
  appearance: Appearance;
};

export const encodeAppState = (state: AppState): Uint8Array => new TextEncoder().encode(JSON.stringify(state));

export function decodeAppState(input: Uint8Array): AppState | null {
  try {
    const value = JSON.parse(decodeUtf8(input)) as Partial<AppState> | null;
    if (!value || value.v !== 1) return null;
    return {
      v: 1,
      readState: parseReadState(JSON.stringify(value.readState ?? {})),
      receiptMarks: parseReceiptMarks(JSON.stringify(value.receiptMarks ?? {})),
      declined: parseDeclined(JSON.stringify(value.declined ?? {})),
      readReceipts: value.readReceipts !== false,
      notificationPreview: parseNotificationPreview(value.notificationPreview),
      appearance: parseAppearance(value.appearance),
    };
  } catch {
    return null;
  }
}

// Marks this device already has win: they are newer than any backup.
const fill = <T>(local: Record<string, T>, restored: Record<string, T>): Record<string, T> => ({ ...restored, ...local });

export const mergeAppState = (local: AppState, restored: AppState): AppState => ({
  ...restored,
  readState: fill(local.readState, restored.readState),
  receiptMarks: fill(local.receiptMarks, restored.receiptMarks),
  declined: fill(local.declined, restored.declined),
});

const messages: [RegExp, string][] = [
  [/backup_not_found/, 'No backup from the past week opens with that code. Check the code, or turn backups on again.'],
  [/backup_code_mismatch/, 'That isn’t the recovery code. Check it and try again.'],
  [/backup_account_mismatch/, 'That backup belongs to another account.'],
  [/backup_expired/, 'That backup has expired. Backups are kept for six days.'],
  [/backup_damaged|backup_incomplete/, 'That backup is damaged. Make a new one on your other device and try again.'],
  [/backup_restore_needs_account/, 'Link this device to your account first, then restore.'],
  [/backup_has_no_account_key/, 'That backup was made on a linked device, so it can’t bring the account back on its own. Link this device from another device of the account, then restore.'],
  [/account_already_exists/, 'This device already has an account. Restore from Settings → Backups instead.'],
  [/device_set_transparency_unverified|transparency_/, 'The directory’s record of your devices couldn’t be checked. Try again in a minute.'],
  [/registration_refused/, 'The directory didn’t take this device. Try again in a minute.'],
  [/backup_limit_reached/, 'You’ve backed up four times today. The next backup can be made tomorrow.'],
  [/backup_too_large/, 'There’s more than 16 MB to back up, which a backup can’t hold yet.'],
  [/Network request failed|Server returned 5\d\d|aborted/i, 'No connection. Try again.'],
];

export function backupErrorMessage(error: unknown): string {
  const text = String(error instanceof Error ? error.message : error);
  return messages.find(([pattern]) => pattern.test(text))?.[1] ?? text.replace(/^Error:\s*/, '');
}
