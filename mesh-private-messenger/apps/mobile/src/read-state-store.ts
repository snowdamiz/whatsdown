import { File, Paths } from 'expo-file-system';
import type { LegacyJournal } from './journal-store';
import { parseReadState, type ReadState } from './read-state';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { journals } from './sealed-journals';

// The journals are sealed in the app's database (sealed-journals.ts). These files are
// where they were kept in the clear before that: read once, then removed.
const legacy = (name: string): LegacyJournal => {
  const file = new File(Paths.document, name);
  return { read: () => (file.exists ? file.textSync() : null), remove: () => { if (file.exists) file.delete(); } };
};

export const loadReadState = async (account: string): Promise<ReadState> =>
  parseReadState(await journals.load('read-state', legacy(`read-state-${account}.json`)));
export const saveReadState = (_account: string, state: ReadState): Promise<void> => journals.save('read-state', state);

export async function loadNotificationState(account: string): Promise<ReadState | null> {
  const kept = await journals.load('notification-state', legacy(`notification-state-${account}.json`));
  return kept === null ? null : parseReadState(kept);
}
export const saveNotificationState = (_account: string, state: ReadState): Promise<void> =>
  journals.save('notification-state', state);

// Whether this account tells people when it has read their messages. On unless turned off.
const receiptsFile = (account: string) => new File(Paths.document, `read-receipts-${account}`);
export function loadReadReceipts(account: string): boolean {
  const file = receiptsFile(account);
  return !file.exists || file.textSync() !== 'off';
}
export function saveReadReceipts(account: string, enabled: boolean): void {
  const file = receiptsFile(account);
  if (!file.exists) file.create();
  file.write(enabled ? 'on' : 'off');
}

// How much a notification shows; see NotificationPreview. Everything unless changed.
const previewFile = (account: string) => new File(Paths.document, `notification-preview-${account}`);
export function loadNotificationPreview(account: string): NotificationPreview {
  const file = previewFile(account);
  return parseNotificationPreview(file.exists ? file.textSync() : null);
}
export function saveNotificationPreview(account: string, preview: NotificationPreview): void {
  const file = previewFile(account);
  if (!file.exists) file.create();
  file.write(preview);
}

// How far each chat's other side has acknowledged; see ReceiptMarks. Timestamps of
// messages still in history only, and gone when they are.
export const loadReceiptMarks = async (account: string): Promise<Record<string, ReceiptMarks>> =>
  parseReceiptMarks(await journals.load('receipt-marks', legacy(`receipt-marks-${account}.json`)));
export const saveReceiptMarks = (_account: string, marks: Record<string, ReceiptMarks>): Promise<void> =>
  journals.save('receipt-marks', marks);
