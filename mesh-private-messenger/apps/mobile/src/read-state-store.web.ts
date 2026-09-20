import type { LegacyJournal } from './journal-store';
import { parseReadState, type ReadState } from './read-state';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { journals } from './sealed-journals';
import { databasePath } from './storage';

// The journals are sealed in the app's database (sealed-journals.ts). These keys are
// where they were kept in the clear before that: read once, then removed.
const legacy = (key: string): LegacyJournal =>
  ({ read: () => localStorage.getItem(key), remove: () => localStorage.removeItem(key) });

export const loadReadState = async (account: string): Promise<ReadState> =>
  parseReadState(await journals.load('read-state', legacy(`${databasePath}/read-state/v1/${account}`)));
export const saveReadState = (_account: string, state: ReadState): Promise<void> => journals.save('read-state', state);

export async function loadNotificationState(account: string): Promise<ReadState | null> {
  const kept = await journals.load('notification-state', legacy(`${databasePath}/notification-state/v1/${account}`));
  return kept === null ? null : parseReadState(kept);
}
export const saveNotificationState = (_account: string, state: ReadState): Promise<void> =>
  journals.save('notification-state', state);

// Whether this account tells people when it has read their messages. On unless turned off.
const receiptsKey = (account: string) => `${databasePath}/read-receipts/v1/${account}`;
export const loadReadReceipts = (account: string): boolean => localStorage.getItem(receiptsKey(account)) !== 'off';
export function saveReadReceipts(account: string, enabled: boolean): void {
  localStorage.setItem(receiptsKey(account), enabled ? 'on' : 'off');
}

// How much a notification shows; see NotificationPreview. Everything unless changed.
const previewKey = (account: string) => `${databasePath}/notification-preview/v1/${account}`;
export const loadNotificationPreview = (account: string): NotificationPreview =>
  parseNotificationPreview(localStorage.getItem(previewKey(account)));
export function saveNotificationPreview(account: string, preview: NotificationPreview): void {
  localStorage.setItem(previewKey(account), preview);
}

// How far each chat's other side has acknowledged; see ReceiptMarks.
export const loadReceiptMarks = async (account: string): Promise<Record<string, ReceiptMarks>> =>
  parseReceiptMarks(await journals.load('receipt-marks', legacy(`${databasePath}/receipt-marks/v1/${account}`)));
export const saveReceiptMarks = (_account: string, marks: Record<string, ReceiptMarks>): Promise<void> =>
  journals.save('receipt-marks', marks);
