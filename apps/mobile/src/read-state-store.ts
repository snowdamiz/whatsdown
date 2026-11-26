import { File, Paths } from 'expo-file-system';
import type { LegacyJournal } from './journal-store';
import { parseReadState, type ReadState } from './read-state';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { journals, settings } from './sealed-journals';
import { parseDeclined } from './community-requests';

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

// Requests to join a community this admin declined, by the chat they came in.
export const loadDeclinedRequests = async (): Promise<Record<string, string[]>> =>
  parseDeclined(await journals.load('community-requests'));
export const saveDeclinedRequests = (declined: Record<string, string[]>): Promise<void> => journals.save('community-requests', declined);

// Whether this account tells people when it has read their messages. On unless turned off.
export const loadReadReceipts = async (account: string): Promise<boolean> =>
  await settings.load('read-receipts', legacy(`read-receipts-${account}`)) !== 'off';
export const saveReadReceipts = (_account: string, enabled: boolean): Promise<void> =>
  settings.save('read-receipts', enabled ? 'on' : 'off');

// How much a notification shows; see NotificationPreview. Everything unless changed.
export const loadNotificationPreview = async (account: string): Promise<NotificationPreview> =>
  parseNotificationPreview(await settings.load('notification-preview', legacy(`notification-preview-${account}`)));
export const saveNotificationPreview = (_account: string, preview: NotificationPreview): Promise<void> =>
  settings.save('notification-preview', preview);

// The sealed settings go with the database; this removes any copy an older build
// left in the clear.
export function forgetPreferences(account: string): void {
  for (const name of [`read-receipts-${account}`, `notification-preview-${account}`]) legacy(name).remove();
}

// How far each chat's other side has acknowledged; see ReceiptMarks. Timestamps of
// messages still in history only, and gone when they are.
export const loadReceiptMarks = async (account: string): Promise<Record<string, ReceiptMarks>> =>
  parseReceiptMarks(await journals.load('receipt-marks', legacy(`receipt-marks-${account}.json`)));
export const saveReceiptMarks = (_account: string, marks: Record<string, ReceiptMarks>): Promise<void> =>
  journals.save('receipt-marks', marks);
