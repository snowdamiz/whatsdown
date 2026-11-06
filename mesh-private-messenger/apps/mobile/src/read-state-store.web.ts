import type { LegacyJournal } from './journal-store';
import { parseReadState, type ReadState } from './read-state';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { journalsFor } from './sealed-journals';
import { loadSealedPreference, saveSealedPreference } from './sealed-preferences';
import { hex, parseProfileSummary } from './codec';
import { parseDeclined } from './community-requests';
import { databasePath } from './storage';

const journalAccount = (profile: Uint8Array): string => hex(parseProfileSummary(profile).accountId);

// The journals are sealed in the app's database (sealed-journals.ts). These keys are
// where they were kept in the clear before that: read once, then removed.
const legacy = (key: string): LegacyJournal =>
  ({ read: () => localStorage.getItem(key), remove: () => localStorage.removeItem(key) });

export const loadReadState = async (profile: Uint8Array): Promise<ReadState> =>
  parseReadState(await journalsFor(profile).load('read-state', legacy(`${databasePath}/read-state/v1/${journalAccount(profile)}`)));
export const saveReadState = (profile: Uint8Array, state: ReadState): Promise<void> => journalsFor(profile).save('read-state', state);

export async function loadNotificationState(profile: Uint8Array): Promise<ReadState | null> {
  const kept = await journalsFor(profile).load('notification-state', legacy(`${databasePath}/notification-state/v1/${journalAccount(profile)}`));
  return kept === null ? null : parseReadState(kept);
}
export const saveNotificationState = (profile: Uint8Array, state: ReadState): Promise<void> =>
  journalsFor(profile).save('notification-state', state);

// Requests to join a community this admin declined, by the chat they came in.
export const loadDeclinedRequests = async (profile: Uint8Array): Promise<Record<string, string[]>> =>
  parseDeclined(await journalsFor(profile).load('community-requests'));
export const saveDeclinedRequests = (profile: Uint8Array, declined: Record<string, string[]>): Promise<void> => journalsFor(profile).save('community-requests', declined);

// Old clear keys are used only for one-time migration and erasure cleanup.
const receiptsKey = (account: string) => `${databasePath}/read-receipts/v1/${account}`;
const previewKey = (account: string) => `${databasePath}/notification-preview/v1/${account}`;
export const loadReadReceipts = async (profile: Uint8Array): Promise<boolean> =>
  await loadSealedPreference(profile, 'read-receipts', legacy(receiptsKey(journalAccount(profile)))) === 'on';
export const saveReadReceipts = (profile: Uint8Array, enabled: boolean): Promise<void> =>
  saveSealedPreference(profile, 'read-receipts', enabled ? 'on' : 'off');
export const loadNotificationPreview = async (profile: Uint8Array): Promise<NotificationPreview> =>
  parseNotificationPreview(await loadSealedPreference(profile, 'notification-preview', legacy(previewKey(journalAccount(profile)))));
export const saveNotificationPreview = (profile: Uint8Array, preview: NotificationPreview): Promise<void> =>
  saveSealedPreference(profile, 'notification-preview', preview);

export async function forgetPreferences(account: string): Promise<void> {
  localStorage.removeItem(receiptsKey(account));
  localStorage.removeItem(previewKey(account));
}

// How far each chat's other side has acknowledged; see ReceiptMarks.
export const loadReceiptMarks = async (profile: Uint8Array): Promise<Record<string, ReceiptMarks>> =>
  parseReceiptMarks(await journalsFor(profile).load('receipt-marks', legacy(`${databasePath}/receipt-marks/v1/${journalAccount(profile)}`)));
export const saveReceiptMarks = (profile: Uint8Array, marks: Record<string, ReceiptMarks>): Promise<void> =>
  journalsFor(profile).save('receipt-marks', marks);
