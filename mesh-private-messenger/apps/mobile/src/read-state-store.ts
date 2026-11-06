import { File, Paths } from 'expo-file-system';
import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import type { LegacyJournal } from './journal-store';
import { parseReadState, type ReadState } from './read-state';
import { parseNotificationPreview, type NotificationPreview } from './notification-policy';
import { parseReceiptMarks, type ReceiptMarks } from './receipts';
import { journalsFor } from './sealed-journals';
import { loadSealedPreference, saveSealedPreference } from './sealed-preferences';
import { hex, parseProfileSummary } from './codec';
import { parseDeclined } from './community-requests';
// The journals are sealed in the app's database (sealed-journals.ts). These files are
// where they were kept in the clear before that: read once, then removed.
// Old clear files are used only for one-time migration and erasure cleanup.
export function createReadStateServices(deps: Pick<ScopedClient, 'runPrivate'> & { readLegacyPreference: (profile: Uint8Array, kind: string) => ReturnType<LegacyJournal['read']>; removeLegacyPreference: (profile: Uint8Array, kind: string) => ReturnType<LegacyJournal['remove']>; forgetLegacyPreferences: (account: string) => void | Promise<void>; journalsFor: typeof journalsFor; loadSealedPreference: typeof loadSealedPreference; saveSealedPreference: typeof saveSealedPreference }) {
const { journalsFor, loadSealedPreference, saveSealedPreference } = deps;
const legacy = (kind: string, profile: Uint8Array): LegacyJournal => {
  const expected = profile.slice();
  return { read: () => deps.readLegacyPreference(expected, kind), remove: () => deps.removeLegacyPreference(expected, kind) };
};
const loadReadState = async (profile: Uint8Array): Promise<ReadState> =>
  parseReadState(await journalsFor(profile).load('read-state', legacy('read-state', profile)));
const saveReadState = (profile: Uint8Array, state: ReadState): Promise<void> => journalsFor(profile).save('read-state', state);
async function loadNotificationState(profile: Uint8Array): Promise<ReadState | null> {
  const kept = await journalsFor(profile).load('notification-state', legacy('notification-state', profile));
  return kept === null ? null : parseReadState(kept);
}
const saveNotificationState = (profile: Uint8Array, state: ReadState): Promise<void> =>
  journalsFor(profile).save('notification-state', state);
// Requests to join a community this admin declined, by the chat they came in.
const loadDeclinedRequests = async (profile: Uint8Array): Promise<Record<string, string[]>> =>
  parseDeclined(await journalsFor(profile).load('community-requests'));
const saveDeclinedRequests = (profile: Uint8Array, declined: Record<string, string[]>): Promise<void> => journalsFor(profile).save('community-requests', declined);
const loadReadReceipts = async (profile: Uint8Array): Promise<boolean> =>
  await loadSealedPreference(profile, 'read-receipts', legacy('read-receipts', profile)) === 'on';
const saveReadReceipts = (profile: Uint8Array, enabled: boolean): Promise<void> =>
  saveSealedPreference(profile, 'read-receipts', enabled ? 'on' : 'off');
const loadNotificationPreview = async (profile: Uint8Array): Promise<NotificationPreview> =>
  parseNotificationPreview(await loadSealedPreference(profile, 'notification-preview', legacy('notification-preview', profile)));
const saveNotificationPreview = (profile: Uint8Array, preview: NotificationPreview): Promise<void> =>
  saveSealedPreference(profile, 'notification-preview', preview);
async function forgetPreferences(account: string): Promise<void> {
  await deps.forgetLegacyPreferences(account);
}
// How far each chat's other side has acknowledged; see ReceiptMarks. Timestamps of
// messages still in history only, and gone when they are.
const loadReceiptMarks = async (profile: Uint8Array): Promise<Record<string, ReceiptMarks>> =>
  parseReceiptMarks(await journalsFor(profile).load('receipt-marks', legacy('receipt-marks', profile)));
const saveReceiptMarks = (profile: Uint8Array, marks: Record<string, ReceiptMarks>): Promise<void> =>
  journalsFor(profile).save('receipt-marks', marks);
return Object.freeze({
  loadReadState: (...args: Parameters<typeof loadReadState>) => deps.runPrivate(() => loadReadState(...args)),
  saveReadState: (...args: Parameters<typeof saveReadState>) => deps.runPrivate(() => saveReadState(...args)),
  loadNotificationState: (...args: Parameters<typeof loadNotificationState>) => deps.runPrivate(() => loadNotificationState(...args)),
  saveNotificationState: (...args: Parameters<typeof saveNotificationState>) => deps.runPrivate(() => saveNotificationState(...args)),
  loadDeclinedRequests: (...args: Parameters<typeof loadDeclinedRequests>) => deps.runPrivate(() => loadDeclinedRequests(...args)),
  saveDeclinedRequests: (...args: Parameters<typeof saveDeclinedRequests>) => deps.runPrivate(() => saveDeclinedRequests(...args)),
  loadReadReceipts: (...args: Parameters<typeof loadReadReceipts>) => deps.runPrivate(() => loadReadReceipts(...args)),
  saveReadReceipts: (...args: Parameters<typeof saveReadReceipts>) => deps.runPrivate(() => saveReadReceipts(...args)),
  loadNotificationPreview: (...args: Parameters<typeof loadNotificationPreview>) => deps.runPrivate(() => loadNotificationPreview(...args)),
  saveNotificationPreview: (...args: Parameters<typeof saveNotificationPreview>) => deps.runPrivate(() => saveNotificationPreview(...args)),
  forgetPreferences: (...args: Parameters<typeof forgetPreferences>) => deps.runPrivate(() => forgetPreferences(...args)),
  loadReceiptMarks: (...args: Parameters<typeof loadReceiptMarks>) => deps.runPrivate(() => loadReceiptMarks(...args)),
  saveReceiptMarks: (...args: Parameters<typeof saveReceiptMarks>) => deps.runPrivate(() => saveReceiptMarks(...args)),
});
}
function desktopLegacyFile(profile: Uint8Array, kind: string): File {
  const account = hex(parseProfileSummary(profile).accountId);
  switch (kind) {
    case 'read-state': case 'notification-state': case 'receipt-marks':
      return new File(Paths.document, `${kind}-${account}.json`);
    case 'read-receipts': case 'notification-preview':
      return new File(Paths.document, `${kind}-${account}`);
    default: throw Error('invalid_legacy_preference');
  }
}
const desktopLegacyPreferences: Pick<ScopedClient, 'readLegacyPreference' | 'removeLegacyPreference' | 'forgetLegacyPreferences'> = {
  readLegacyPreference(profile, kind) { const file = desktopLegacyFile(profile, kind); return file.exists ? file.textSync() : null; },
  removeLegacyPreference(profile, kind) { const file = desktopLegacyFile(profile, kind); if (file.exists) file.delete(); },
  forgetLegacyPreferences(account) {
    if (!/^[a-f0-9]{64}$/.test(account)) throw Error('invalid_legacy_account');
    for (const kind of ['read-receipts', 'notification-preview']) {
      const file = new File(Paths.document, `${kind}-${account}`); if (file.exists) file.delete();
    }
  },
};
let legacyScopeServices: ReturnType<typeof createReadStateServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createReadStateServices({ runPrivate: operation => operation(), ...desktopLegacyPreferences, journalsFor, loadSealedPreference, saveSealedPreference });
}
export const loadReadState: ReturnType<typeof createReadStateServices>['loadReadState'] = (...args) => desktopCompatibility().loadReadState(...args);
export const saveReadState: ReturnType<typeof createReadStateServices>['saveReadState'] = (...args) => desktopCompatibility().saveReadState(...args);
export const loadNotificationState: ReturnType<typeof createReadStateServices>['loadNotificationState'] = (...args) => desktopCompatibility().loadNotificationState(...args);
export const saveNotificationState: ReturnType<typeof createReadStateServices>['saveNotificationState'] = (...args) => desktopCompatibility().saveNotificationState(...args);
export const loadDeclinedRequests: ReturnType<typeof createReadStateServices>['loadDeclinedRequests'] = (...args) => desktopCompatibility().loadDeclinedRequests(...args);
export const saveDeclinedRequests: ReturnType<typeof createReadStateServices>['saveDeclinedRequests'] = (...args) => desktopCompatibility().saveDeclinedRequests(...args);
export const loadReadReceipts: ReturnType<typeof createReadStateServices>['loadReadReceipts'] = (...args) => desktopCompatibility().loadReadReceipts(...args);
export const saveReadReceipts: ReturnType<typeof createReadStateServices>['saveReadReceipts'] = (...args) => desktopCompatibility().saveReadReceipts(...args);
export const loadNotificationPreview: ReturnType<typeof createReadStateServices>['loadNotificationPreview'] = (...args) => desktopCompatibility().loadNotificationPreview(...args);
export const saveNotificationPreview: ReturnType<typeof createReadStateServices>['saveNotificationPreview'] = (...args) => desktopCompatibility().saveNotificationPreview(...args);
export const forgetPreferences: ReturnType<typeof createReadStateServices>['forgetPreferences'] = (...args) => desktopCompatibility().forgetPreferences(...args);
export const loadReceiptMarks: ReturnType<typeof createReadStateServices>['loadReceiptMarks'] = (...args) => desktopCompatibility().loadReceiptMarks(...args);
export const saveReceiptMarks: ReturnType<typeof createReadStateServices>['saveReceiptMarks'] = (...args) => desktopCompatibility().saveReceiptMarks(...args);
