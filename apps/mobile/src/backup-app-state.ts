// What the app itself keeps goes into a backup as one opaque record the core
// carries (backup-model.ts), and comes back merged with what this device has.

import { journal_save_export, load_profile_export } from '../modules/mesh-messenger';
import { loadAppearance, saveAppearance } from './appearance-store';
import { backUp, loadBackupStatus } from './backup.ts';
import { backupDue, decodeAppState, encodeAppState, mergeAppState, type AppState, type RestoredBackup } from './backup-model.ts';
import { hex, parseProfileSummary, utf8, vectors } from './codec';
import {
  loadDeclinedRequests,
  loadNotificationPreview,
  loadReadReceipts,
  loadReadState,
  loadReceiptMarks,
  saveDeclinedRequests,
  saveNotificationPreview,
  saveReadReceipts,
  saveReadState,
  saveReceiptMarks,
} from './read-state-store';
import { databasePath } from './storage';

const ownAccount = async (): Promise<string> =>
  hex(parseProfileSummary(await load_profile_export(utf8(databasePath))).accountId);

export async function currentAppState(): Promise<AppState> {
  const account = await ownAccount();
  return {
    v: 1,
    readState: await loadReadState(account),
    receiptMarks: await loadReceiptMarks(account),
    declined: await loadDeclinedRequests(),
    readReceipts: await loadReadReceipts(account),
    notificationPreview: await loadNotificationPreview(account),
    appearance: await loadAppearance(),
  };
}

// Returns the settings now in force, for the app to show at once. The
// notification journal starts afresh from what is here now: the restored
// messages were announced where they first arrived.
export async function applyRestoredAppState(restored: RestoredBackup): Promise<AppState | null> {
  const account = await ownAccount();
  const saved = decodeAppState(restored.appState);
  let merged: AppState | null = null;
  if (saved) {
    merged = mergeAppState(await currentAppState(), saved);
    await saveReadState(account, merged.readState);
    await saveReceiptMarks(account, merged.receiptMarks);
    await saveDeclinedRequests(merged.declined);
    await saveReadReceipts(account, merged.readReceipts);
    await saveNotificationPreview(account, merged.notificationPreview);
    saveAppearance(merged.appearance);
  }
  await journal_save_export(vectors(utf8(databasePath), utf8('notification-state/index'), Uint8Array.of(0)));
  return merged;
}

// The last scheduled backup's failure, if it failed, for Settings to show.
let lastProblem: unknown = null;
export const scheduledBackupProblem = (): unknown => lastProblem;

export async function backUpNow(): Promise<void> {
  await backUp(databasePath, encodeAppState(await currentAppState()));
  lastProblem = null;
}

// Once a UTC day while backups are on; the app calls this now and then.
export async function backUpIfDue(now = Date.now()): Promise<void> {
  try {
    if (!backupDue(await loadBackupStatus(databasePath), now)) return;
    await backUpNow();
  } catch (error) {
    lastProblem = error;
  }
}
