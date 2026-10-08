import {
  expiry_purge_export,
  group_open_view_once_export,
  group_timer_state_export,
  journal_load_export,
  journal_save_export,
  open_view_once_export,
  safety_code_check_export,
  safety_code_export,
} from '../modules/mesh-messenger';
import {
  decodeUtf8,
  parseGroupHistory,
  parseHistory,
  utf8,
  vectors,
  writeU32,
  type GroupHistoryMessage,
  type HistoryMessage,
} from './codec';
import { encodeLockSetting, parseLockSetting, type LockSetting } from './app-lock';
import { parsePurge, safetyOutcome, type Purge, type SafetyOutcome } from './ephemeral';

// The core calls behind disappearing and view-once messages, safety codes and
// the app lock's setting; what they mean is in ephemeral.ts and app-lock.ts.

export async function purgeExpired(databasePath: string): Promise<Purge> {
  return parsePurge(await expiry_purge_export(utf8(databasePath)));
}

export async function groupTimer(databasePath: string, groupId: Uint8Array): Promise<number> {
  const value = await group_timer_state_export(vectors(utf8(databasePath), groupId));
  if (value.length !== 4) throw new Error('Invalid group timer');
  return new DataView(value.buffer, value.byteOffset, 4).getUint32(0, false);
}

// The content comes back once, and is gone from this device when the call returns.
export async function openViewOnce(databasePath: string, peerAccountId: Uint8Array, messageId: Uint8Array): Promise<HistoryMessage> {
  const summary = await open_view_once_export(vectors(utf8(databasePath), peerAccountId, messageId));
  const [message] = parseHistory(vectors(writeU32(1), summary));
  if (!message) throw new Error('Invalid view-once message');
  return message;
}

export async function openGroupViewOnce(databasePath: string, groupId: Uint8Array, messageId: Uint8Array): Promise<GroupHistoryMessage> {
  const summary = await group_open_view_once_export(vectors(utf8(databasePath), groupId, messageId));
  const [message] = parseGroupHistory(vectors(writeU32(1), summary));
  if (!message) throw new Error('Invalid view-once message');
  return message;
}

export async function safetyCode(databasePath: string, peerAccountId: Uint8Array): Promise<string> {
  return decodeUtf8(await safety_code_export(vectors(utf8(databasePath), peerAccountId)));
}

export async function checkSafetyCode(databasePath: string, peerAccountId: Uint8Array, code: string): Promise<SafetyOutcome> {
  const scanned = code.trim() || ' ';
  return safetyOutcome(decodeUtf8(await safety_code_check_export(vectors(utf8(databasePath), peerAccountId, utf8(scanned)))));
}

const lockKey = 'settings/app-lock';

export async function loadLockSetting(databasePath: string): Promise<LockSetting> {
  return parseLockSetting(decodeUtf8(await journal_load_export(vectors(utf8(databasePath), utf8(lockKey)))));
}

export async function saveLockSetting(databasePath: string, setting: LockSetting): Promise<void> {
  await journal_save_export(vectors(utf8(databasePath), utf8(lockKey), utf8(encodeLockSetting(setting))));
}
