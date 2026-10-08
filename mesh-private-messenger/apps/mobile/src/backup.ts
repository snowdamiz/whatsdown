// Encrypted backups (protocol/backup-wire-v1.md, version 2). The core seals
// everything; this moves the sealed parts to and from the object store, where a
// backup is framed and sized like an attachment. Only the recovery code names
// where a backup is, so restoring needs the code and nothing else.

import {
  backup_begin_export,
  backup_confirm_export,
  backup_disable_export,
  backup_finish_export,
  backup_part_export,
  backup_prepare_export,
  backup_restore_account_export,
  backup_restore_begin_export,
  backup_restore_chunk_export,
  backup_restore_finish_export,
  backup_restore_identity_export,
  backup_restore_slots_export,
  backup_status_export,
} from '../modules/mesh-messenger';
import { parseBackupStatus, parseRestored, type BackupStatus, type RestoredBackup } from './backup-model.ts';
import { Reader, decodeUtf8, hex, parseByteList, utf8, vectors, writeU32 } from './codec.ts';
import { ServerStatusError, objectRequest, objectWorkDifficulty, registerDirectory, resolveDeviceSet } from './network.ts';
import { createKeyedSingleFlight } from './single-flight.ts';

export type TransferProgress = (completed: number, total: number) => void;

const request = (databasePath: string, ...fields: Uint8Array[]): Uint8Array => vectors(utf8(databasePath), ...fields);
const readU32 = (value: Uint8Array): number => {
  if (value.length !== 4) throw new Error('Invalid u32');
  return new DataView(value.buffer, value.byteOffset, 4).getUint32(0);
};
const backUpByDatabase = createKeyedSingleFlight<string, void>();

export const loadBackupStatus = async (databasePath: string): Promise<BackupStatus> =>
  parseBackupStatus(await backup_status_export(request(databasePath)));

// Turning backups on: the core makes the recovery code and hands it over this
// once. Backups start only when the code is typed back.
export const beginBackups = (databasePath: string): Promise<Uint8Array> => backup_begin_export(request(databasePath));

export async function confirmBackups(databasePath: string, code: Uint8Array): Promise<void> {
  await backup_confirm_export(request(databasePath, code));
}

// One backup: the core snapshots and seals it into today's next slot; the parts
// go up in order, and the object is completed only once every one is stored.
// A backup that fails is deleted and does not count.
export function backUp(databasePath: string, appState: Uint8Array, onProgress?: TransferProgress): Promise<void> {
  return backUpByDatabase(databasePath, async () => {
    const [objectId, uploadCapability, grant, complete, remove, count] = parseByteList(
      await backup_prepare_export(request(databasePath, appState, writeU32(objectWorkDifficulty()))),
      6,
      1024,
    );
    if (!objectId || !uploadCapability || !grant || !complete || !remove || !count || objectId.length !== 32) {
      throw new Error('Mesh returned an invalid backup');
    }
    const parts = readU32(count);
    try {
      await objectRequest('/v1/attachments/grant', grant);
      for (let index = 0; index < parts; index += 1) {
        const part = await backup_part_export(request(databasePath, writeU32(index)));
        await objectRequest(`/v1/objects/${hex(objectId)}/parts/${index}`, part, 'PUT', uploadCapability);
        onProgress?.(index + 1, parts);
      }
      await objectRequest('/v1/attachments/complete', complete);
    } catch (error) {
      await objectRequest('/v1/attachments/delete', remove).catch(() => {});
      await backup_finish_export(request(databasePath, Uint8Array.of(0))).catch(() => {});
      throw error;
    }
    await backup_finish_export(request(databasePath, Uint8Array.of(1)));
  });
}

// Backups off: the core forgets its key at once, and every backup of the past
// week is deleted. Returns how many could not be reached; they expire within
// six days, and nothing on this device can open them any more.
export async function disableBackups(databasePath: string): Promise<number> {
  const deletions = parseByteList(await backup_disable_export(request(databasePath)), 64, 68);
  const results = await Promise.allSettled(deletions.map((control) => objectRequest('/v1/attachments/delete', control)));
  return results.filter((result) => result.status === 'rejected' &&
    !(result.reason instanceof ServerStatusError && result.reason.status === 404)).length;
}

// A slot that answers anything but the part is not a backup to restore: never
// made (404), not completed (409), expired (410).
const absent = (error: unknown): boolean =>
  error instanceof ServerStatusError && [403, 404, 409, 410].includes(error.status);

// The code names every slot of the past week, newest first. The first one
// that answers is downloaded whole, padding included as an attachment's is,
// and checked chunk by chunk; the core keeps it until it is restored.
async function downloadBackup(databasePath: string, code: Uint8Array, onProgress?: TransferProgress): Promise<void> {
  const slots = parseByteList(await backup_restore_slots_export(request(databasePath, code)), 32, 64);
  for (const slot of slots) {
    const objectId = slot.slice(0, 32);
    const capability = slot.slice(32);
    const parts = `/v1/objects/${hex(objectId)}/parts/`;
    let first: Uint8Array;
    try {
      first = await objectRequest(`${parts}0`, new Uint8Array(), 'GET', capability);
    } catch (error) {
      if (absent(error)) continue;
      throw error;
    }
    const chunks = readU32(await backup_restore_begin_export(request(databasePath, code, first)));
    for (let index = 0; index < chunks; index += 1) {
      const sealed = await objectRequest(`${parts}${index + 1}`, new Uint8Array(), 'GET', capability).catch((error) => {
        throw error instanceof ServerStatusError && error.status === 410 ? new Error('backup_expired') : error;
      });
      await backup_restore_chunk_export(request(databasePath, writeU32(index), sealed));
      onProgress?.(index + 1, chunks);
    }
    return;
  }
  throw new Error('backup_not_found');
}

// Restoring onto a device already linked to the backup's account.
export async function restoreBackup(
  databasePath: string,
  code: Uint8Array,
  onProgress?: TransferProgress,
): Promise<RestoredBackup> {
  await downloadBackup(databasePath, code, onProgress);
  return parseRestored(await backup_restore_finish_export(request(databasePath)));
}

export type RecoveredAccount = RestoredBackup & { username: string };

// The account itself onto a fresh install, when every other device is gone.
// The backup names the account; the key log shows its devices now; the core
// adds this device at the next sequence with the account key the backup
// brought, and the directory registers it like any linked device.
export async function recoverAccount(
  databasePath: string,
  code: Uint8Array,
  onProgress?: TransferProgress,
): Promise<RecoveredAccount> {
  await downloadBackup(databasePath, code, onProgress);
  const identity = new Reader(await backup_restore_identity_export(request(databasePath)));
  const username = decodeUtf8(identity.vector(64));
  identity.vector(32);
  const holdsAccountKey = identity.vector(1)[0] === 1;
  identity.finish();
  if (!holdsAccountKey) throw new Error('backup_has_no_account_key');
  const deviceSet = await resolveDeviceSet(databasePath, username);
  const restored = parseRestored(await backup_restore_account_export(request(databasePath, deviceSet)));
  await registerDirectory(databasePath);
  return { ...restored, username };
}
