import { journal_load_export, journal_save_export } from '../modules/mesh-messenger';
import { decodeUtf8, utf8, vectors } from './codec';
import { createJournalStore, createSettingStore } from './journal-store';
import { databasePath } from './storage';

// The journals and settings, sealed by the core in the app's database. A request
// cannot carry an empty value, so a single zero byte is how a record is removed.
const load = async (key: string): Promise<string> =>
  decodeUtf8(await journal_load_export(vectors(utf8(databasePath), utf8(key))));
const save = async (key: string, data: string): Promise<void> => {
  await journal_save_export(vectors(utf8(databasePath), utf8(key), data ? utf8(data) : Uint8Array.of(0)));
};
export const journals = createJournalStore(load, save);
export const settings = createSettingStore(load, save);
