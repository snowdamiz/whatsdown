import { journal_load_export, journal_save_export } from '../modules/mesh-messenger';
import { decodeUtf8, utf8, vectors } from './codec';
import { createJournalStore } from './journal-store';
import { databasePath } from './storage';

// The journals, sealed by the core in the app's database. A request cannot carry an
// empty value, so a single zero byte is how a record is removed.
export const journals = createJournalStore(
  async (key) => decodeUtf8(await journal_load_export(vectors(utf8(databasePath), utf8(key)))),
  async (key, data) => {
    await journal_save_export(vectors(utf8(databasePath), utf8(key), data ? utf8(data) : Uint8Array.of(0)));
  },
);
