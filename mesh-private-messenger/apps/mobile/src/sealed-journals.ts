import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { journal_load_bound_export, journal_save_bound_export } from '../modules/mesh-messenger';
import { decodeUtf8, hex, parseProfileSummary, utf8, vectors } from './codec';
import { createJournalStore } from './journal-store';
import { databasePath } from './storage';
export function createJournalServices(deps: Pick<ScopedClient, 'assertCurrent' | 'runPrivate' | 'journal_load_bound_export' | 'journal_save_bound_export' | 'onDispose'> & { readonly databasePath: string }) {
const { journal_load_bound_export, journal_save_bound_export, databasePath } = deps;
let current: { profile: string; store: ReturnType<typeof createJournalStore> } | undefined;
deps.onDispose(() => { current = undefined; });
// Each cache and queued writer retains the public profile it was created for.
// Native reads and atomic commits reject replacement accounts even when an old
// JS job resumes after the new account has already opened the same database.
function journalsFor(expectedProfile: Uint8Array): ReturnType<typeof createJournalStore> {
  deps.assertCurrent();
  const expected = expectedProfile.slice();
  const profile = parseProfileSummary(expected);
  const identity = `${hex(profile.accountId)}/${hex(profile.deviceId)}`;
  if (current?.profile === identity) return current.store;
  const raw = createJournalStore(
    async (key) => decodeUtf8(await journal_load_bound_export(vectors(utf8(databasePath), expected, utf8(key)))),
    async (key, data) => {
      await journal_save_bound_export(vectors(utf8(databasePath), expected, utf8(key), data ? utf8(data) : Uint8Array.of(0)));
    },
  );
  const store = Object.freeze({
    load: (...args: Parameters<typeof raw.load>) => deps.runPrivate(() => raw.load(...args)),
    save: (...args: Parameters<typeof raw.save>) => deps.runPrivate(() => raw.save(...args)),
  });
  current = { profile: identity, store };
  return store;
}
return Object.freeze({ journalsFor });
}
let legacyScopeServices: ReturnType<typeof createJournalServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createJournalServices({ assertCurrent: () => {}, runPrivate: operation => operation(), onDispose: () => () => {}, databasePath, journal_load_bound_export, journal_save_bound_export });
}
export const journalsFor: ReturnType<typeof createJournalServices>['journalsFor'] = (...args) => desktopCompatibility().journalsFor(...args);
