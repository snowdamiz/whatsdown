import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { journal_load_bound_export, journal_save_bound_export } from '../modules/mesh-messenger';
import { decodeUtf8, hex, parseProfileSummary, utf8, vectors } from './codec';
import type { LegacyJournal } from './journal-store';
import { createKeyedSerialQueue } from './single-flight';
import { databasePath } from './storage';
type Preference = 'read-receipts' | 'notification-preview';
const fallback = { 'read-receipts': 'on', 'notification-preview': 'full' } as const;
const valid = (name: Preference, value: string): boolean =>
  name === 'read-receipts' ? value === 'on' || value === 'off' : ['full', 'sender', 'none'].includes(value);
function action(databasePath: string, profile: Uint8Array, name: Preference) {
  const expected = profile.slice();
  const identity = parseProfileSummary(expected);
  return {
    request: [utf8(databasePath), expected, utf8(`preferences/${name}`)],
    queue: `${hex(identity.accountId)}/${hex(identity.deviceId)}/${name}`,
  };
}
export function createPreferenceServices(deps: Pick<ScopedClient, 'runPrivate' | 'journal_load_bound_export' | 'journal_save_bound_export' | 'onDispose'> & { readonly databasePath: string }) {
const { journal_load_bound_export, journal_save_bound_export, databasePath } = deps;
const serialize = createKeyedSerialQueue<string>();
// Migrate only after the native account check; remove the old clear choice only
// after the encrypted write commits. A failed migration is safe to retry.
function loadSealedPreference(profile: Uint8Array, name: Preference, legacy: LegacyJournal): Promise<string> {
  const held = action(databasePath, profile, name);
  return serialize(held.queue, async () => {
    const stored = decodeUtf8(await journal_load_bound_export(vectors(...held.request)));
    if (stored) {
      if (!valid(name, stored)) throw Error('invalid_journal_preference');
      await legacy.remove();
      return stored;
    }
    const old = await legacy.read();
    const chosen = old !== null && valid(name, old) ? old : fallback[name];
    await journal_save_bound_export(vectors(...held.request, utf8(chosen)));
    await legacy.remove();
    return chosen;
  });
}
function saveSealedPreference(profile: Uint8Array, name: Preference, value: string): Promise<void> {
  const held = action(databasePath, profile, name);
  return serialize(held.queue, async () => {
    if (!valid(name, value)) throw Error('invalid_journal_preference');
    await journal_save_bound_export(vectors(...held.request, utf8(value)));
  });
}
return Object.freeze({
  loadSealedPreference: (...args: Parameters<typeof loadSealedPreference>) => deps.runPrivate(() => loadSealedPreference(...args)),
  saveSealedPreference: (...args: Parameters<typeof saveSealedPreference>) => deps.runPrivate(() => saveSealedPreference(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createPreferenceServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createPreferenceServices({ runPrivate: operation => operation(), onDispose: () => () => {}, databasePath, journal_load_bound_export, journal_save_bound_export });
}
export const loadSealedPreference: ReturnType<typeof createPreferenceServices>['loadSealedPreference'] = (...args) => desktopCompatibility().loadSealedPreference(...args);
export const saveSealedPreference: ReturnType<typeof createPreferenceServices>['saveSealedPreference'] = (...args) => desktopCompatibility().saveSealedPreference(...args);
