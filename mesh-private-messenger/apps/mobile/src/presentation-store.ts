import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { presentation_load_export, presentation_save_export } from '../modules/mesh-messenger';
import { utf8, vectors } from './codec';
import { encodePresentation, parsePresentation, type Presentation } from './presentation';
export function createPresentationServices(deps: Pick<ScopedClient, 'runPrivate' | 'onDispose' | 'presentation_load_export' | 'presentation_save_export'>) {
const { presentation_load_export, presentation_save_export } = deps;
async function loadPresentation(database: string, key: string): Promise<Presentation | undefined> {
  return parsePresentation(await presentation_load_export(vectors(utf8(database), utf8(key))));
}
async function savePresentation(database: string, key: string, value: Presentation): Promise<Presentation> {
  return parsePresentation(await presentation_save_export(vectors(utf8(database), utf8(key), encodePresentation({ ...value, revision: Date.now() }))))!;
}
async function saveNickname(database: string, key: string, name: string): Promise<Presentation | undefined> {
  if (!/^nickname\/[a-f0-9]{64}$/.test(key)) throw new Error('Invalid nickname identity.');
  // The native boundary requires a nonempty payload; zero clears this local record.
  const value = name.trim() ? encodePresentation({ name }) : Uint8Array.of(0);
  return parsePresentation(await presentation_save_export(vectors(utf8(database), utf8(key), value)));
}
return Object.freeze({
  loadPresentation: (...args: Parameters<typeof loadPresentation>) => deps.runPrivate(() => loadPresentation(...args)),
  savePresentation: (...args: Parameters<typeof savePresentation>) => deps.runPrivate(() => savePresentation(...args)),
  saveNickname: (...args: Parameters<typeof saveNickname>) => deps.runPrivate(() => saveNickname(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createPresentationServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createPresentationServices({ runPrivate: operation => operation(), onDispose: () => () => {}, presentation_load_export, presentation_save_export });
}
export const loadPresentation: ReturnType<typeof createPresentationServices>['loadPresentation'] = (...args) => desktopCompatibility().loadPresentation(...args);
export const savePresentation: ReturnType<typeof createPresentationServices>['savePresentation'] = (...args) => desktopCompatibility().savePresentation(...args);
export const saveNickname: ReturnType<typeof createPresentationServices>['saveNickname'] = (...args) => desktopCompatibility().saveNickname(...args);
