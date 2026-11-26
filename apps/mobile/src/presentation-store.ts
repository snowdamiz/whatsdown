import { presentation_load_export, presentation_save_export } from '../modules/mesh-messenger';
import { utf8, vectors } from './codec';
import { encodePresentation, parsePresentation, type Presentation } from './presentation';

export async function loadPresentation(database: string, key: string): Promise<Presentation | undefined> {
  return parsePresentation(await presentation_load_export(vectors(utf8(database), utf8(key))));
}

export async function savePresentation(database: string, key: string, value: Presentation): Promise<Presentation> {
  return parsePresentation(await presentation_save_export(vectors(utf8(database), utf8(key), encodePresentation({ ...value, revision: Date.now() }))))!;
}

export async function saveNickname(database: string, key: string, name: string): Promise<Presentation | undefined> {
  if (!/^nickname\/[a-f0-9]{64}$/.test(key)) throw new Error('Invalid nickname identity.');
  // The native boundary requires a nonempty payload; zero clears this local record.
  const value = name.trim() ? encodePresentation({ name }) : Uint8Array.of(0);
  return parsePresentation(await presentation_save_export(vectors(utf8(database), utf8(key), value)));
}
