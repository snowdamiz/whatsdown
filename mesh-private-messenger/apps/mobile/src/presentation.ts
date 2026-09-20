import { Reader, decodeUtf8, utf8, vectors } from './codec.ts';

export type Presentation = { name: string; avatar?: string; revision?: number };
export const MAX_AVATAR_LENGTH = 12_288;

export function identityName(username: string | null, profile?: Presentation, nickname?: Presentation): string | undefined {
  return nickname?.name || (profile?.name !== username ? profile?.name : undefined) || (username ? `@${username}` : undefined);
}

export function validateAvatar(avatar: string): string {
  if (avatar.length > MAX_AVATAR_LENGTH || !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(avatar)) {
    throw new Error('Choose a smaller JPEG photo.');
  }
  return avatar;
}

export function encodePresentation(value: Presentation): Uint8Array {
  const name = value.name.trim();
  if (!name || utf8(name).length > 96 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new Error('Enter a name, or shorten it if it is too long.');
  }
  const revision = new Uint8Array(8);
  if (!Number.isSafeInteger(value.revision ?? 0) || (value.revision ?? 0) < 0) throw new Error('Invalid photo revision.');
  new DataView(revision.buffer).setBigUint64(0, BigInt(value.revision ?? 0));
  return vectors(utf8(name), utf8(value.avatar ? validateAvatar(value.avatar) : ''), ...(value.revision === undefined ? [] : [revision]));
}

export function parsePresentation(input: Uint8Array): Presentation | undefined {
  if (!input.length) return undefined;
  const reader = new Reader(input);
  const name = decodeUtf8(reader.vector(96));
  const avatar = decodeUtf8(reader.vector(MAX_AVATAR_LENGTH)) || undefined;
  let revision: number | undefined;
  // Older records contain just the name and photo.
  try { reader.finish(); } catch {
    const bytes = reader.vector(8);
    if (bytes.length !== 8) throw new Error('Invalid photo revision.');
    revision = Number(new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0));
  }
  reader.finish();
  const value = { name, avatar, ...(revision === undefined ? {} : { revision }) };
  encodePresentation(value);
  return value;
}
