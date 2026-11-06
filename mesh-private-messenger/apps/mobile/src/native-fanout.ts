import { utf8, vectors } from './codec.ts';
export type FanoutKind = 1 | 2 | 3 | 4 | 5;
export function nativeFanoutRequest(
  path: string,
  profile: Uint8Array,
  username: string,
  kind: FanoutKind,
  payload: Uint8Array,
  expectedPeer?: Uint8Array,
  attachment?: Uint8Array,
): Uint8Array {
  const database = utf8(path);
  if (!database.length || database.length > 4096 || path.includes('\0') || !profile.length || profile.length > 36134 ||
      !/^(?:@[0-9a-f]{64}|[a-z0-9_.-]{1,64})$/.test(username) || kind < 1 || kind > 5 ||
      payload.length > 32000 || (expectedPeer && expectedPeer.length !== 32) || (attachment && attachment.length > 16384) ||
      ((kind === 2 || kind === 3) && (payload.length !== 32 || !!attachment?.length)) ||
      (kind === 4 && (!!payload.length || !!attachment?.length)) ||
      (kind === 5 && (payload.length < 32 || payload.length > 2048 || payload.length % 32 !== 0 || !!attachment?.length || !!expectedPeer?.length)) || (kind === 1 && !payload.length && !attachment?.length)) {
    throw new Error('invalid_fanout_action');
  }
  // Framing copies every byte now, before a serialized operation can wait.
  return vectors(database, profile, utf8(username), Uint8Array.of(kind), payload, expectedPeer ?? new Uint8Array(), attachment ?? new Uint8Array());
}
export function parseNativeFanoutStatus(bytes: Uint8Array): boolean {
  if (bytes.length !== 5 || bytes[0] !== 1 || bytes[1] !== 70 || bytes[2] !== 78 || bytes[3] !== 79 ||
      (bytes[4] !== 0 && bytes[4] !== 1)) throw new Error('invalid_native_fanout_status');
  return bytes[4] === 1;
}
