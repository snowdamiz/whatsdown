const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export type Conversation = {
  conversationId: Uint8Array;
  username: string;
  peerAccountId: Uint8Array;
  peerDeviceId: Uint8Array;
  safetyNumber: string;
  requestPending: boolean;
  blocked: boolean;
  verified: boolean;
  keyChanged: boolean;
  disappearingSeconds: number;
};

export type HistoryMessage = {
  direction: 'sent' | 'received';
  messageId: Uint8Array;
  timestamp: number;
  body: string;
  disappearingSeconds: number;
};

export const utf8 = (value: string): Uint8Array => textEncoder.encode(value);
export const decodeUtf8 = (value: Uint8Array): string => textDecoder.decode(value);

export function writeU32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError('Expected an unsigned 32-bit integer');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export const vector = (value: Uint8Array): Uint8Array => concat([writeU32(value.length), value]);
export const vectors = (...values: readonly Uint8Array[]): Uint8Array =>
  concat(values.map(vector));

class Reader {
  private offset = 0;
  private readonly input: Uint8Array;

  constructor(input: Uint8Array) {
    this.input = input;
  }

  vector(maximum: number): Uint8Array {
    if (this.offset + 4 > this.input.length) throw new Error('Truncated vector length');
    const length = new DataView(
      this.input.buffer,
      this.input.byteOffset + this.offset,
      4,
    ).getUint32(0, false);
    this.offset += 4;
    if (length > maximum || this.offset + length > this.input.length) {
      throw new Error('Invalid vector length');
    }
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  finish(): void {
    if (this.offset !== this.input.length) throw new Error('Trailing bytes');
  }
}

const readByte = (value: Uint8Array): number => {
  if (value.length !== 1 || value[0] === undefined) throw new Error('Invalid byte');
  return value[0];
};

const readU32 = (value: Uint8Array): number => {
  if (value.length !== 4) throw new Error('Invalid u32');
  return new DataView(value.buffer, value.byteOffset, 4).getUint32(0, false);
};

const readU64Number = (value: Uint8Array): number => {
  if (value.length !== 8) throw new Error('Invalid u64');
  const parsed = new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0, false);
  const number = Number(parsed);
  if (!Number.isSafeInteger(number)) throw new Error('Unsafe timestamp');
  return number;
};

export const accountRequest = (databasePath: string, username: string): Uint8Array =>
  vectors(utf8(databasePath), utf8(username));

export const startRequest = (
  databasePath: string,
  peerProfile: Uint8Array,
  body: string,
): Uint8Array => vectors(utf8(databasePath), peerProfile, utf8(body));

export const peerRequest = (
  databasePath: string,
  peerReference: Uint8Array,
): Uint8Array => vectors(utf8(databasePath), peerReference);

export const policyRequest = (
  databasePath: string,
  peerReference: Uint8Array,
  action: number,
  value = 0,
): Uint8Array => vectors(utf8(databasePath), Uint8Array.of(action), writeU32(value));

export const batchRequest = (databasePath: string, batch: Uint8Array): Uint8Array =>
  vectors(utf8(databasePath), batch);

export function parseConversations(input: Uint8Array): Conversation[] {
  const list = new Reader(input);
  const count = readU32(list.vector(4));
  if (count > 256) throw new Error('Conversation list is too large');
  const conversations: Conversation[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = new Reader(list.vector(2_048));
    const conversationId = entry.vector(16);
    const username = decodeUtf8(entry.vector(64));
    const peerAccountId = entry.vector(32);
    const peerDeviceId = entry.vector(16);
    const safetyNumber = decodeUtf8(entry.vector(64));
    const requestPending = readByte(entry.vector(1)) === 0;
    const blocked = readByte(entry.vector(1)) === 1;
    const verified = readByte(entry.vector(1)) === 1;
    const keyChanged = readByte(entry.vector(1)) === 1;
    const disappearingSeconds = readU32(entry.vector(4));
    entry.finish();
    conversations.push({
      conversationId,
      username,
      peerAccountId,
      peerDeviceId,
      safetyNumber,
      requestPending,
      blocked,
      verified,
      keyChanged,
      disappearingSeconds,
    });
  }
  list.finish();
  return conversations;
}

export function parseHistory(input: Uint8Array): HistoryMessage[] {
  const list = new Reader(input);
  const count = readU32(list.vector(4));
  if (count > 256) throw new Error('History is too large');
  const messages: HistoryMessage[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = new Reader(list.vector(65_600));
    const direction = readByte(entry.vector(1));
    const messageId = entry.vector(16);
    const timestamp = readU64Number(entry.vector(8));
    const body = decodeUtf8(entry.vector(32_768));
    const disappearingSeconds = readU32(entry.vector(4));
    entry.finish();
    if (direction !== 1 && direction !== 2) throw new Error('Invalid message direction');
    messages.push({
      direction: direction === 1 ? 'sent' : 'received',
      messageId,
      timestamp,
      body,
      disappearingSeconds,
    });
  }
  list.finish();
  return messages;
}

function binaryString(value: Uint8Array): string {
  let output = '';
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    output += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return output;
}

export const profileQrValue = (profile: Uint8Array): string =>
  `mesh://contact/${btoa(binaryString(profile)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`;

export function profileFromQr(value: string): Uint8Array {
  const prefix = 'mesh://contact/';
  if (!value.startsWith(prefix)) throw new Error('Not a Whatsdown contact code');
  const encoded = value.slice(prefix.length).replaceAll('-', '+').replaceAll('_', '/');
  const decoded = atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '='));
  const profile = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (profile.length === 0 || profile.length > 16_384) throw new Error('Invalid contact code');
  return profile;
}

export const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
