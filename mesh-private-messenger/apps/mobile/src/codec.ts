import { applyReactions, type Reaction } from './reactions.ts';
import { applyReceipts, type ReceiptState } from './receipts.ts';
import { applyReplies, type Reply } from './replies.ts';

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

// The opened manifest of one attachment, next to the opaque reference that the
// native core needs back to decrypt its chunks.
export type AttachmentSummary = {
  reference: Uint8Array;
  objectId: Uint8Array;
  downloadCapability: Uint8Array;
  filename: string;
  mimeType: string;
  size: number;
  chunkCount: number;
  chunkSize: number;
  expiresAt: number;
};

export type HistoryMessage = {
  reactions?: Reaction[];
  // The message this one answers, quoted from this device's own history.
  reply?: Reply<Omit<HistoryMessage, 'reply'>>;
  // The furthest the other side has acknowledged a sent message, or this account a received one.
  receipt?: ReceiptState;
  direction: 'sent' | 'received';
  messageId: Uint8Array;
  timestamp: number;
  body: string;
  disappearingSeconds: number;
  attachments?: AttachmentSummary[];
};

export type DeviceSummary = {
  deviceId: Uint8Array;
  active: boolean;
  current: boolean;
};

export type DeviceSetSummary = {
  username: string;
  accountId: Uint8Array;
  sequence: number;
  changed: boolean;
  canManage: boolean;
  devices: DeviceSummary[];
};

export type ProfileSummary = {
  username: string;
  accountId: Uint8Array;
  deviceId: Uint8Array;
};

export type GroupSummary = {
  groupId: Uint8Array;
  epoch: number;
  memberCount: number;
};

export type GroupInvitation = {
  reference: Uint8Array;
  groupId: Uint8Array;
  username: string;
  accountId: Uint8Array;
  state: number;
};

export type GroupHistoryMessage = {
  messageId?: Uint8Array;
  reactions?: Reaction[];
  reply?: Reply<Omit<GroupHistoryMessage, 'reply'>>;
  direction: 'sent' | 'received';
  epoch: number;
  senderAccountId: Uint8Array;
  senderDeviceId: Uint8Array;
  timestamp: number;
  body: string;
  attachments?: AttachmentSummary[];
};

export type GroupMemberSummary = {
  username?: string;
  leaf: number;
  local: boolean;
  accountId: Uint8Array;
  deviceId: Uint8Array;
  directorySequence: number;
  witnessCount: number;
};

export type GroupDetails = {
  groupId: Uint8Array;
  epoch: number;
  treeHash: Uint8Array;
  checkpointHash: Uint8Array;
  members: GroupMemberSummary[];
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

export class Reader {
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

export function parsePrekeyCount(input: Uint8Array): number {
  const count = readU32(input);
  if (count > 64) throw new Error('Prekey count is too large');
  return count;
}

const readU64Number = (value: Uint8Array): number => {
  if (value.length !== 8) throw new Error('Invalid u64');
  const parsed = new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0, false);
  const number = Number(parsed);
  if (!Number.isSafeInteger(number)) throw new Error('Unsafe timestamp');
  return number;
};

export const accountRequest = (databasePath: string, username: string): Uint8Array =>
  vectors(utf8(databasePath), utf8(username));

export const peerRequest = (
  databasePath: string,
  peerReference: Uint8Array,
): Uint8Array => vectors(utf8(databasePath), peerReference);

export const policyRequest = (
  databasePath: string,
  peerReference: Uint8Array,
  action: number,
  value = 0,
): Uint8Array =>
  vectors(utf8(databasePath), peerReference, Uint8Array.of(action), writeU32(value));

export const batchRequest = (databasePath: string, batch: Uint8Array): Uint8Array =>
  vectors(utf8(databasePath), batch);

export function parseByteList(
  input: Uint8Array,
  maximumCount: number,
  maximumItemLength: number,
): Uint8Array[] {
  if (!Number.isInteger(maximumCount) || maximumCount < 0 || !Number.isInteger(maximumItemLength) || maximumItemLength < 0) {
    throw new RangeError('Invalid list bounds');
  }
  const list = new Reader(input);
  const count = readU32(list.vector(4));
  if (count > maximumCount) throw new Error('Binary list is too large');
  const values: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) values.push(list.vector(maximumItemLength));
  list.finish();
  return values;
}

function exactByteList(input: Uint8Array, count: number, maximumItemLength: number): Uint8Array[] {
  const values = parseByteList(input, count, maximumItemLength);
  if (values.length !== count) throw new Error('Invalid binary record');
  return values;
}

export const ATTACHMENT_CHUNK_SIZE = 65_536;
export const MAXIMUM_ATTACHMENT_SIZE = 256 * ATTACHMENT_CHUNK_SIZE;
// A summary with its opened manifest fields; the reference alone is under 1 KiB.
const MAXIMUM_ATTACHMENT_SUMMARY = 2_048;
export const MAXIMUM_ATTACHMENTS = 10;
const MAXIMUM_ATTACHMENT_SUMMARIES = 8 + MAXIMUM_ATTACHMENTS * (4 + MAXIMUM_ATTACHMENT_SUMMARY);

export function parseAttachmentSummary(input: Uint8Array): AttachmentSummary | undefined {
  if (input.length === 0) return undefined;
  const [reference, objectId, downloadCapability, filename, mimeType, size, chunkCount, chunkSize, expiresAt] =
    exactByteList(input, 9, 1_024);
  if (!reference || !objectId || !downloadCapability || !filename || !mimeType || !size || !chunkCount || !chunkSize || !expiresAt) {
    throw new Error('Invalid attachment');
  }
  const summary: AttachmentSummary = {
    reference,
    objectId,
    downloadCapability,
    filename: decodeUtf8(filename),
    mimeType: decodeUtf8(mimeType),
    size: readU32(size),
    chunkCount: readU32(chunkCount),
    chunkSize: readU32(chunkSize),
    expiresAt: readU64Number(expiresAt),
  };
  if (
    reference.length === 0 ||
    objectId.length !== 32 ||
    downloadCapability.length !== 32 ||
    summary.mimeType.length === 0 ||
    summary.size === 0 ||
    summary.size > MAXIMUM_ATTACHMENT_SIZE ||
    summary.chunkSize !== ATTACHMENT_CHUNK_SIZE ||
    summary.chunkCount !== Math.ceil(summary.size / ATTACHMENT_CHUNK_SIZE)
  ) {
    throw new Error('Invalid attachment');
  }
  return summary;
}

// ATB framing is only used for multiple files; old single-file histories still decode.
export function encodeAttachmentReferences(references: Uint8Array[]): Uint8Array {
  if (references.length > MAXIMUM_ATTACHMENTS) throw new Error('You can attach up to 10 files per message.');
  if (references.some((reference) => reference.length === 0 || reference.length > 1_024)) throw new Error('Invalid attachment');
  if (references.length <= 1) return references[0] ?? new Uint8Array();
  return new Uint8Array([1, 65, 84, 66, ...writeU32(references.length), ...vectors(...references)]);
}

function parseAttachmentSummaries(input: Uint8Array): AttachmentSummary[] {
  if (input.length === 0) return [];
  if (input[0] !== 1 || input[1] !== 65 || input[2] !== 84 || input[3] !== 66) {
    return [parseAttachmentSummary(input)!];
  }
  const reader = new Reader(input.subarray(8));
  const count = readU32(input.subarray(4, 8));
  if (count < 2 || count > MAXIMUM_ATTACHMENTS) throw new Error('Invalid attachment count');
  const summaries: AttachmentSummary[] = [];
  for (let index = 0; index < count; index += 1) {
    const summary = parseAttachmentSummary(reader.vector(MAXIMUM_ATTACHMENT_SUMMARY));
    if (!summary) throw new Error('Invalid attachment');
    summaries.push(summary);
  }
  reader.finish();
  return summaries;
}

export function parseGroupList(input: Uint8Array): GroupSummary[] {
  return parseByteList(input, 128, 69).map((record) => {
    const [version, groupId, epoch, memberCount] = exactByteList(record, 4, 32);
    if (!version || !groupId || !epoch || !memberCount) throw new Error('Invalid group summary');
    if (readByte(version) !== 1 || groupId.length !== 32) throw new Error('Invalid group summary');
    const parsedMemberCount = readU32(memberCount);
    if (parsedMemberCount > 64) throw new Error('Invalid group member count');
    return { groupId, epoch: readU64Number(epoch), memberCount: parsedMemberCount };
  });
}

export function parseGroupInvitations(input: Uint8Array): GroupInvitation[] {
  return parseByteList(input, 128, 189).map((record) => {
    const [reference, groupId, usernameBytes, accountId, stateBytes] = exactByteList(record, 5, 64);
    if (!reference || !groupId || !usernameBytes || !accountId || !stateBytes ||
      reference.length !== 32 || groupId.length !== 32 || accountId.length !== 32) {
      throw new Error('Invalid group invitation');
    }
    const state = readByte(stateBytes);
    const username = decodeUtf8(usernameBytes);
    if (state > 3 || !/^[a-z0-9._-]{1,64}$/.test(username)) throw new Error('Invalid group invitation');
    return { reference, groupId, username, accountId, state };
  });
}

export function parseGroupHistory(input: Uint8Array): GroupHistoryMessage[] {
  // The stored history is bounded to 64 KiB; opened attachment manifests add to the export.
  if (input.length > 65_536 + 256 * MAXIMUM_ATTACHMENT_SUMMARIES) throw new Error('Group history is too large');
  const messages: GroupHistoryMessage[] = parseByteList(input, 256, 65_484 + MAXIMUM_ATTACHMENT_SUMMARIES).map((record) => {
    const fields = parseByteList(record, 9, 65_346);
    if (fields.length !== 8 && fields.length !== 9) throw new Error('Invalid group history');
    const [version, direction, epoch, senderAccountId, senderDeviceId, timestamp, body, attachment, messageId] = fields;
    if (messageId?.length && messageId.length !== 32) throw new Error('Invalid group message ID');
    if (
      !version ||
      !direction ||
      !epoch ||
      !senderAccountId ||
      !senderDeviceId ||
      !timestamp ||
      !body ||
      !attachment
    ) {
      throw new Error('Invalid group history');
    }
    const directionValue = readByte(direction);
    if (
      readByte(version) !== 1 ||
      (directionValue !== 1 && directionValue !== 2) ||
      senderAccountId.length !== 32 ||
      senderDeviceId.length !== 16
    ) {
      throw new Error('Invalid group history');
    }
    const attachments = parseAttachmentSummaries(attachment);
    return {
      ...(messageId?.length ? { messageId } : {}),
      direction: directionValue === 1 ? 'sent' : 'received',
      epoch: readU64Number(epoch),
      senderAccountId,
      senderDeviceId,
      timestamp: readU64Number(timestamp),
      body: decodeUtf8(body),
      ...(attachments.length ? { attachments } : {}),
    };
  });
  const keyOf = (message: GroupHistoryMessage) => message.messageId ? hex(message.messageId) : '';
  return applyReplies(applyReactions(messages, keyOf, (message) => hex(message.senderAccountId)), keyOf);
}

function parseGroupMember(input: Uint8Array): GroupMemberSummary {
  const fields = parseByteList(input, 8, 64);
  if (fields.length !== 7 && fields.length !== 8) throw new Error('Invalid group member');
  const [version, leaf, local, accountId, deviceId, directorySequence, witnessCount, usernameBytes] = fields;
  const username = usernameBytes ? decodeUtf8(usernameBytes) : '';
  if (username && !/^[a-z0-9._-]{1,64}$/.test(username)) throw new Error('Invalid group username');
  if (
    !version ||
    !leaf ||
    !local ||
    !accountId ||
    !deviceId ||
    !directorySequence ||
    !witnessCount
  ) {
    throw new Error('Invalid group member');
  }
  const parsedLeaf = readU32(leaf);
  const parsedLocal = readByte(local);
  const parsedWitnessCount = readByte(witnessCount);
  if (
    readByte(version) !== 1 ||
    parsedLeaf >= 64 ||
    parsedLocal > 1 ||
    accountId.length !== 32 ||
    deviceId.length !== 16 ||
    parsedWitnessCount > 16
  ) {
    throw new Error('Invalid group member');
  }
  return {
    leaf: parsedLeaf,
    local: parsedLocal === 1,
    accountId,
    deviceId,
    directorySequence: readU64Number(directorySequence),
    witnessCount: parsedWitnessCount,
    ...(username ? { username } : {}),
  };
}

export function parseGroupDetails(input: Uint8Array): GroupDetails {
  if (input.length > 11_097) throw new Error('Group details are too large');
  const [version, groupId, epoch, localLeaf, treeHash, checkpointHash, encodedMembers] =
    exactByteList(input, 7, 10_952);
  if (
    !version ||
    !groupId ||
    !epoch ||
    !localLeaf ||
    !treeHash ||
    !checkpointHash ||
    !encodedMembers
  ) {
    throw new Error('Invalid group details');
  }
  if (
    readByte(version) !== 1 ||
    groupId.length !== 32 ||
    readU32(localLeaf) >= 64 ||
    treeHash.length !== 32 ||
    checkpointHash.length !== 32
  ) {
    throw new Error('Invalid group details');
  }
  return {
    groupId,
    epoch: readU64Number(epoch),
    treeHash,
    checkpointHash,
    members: parseByteList(encodedMembers, 64, 167).map(parseGroupMember),
  };
}

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
    const attachments = parseAttachmentSummaries(entry.vector(MAXIMUM_ATTACHMENT_SUMMARIES));
    entry.finish();
    if (direction !== 1 && direction !== 2) throw new Error('Invalid message direction');
    messages.push({
      direction: direction === 1 ? 'sent' : 'received',
      messageId,
      timestamp,
      body,
      disappearingSeconds,
      ...(attachments.length ? { attachments } : {}),
    });
  }
  list.finish();
  const keyOf = (message: HistoryMessage) => hex(message.messageId);
  return applyReplies(applyReactions(applyReceipts(messages), keyOf, (message) => message.direction), keyOf);
}

// The core stamps an envelope to expire 30 days after the timestamp of the message
// it carries, so the expiry of a queued envelope dates the send. Delivery wire 1:
// version, "MSG", envelope ID (16), mailbox token (32), suite (2), expiry (8).
export function envelopeExpiresAt(envelope: Uint8Array): number {
  if (envelope.length < 62 || envelope[0] !== 1 || decodeUtf8(envelope.subarray(1, 4)) !== 'MSG') {
    throw new Error('Invalid envelope');
  }
  return readU64Number(envelope.subarray(54, 62));
}

// Mesh gives every envelope thirty days from the moment it is queued.
export const envelopeQueuedAt = (envelope: Uint8Array): number => envelopeExpiresAt(envelope) - 2_592_000_000;

export function parseDeviceSetSummary(input: Uint8Array): DeviceSetSummary {
  const summary = new Reader(input);
  const username = decodeUtf8(summary.vector(64));
  const accountId = summary.vector(32);
  const sequence = readU64Number(summary.vector(8));
  const changed = readByte(summary.vector(1)) === 1;
  const canManage = readByte(summary.vector(1)) === 1;
  const encodedDevices = new Reader(summary.vector(8_192));
  const count = readU32(encodedDevices.vector(4));
  if (count > 40) throw new Error('Device list is too large');
  const devices: DeviceSummary[] = [];
  for (let index = 0; index < count; index += 1) {
    const encoded = new Reader(encodedDevices.vector(64));
    const deviceId = encoded.vector(16);
    const activeValue = readByte(encoded.vector(1));
    const currentValue = readByte(encoded.vector(1));
    encoded.finish();
    if (activeValue > 1 || currentValue > 1 || (currentValue === 1 && activeValue === 0)) {
      throw new Error('Invalid device state');
    }
    devices.push({ deviceId, active: activeValue === 1, current: currentValue === 1 });
  }
  encodedDevices.finish();
  summary.finish();
  return { username, accountId, sequence, changed, canManage, devices };
}

export function parseProfileSummary(input: Uint8Array): ProfileSummary {
  const profile = new Reader(input);
  const username = decodeUtf8(profile.vector(64));
  const accountId = profile.vector(32);
  const deviceId = profile.vector(16);
  profile.vector(36_006);
  profile.finish();
  return { username, accountId, deviceId };
}

function binaryString(value: Uint8Array): string {
  let output = '';
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    output += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return output;
}

export const payloadQrValue = (kind: string, payload: Uint8Array): string =>
  `mesh://${kind}/${btoa(binaryString(payload)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`;

export function payloadFromQr(value: string, kind: string, maximum = 305_260): Uint8Array {
  const prefix = `mesh://${kind}/`;
  if (!value.startsWith(prefix)) throw new Error(`Not a Morse ${kind} code`);
  const encoded = value.slice(prefix.length).replaceAll('-', '+').replaceAll('_', '/');
  const decoded = atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '='));
  const payload = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (payload.length === 0 || payload.length > maximum) throw new Error(`Invalid ${kind} code`);
  return payload;
}

export const profileQrValue = (profile: Uint8Array): string => payloadQrValue('contact', profile);

export const profileFromQr = (value: string): Uint8Array =>
  payloadFromQr(value, 'contact', 36_134);

export const linkRequestFromQr = (value: string): Uint8Array =>
  payloadFromQr(value, 'link-request', 1_326);

export const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
