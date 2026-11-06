export type BackupAction = { databasePath: string; expectedProfile: Uint8Array };
export type BackupScope = { kind: 'direct'; id: Uint8Array } | { kind: 'group'; id: Uint8Array };
export type BackupSelection = { scope: BackupScope; fromTime: string | null; throughTime: string | null };
export type BackupRequest =
  | { kind: 'create'; selections: BackupSelection[] }
  | { kind: 'preview'; wire: Uint8Array; recoveryCode: string }
  | { kind: 'import'; wire: Uint8Array; recoveryCode: string; confirmedId: Uint8Array }
  | { kind: 'list' }
  | { kind: 'remove'; backupId: Uint8Array }
  | { kind: 'overview'; backupId: Uint8Array }
  | { kind: 'page'; backupId: Uint8Array; scope: BackupScope; offset: number; limit: number }
  | { kind: 'pending_state' }
  | { kind: 'pending_resume'; draftId: Uint8Array; recoveryCode: string }
  | { kind: 'pending_discard'; draftId: Uint8Array }
  | { kind: 'pending_repair' };
export type BackupCreateReply = { draftId: Uint8Array; wire: Uint8Array; recoveryCode: string };
export type BackupPendingExportState =
  | { kind: 'empty' }
  | { kind: 'repairRequired' }
  | { kind: 'pending'; draftId: Uint8Array; createdAt: string; wireSize: number };
export type BackupDiscardReply = { draftId: Uint8Array };
export type BackupSummary = { backupId: Uint8Array; createdAt: string };
export type BackupImportReply = { backupId: Uint8Array; disposition: 1 | 2 };
export type BackupRemoveReply = { backupId: Uint8Array };
export type BackupConversation =
  | { kind: 'direct'; id: Uint8Array; peer: Uint8Array; name: string; messageCount: number }
  | { kind: 'group'; id: Uint8Array; peer: Uint8Array; name: string; messageCount: number };
export type BackupOverview = {
  backupId: Uint8Array; createdAt: string; includedCount: number; candidateCount: number;
  omittedTimed: number; omittedUnknown: number; omittedNontext: number; omittedEmpty: number;
  attachmentMessages: number; conversations: BackupConversation[];
};
export type BackupRecord = {
  ordinal: number; direction: 1 | 2; messageId: Uint8Array; senderAccount: Uint8Array;
  senderDevice: Uint8Array; timestamp: string; attachmentOmitted: boolean; text: string;
};
type BackupPageFields = { backupId: Uint8Array; scopeId: Uint8Array; offset: number; nextOffset: number | null; entries: BackupRecord[] };
export type BackupPage = (BackupPageFields & { kind: 'direct' }) | (BackupPageFields & { kind: 'group' });

const MAX_WIRE = 16_796_864;
const MAX_U64 = 18_446_744_073_709_551_615n;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const requestError = (): never => { throw new Error('invalid_backup_native_request'); };
const replyError = (): never => { throw new Error('invalid_backup_native_reply'); };
function requestBytes(value: Uint8Array, minimum: number, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) return requestError();
  return value;
}
function requestText(value: string, maximum: number, codepoints = maximum): Uint8Array {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) return requestError();
  let count = 0;
  for (const char of value) {
    const code = char.codePointAt(0);
    if (code === undefined || (code >= 0xd800 && code <= 0xdfff) || ++count > codepoints) return requestError();
  }
  const bytes = encoder.encode(value);
  return requestBytes(bytes, 1, maximum);
}
function withRecoveryCode(value: string, makeRequest: (code: Uint8Array) => Uint8Array): Uint8Array {
  const code = requestText(value, 4096, 1024);
  try { return makeRequest(code); }
  finally { code.fill(0); }
}
function integer(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) return requestError();
  return value;
}
function uint(value: number, size: number): Uint8Array {
  integer(value, 0, size === 1 ? 255 : 0xffff_ffff);
  const out = new Uint8Array(size);
  if (size === 1) out[0] = value;
  else new DataView(out.buffer).setUint32(0, value);
  return out;
}
function join(parts: readonly Uint8Array[], maximum: number): Uint8Array {
  let size = 0;
  for (const part of parts) { size += part.length; if (size > maximum) return requestError(); }
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function vector(value: Uint8Array): Uint8Array { return join([uint(value.length, 4), value], 16_841_239); }
function time(value: string | null): { bytes: Uint8Array; value: bigint | null } {
  if (value === null) return { bytes: uint(0, 1), value: null };
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return requestError();
  const number = BigInt(value);
  if (number > MAX_U64) return requestError();
  const bytes = new Uint8Array(9); bytes[0] = 1;
  new DataView(bytes.buffer).setBigUint64(1, number);
  return { bytes, value: number };
}
function scopeBytes(scope: BackupScope): { kind: Uint8Array; id: Uint8Array } {
  switch (scope.kind) {
    case 'direct': return { kind: uint(1, 1), id: requestBytes(scope.id, 16, 16) };
    case 'group': return { kind: uint(2, 1), id: requestBytes(scope.id, 32, 32) };
    default: { const exhaustive: never = scope; void exhaustive; return requestError(); }
  }
}
function hex(value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join(''); }
export function encodeBackupRequest(action: BackupAction, request: BackupRequest): Uint8Array {
  try {
    const path = requestText(action.databasePath, 4096);
    if (action.databasePath.includes('\0')) return requestError();
    const profile = requestBytes(action.expectedProfile, 1, 36134);
    const base = [uint(1, 1), vector(path), vector(profile)];
    switch (request.kind) {
      case 'list': case 'pending_state': case 'pending_repair': return join(base, 40239);
      case 'pending_resume': {
        const draftId = requestBytes(request.draftId, 32, 32);
        return withRecoveryCode(request.recoveryCode, code => join([...base, draftId, uint(code.length, 4), code], 44371));
      }
      case 'pending_discard': return join([...base, requestBytes(request.draftId, 32, 32)], 40271);
      case 'create': {
        if (!Array.isArray(request.selections) || request.selections.length < 1 || request.selections.length > 32) return requestError();
        const seen = new Set<string>();
        const rows = request.selections.map(selection => {
          const scope = scopeBytes(selection.scope);
          const key = selection.scope.kind + '/' + hex(scope.id);
          if (seen.has(key)) return requestError(); seen.add(key);
          const first = time(selection.fromTime), last = time(selection.throughTime);
          if (first.value !== null && last.value !== null && first.value > last.value) return requestError();
          return join([scope.kind, vector(scope.id), first.bytes, last.bytes], 55);
        });
        return join([...base, vector(join([uint(rows.length, 1), ...rows], 1761))], 42004);
      }
      case 'preview': case 'import': {
        const wire = requestBytes(request.wire, 1, MAX_WIRE);
        return withRecoveryCode(request.recoveryCode, code => {
          const parts = [...base, vector(wire), uint(code.length, 4), code];
          if (request.kind === 'import') parts.push(requestBytes(request.confirmedId, 32, 32));
          return join(parts, request.kind === 'import' ? 16_841_239 : 16_841_207);
        });
      }
      case 'remove': case 'overview': return join([...base, requestBytes(request.backupId, 32, 32)], 40271);
      case 'page': {
        const scope = scopeBytes(request.scope);
        return join([...base, requestBytes(request.backupId, 32, 32), scope.kind, vector(scope.id), uint(integer(request.offset, 0, 256), 4), uint(integer(request.limit, 1, 16), 1)], 40313);
      }
      default: { const exhaustive: never = request; void exhaustive; return requestError(); }
    }
  } catch { return requestError(); }
}

class Reader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array, maximum: number) {
    if (!(bytes instanceof Uint8Array) || bytes.length > maximum) replyError();
  }
  fixed(length: number): Uint8Array {
    if (length < 0 || length > this.bytes.length - this.offset) return replyError();
    const value = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return value;
  }
  byte(): number { return readByte(this.fixed(1)); }
  vector(maximum = this.bytes.length): Uint8Array {
    const length = readU32(this.fixed(4));
    if (length > maximum) return replyError();
    return this.fixed(length);
  }
  list(maximum: number): Uint8Array[] {
    const count = readU32(this.vector(4));
    if (count > maximum) return replyError();
    const fields: Uint8Array[] = [];
    for (let index = 0; index < count; index++) fields.push(this.vector());
    return fields;
  }
  finish(): void { if (this.offset !== this.bytes.length) replyError(); }
}
function exact(value: Uint8Array, size: number): Uint8Array { if (value.length !== size) return replyError(); return value; }
function view(value: Uint8Array): DataView { return new DataView(value.buffer, value.byteOffset, value.byteLength); }
function readByte(value: Uint8Array): number { return view(exact(value, 1)).getUint8(0); }
function readU32(value: Uint8Array): number { return view(exact(value, 4)).getUint32(0); }
function readU64(value: Uint8Array): string { return view(exact(value, 8)).getBigUint64(0).toString(); }
function field(fields: Uint8Array[], index: number): Uint8Array { const value = fields[index]; if (value === undefined) return replyError(); return value; }
function fieldsOf(value: Uint8Array, count: number): Uint8Array[] {
  const reader = new Reader(value, value.length), fields = reader.list(count); reader.finish();
  if (fields.length !== count) return replyError(); return fields;
}
function listOf(value: Uint8Array, maximum: number): Uint8Array[] { const reader = new Reader(value, value.length), fields = reader.list(maximum); reader.finish(); return fields; }
function start(input: Uint8Array, maximum: number, version = 1): Reader { const reader = new Reader(input, maximum); if (reader.byte() !== version) return replyError(); return reader; }
function decode<T>(body: () => T): T { try { return body(); } catch { return replyError(); } }
function readCode(bytes: Uint8Array): string {
  if (bytes.length < 1 || bytes.length > 4096) return replyError();
  const text = decoder.decode(bytes);
  let length = 0; for (const _char of text) if (++length > 1024) return replyError();
  if (length === 0) return replyError(); return text;
}
export function decodeBackupCreateReply(input: Uint8Array): BackupCreateReply {
  return decode(() => {
    const reader = start(input, 16_801_001, 2), draftId = reader.fixed(32), wire = reader.vector(MAX_WIRE), code = reader.vector(4096); reader.finish();
    if (wire.length === 0) return replyError();
    const recoveryCode = readCode(code);
    return { draftId: new Uint8Array(draftId), wire: new Uint8Array(wire), recoveryCode };
  });
}
export function decodeBackupPendingStateReply(input: Uint8Array): BackupPendingExportState {
  return decode(() => {
    const reader = start(input, 46), tag = reader.byte();
    if (tag === 0 || tag === 2) { reader.finish(); return tag === 0 ? { kind: 'empty' } : { kind: 'repairRequired' }; }
    if (tag !== 1) return replyError();
    const draftId = reader.fixed(32), createdAt = readU64(reader.fixed(8)), wireSize = readU32(reader.fixed(4)); reader.finish();
    if (wireSize < 1 || wireSize > MAX_WIRE) return replyError();
    return { kind: 'pending', draftId: new Uint8Array(draftId), createdAt, wireSize };
  });
}
export function decodeBackupResumeReply(input: Uint8Array): Uint8Array {
  return decode(() => {
    const reader = start(input, 16_796_869), wire = reader.vector(MAX_WIRE); reader.finish();
    if (wire.length === 0) return replyError(); return new Uint8Array(wire);
  });
}
export function decodeBackupDiscardReply(input: Uint8Array): BackupDiscardReply {
  return decode(() => {
    const reader = start(input, 34), draftId = reader.fixed(32), status = reader.byte(); reader.finish();
    if (status !== 1 && status !== 2) return replyError(); return { draftId: new Uint8Array(draftId) };
  });
}
export function decodeBackupRepairReply(input: Uint8Array): void {
  return decode(() => {
    const reader = start(input, 2), status = reader.byte(); reader.finish();
    if (status !== 1 && status !== 2) return replyError();
  });
}
export function decodeBackupImportReply(input: Uint8Array): BackupImportReply {
  return decode(() => {
    const reader = start(input, 34), backupId = reader.fixed(32), disposition = reader.byte(); reader.finish();
    if (disposition !== 1 && disposition !== 2) return replyError();
    return { backupId: new Uint8Array(backupId), disposition };
  });
}
export function decodeBackupRemoveReply(input: Uint8Array): BackupRemoveReply {
  return decode(() => {
    const reader = start(input, 34), backupId = reader.fixed(32), disposition = reader.byte(); reader.finish();
    if (disposition !== 1) return replyError(); return { backupId: new Uint8Array(backupId) };
  });
}
export function decodeBackupListReply(input: Uint8Array): BackupSummary[] {
  return decode(() => {
    const reader = start(input, 4096), rows = reader.list(8); reader.finish();
    const values = rows.map(row => { const fields = fieldsOf(row, 2); return { backupId: exact(field(fields, 0), 32), createdAt: readU64(field(fields, 1)) }; });
    return values.map(value => ({ ...value, backupId: new Uint8Array(value.backupId) }));
  });
}
function readConversation(input: Uint8Array): BackupConversation {
  const fields = fieldsOf(input, 5), kind = readByte(field(fields, 0)), id = field(fields, 1), peer = field(fields, 2), nameBytes = field(fields, 3), messageCount = readU32(field(fields, 4));
  if (messageCount < 1 || messageCount > 256 || nameBytes.length > 96) return replyError();
  const name = decoder.decode(nameBytes);
  if (/\p{Cc}/u.test(name)) return replyError();
  if (kind === 1) return { kind: 'direct', id: exact(id, 16), peer: exact(peer, 32), name, messageCount };
  if (kind === 2) return { kind: 'group', id: exact(id, 32), peer: exact(peer, 0), name, messageCount };
  return replyError();
}
export function decodeBackupOverviewReply(input: Uint8Array): BackupOverview {
  return decode(() => {
    const reader = start(input, 8192), fields = reader.list(10); reader.finish();
    if (fields.length !== 10) return replyError();
    const backupId = exact(field(fields, 0), 32), createdAt = readU64(field(fields, 1));
    const counts = { includedCount: readU32(field(fields, 2)), candidateCount: readU32(field(fields, 3)), omittedTimed: readU32(field(fields, 4)), omittedUnknown: readU32(field(fields, 5)), omittedNontext: readU32(field(fields, 6)), omittedEmpty: readU32(field(fields, 7)), attachmentMessages: readU32(field(fields, 8)) };
    if (counts.includedCount < 1 || counts.includedCount > 4096 || Object.values(counts).some(count => count > 8192)
      || counts.candidateCount !== counts.includedCount + counts.omittedTimed + counts.omittedUnknown + counts.omittedNontext + counts.omittedEmpty
      || counts.attachmentMessages > counts.candidateCount) return replyError();
    const rows = listOf(field(fields, 9), 32);
    if (rows.length < 1) return replyError();
    const conversations = rows.map(readConversation);
    if (conversations.reduce((count, scope) => count + scope.messageCount, 0) !== counts.includedCount) return replyError();
    return { backupId: new Uint8Array(backupId), createdAt, ...counts, conversations: conversations.map(scope => ({ ...scope, id: new Uint8Array(scope.id), peer: new Uint8Array(scope.peer) })) };
  });
}
export function decodeBackupPageReply(input: Uint8Array): BackupPage {
  return decode(() => {
    const reader = start(input, 135168), fields = reader.list(6); reader.finish();
    if (fields.length !== 6) return replyError();
    const backupId = exact(field(fields, 0), 32), kind = readByte(field(fields, 1)), scopeId = field(fields, 2), offset = readU32(field(fields, 3));
    if ((kind !== 1 && kind !== 2) || scopeId.length !== (kind === 1 ? 16 : 32) || offset > 256) return replyError();
    const rows = listOf(field(fields, 5), 16);
    if (offset + rows.length > 256) return replyError();
    const next = new Reader(field(fields, 4), 5), tag = next.byte();
    let nextOffset: number | null = null;
    if (tag === 1) { nextOffset = readU32(next.fixed(4)); if (nextOffset <= offset || nextOffset > 255 || nextOffset !== offset + rows.length) return replyError(); }
    else if (tag !== 0) return replyError();
    next.finish();
    let textBytes = 0;
    const seen = new Set<string>();
    const raw: Omit<BackupRecord, 'text'>[] = [];
    const texts: Uint8Array[] = [];
    for (const row of rows) {
      const values = fieldsOf(row, 8), ordinal = view(exact(field(values, 0), 2)).getUint16(0), direction = readByte(field(values, 1)), messageId = field(values, 2), senderAccount = exact(field(values, 3), 32), senderDevice = exact(field(values, 4), 16), timestamp = readU64(field(values, 5)), omitted = readByte(field(values, 6)), text = field(values, 7);
      const previous = raw[raw.length - 1];
      if (ordinal > 255 || (direction !== 1 && direction !== 2) || (omitted !== 0 && omitted !== 1)
        || (previous !== undefined && previous.ordinal >= ordinal)
        || (kind === 1 ? messageId.length !== 16 || text.length > 32768 : (messageId.length !== 0 && messageId.length !== 32) || text.length > 65346)
        || (text.length === 0 && omitted !== 1)) return replyError();
      if (messageId.length > 0) { const key = hex(messageId); if (seen.has(key)) return replyError(); seen.add(key); }
      textBytes += text.length; if (textBytes > 131072) return replyError();
      raw.push({ ordinal, direction, messageId, senderAccount, senderDevice, timestamp, attachmentOmitted: omitted === 1 }); texts.push(text);
    }
    const decoded = raw.map((row, index) => ({ ...row, text: decoder.decode(field(texts, index)) }));
    const entries = decoded.map(row => ({ ...row, messageId: new Uint8Array(row.messageId), senderAccount: new Uint8Array(row.senderAccount), senderDevice: new Uint8Array(row.senderDevice) }));
    const result = { backupId: new Uint8Array(backupId), scopeId: new Uint8Array(scopeId), offset, nextOffset, entries };
    return kind === 1 ? { ...result, kind: 'direct' } : { ...result, kind: 'group' };
  });
}

export type BackupAttachmentPolicy = 'require' | 'allowOmissions';
export type BackupFileOmission = 'unavailable' | 'expired' | 'unsupported' | 'aboveProfile';
export type BackupFileSlot =
  | { kind: 'included'; slot: number; filename: string; mimeType: string; size: number; token: Uint8Array }
  | { kind: 'omitted'; slot: number; reason: BackupFileOmission };
export type BackupFileCounts = {
  total: number; included: number; unavailable: number; expired: number; unsupported: number; aboveProfile: number;
};
export type BackupContentOverview = BackupOverview & { policy: BackupAttachmentPolicy; files: BackupFileCounts };
export type BackupContentRecord = Omit<BackupRecord, 'attachmentOmitted'> & { attachments: BackupFileSlot[] };
type BackupContentPageFields = Omit<BackupPageFields, 'entries'> & { entries: BackupContentRecord[] };
export type BackupContentPage = (BackupContentPageFields & { kind: 'direct' }) | (BackupContentPageFields & { kind: 'group' });
export type BackupChunkSelection = { kind: BackupScope['kind']; token: Uint8Array; ordinal: number; slot: number; chunk: number };
export type BackupContentChunk = BackupChunkSelection & {
  backupId: Uint8Array; scopeId: Uint8Array; totalSize: number; bytes: Uint8Array;
};
export type BackupReadonlyOverview = { kind: 'text'; value: BackupOverview } | { kind: 'content'; value: BackupContentOverview };
export type BackupReadonlyPage =
  | { kind: 'text'; value: BackupPage }
  | { kind: 'content'; value: BackupContentPage }
  | { kind: 'chunk'; value: BackupContentChunk };

export function encodeBackupChunkRequest(action: BackupAction, backupId: Uint8Array, selection: BackupChunkSelection): Uint8Array {
  try {
    const base = encodeBackupRequest(action, { kind: 'overview', backupId });
    const tag = selection.kind === 'direct' ? 3 : selection.kind === 'group' ? 4 : requestError();
    return join([base, uint(tag, 1), vector(requestBytes(selection.token, 32, 32)),
      uint(integer(selection.ordinal, 0, 255), 1), uint(integer(selection.slot, 0, 9), 1),
      uint(integer(selection.chunk, 0, 255), 1)], 40311);
  } catch { return requestError(); }
}

export function decodeReadonlyBackupOverviewReply(input: Uint8Array): BackupReadonlyOverview {
  return decode(() => {
    if (!(input instanceof Uint8Array)) return replyError();
    if (input[0] === 1) return { kind: 'text', value: decodeBackupOverviewReply(input) };
    const reader = start(input, 8192, 2), fields = reader.list(12); reader.finish();
    if (fields.length !== 12) return replyError();
    const backupId = exact(field(fields, 0), 32), createdAt = readU64(field(fields, 1));
    const counts = {
      includedCount: readU32(field(fields, 2)), candidateCount: readU32(field(fields, 3)),
      omittedTimed: readU32(field(fields, 4)), omittedUnknown: readU32(field(fields, 5)),
      omittedNontext: readU32(field(fields, 6)), omittedEmpty: readU32(field(fields, 7)),
      attachmentMessages: readU32(field(fields, 8)),
    };
    if (counts.includedCount < 1 || counts.includedCount > 4096 || Object.values(counts).some(n => n > 8192)
      || counts.candidateCount !== counts.includedCount + counts.omittedTimed + counts.omittedUnknown + counts.omittedNontext + counts.omittedEmpty
      || counts.attachmentMessages > counts.candidateCount) return replyError();
    const policyTag = readByte(field(fields, 9));
    const policy: BackupAttachmentPolicy = policyTag === 0 ? 'require' : policyTag === 1 ? 'allowOmissions' : replyError();
    const fc = fieldsOf(field(fields, 10), 6);
    const files: BackupFileCounts = {
      total: readU32(field(fc, 0)), included: readU32(field(fc, 1)), unavailable: readU32(field(fc, 2)),
      expired: readU32(field(fc, 3)), unsupported: readU32(field(fc, 4)), aboveProfile: readU32(field(fc, 5)),
    };
    const omitted = files.unavailable + files.expired + files.unsupported + files.aboveProfile;
    if (Object.values(files).some(n => n > 4096) || files.total !== files.included + omitted
      || files.total > counts.includedCount * 10 || files.total > counts.attachmentMessages * 10 || (policy === 'require' && omitted !== 0)) return replyError();
    const rows = listOf(field(fields, 11), 32);
    if (rows.length < 1) return replyError();
    const conversations = rows.map(readConversation);
    const seen = new Set<string>();
    for (const scope of conversations) {
      const key = scope.kind + '/' + hex(scope.id);
      if (seen.has(key)) return replyError();
      seen.add(key);
    }
    if (conversations.reduce((n, scope) => n + scope.messageCount, 0) !== counts.includedCount) return replyError();
    return { kind: 'content', value: { backupId: new Uint8Array(backupId), createdAt, ...counts, policy, files,
      conversations: conversations.map(scope => ({ ...scope, id: new Uint8Array(scope.id), peer: new Uint8Array(scope.peer) })) } };
  });
}

function readContentSlot(input: Uint8Array, index: number): BackupFileSlot {
  const reader = new Reader(input, input.length), fields = reader.list(6); reader.finish();
  const slot = readByte(field(fields, 0)), kind = readByte(field(fields, 1));
  if (slot !== index || slot > 9) return replyError();
  if (kind === 0) {
    if (fields.length !== 6) return replyError();
    const name = field(fields, 2), mime = field(fields, 3), size = readU32(field(fields, 4)), token = exact(field(fields, 5), 32);
    if (name.length > 255 || mime.length < 1 || mime.length > 127 || size < 1 || size > 16777216) return replyError();
    return { kind: 'included', slot, filename: decoder.decode(name), mimeType: decoder.decode(mime), size, token };
  }
  if (fields.length !== 2) return replyError();
  const reason: BackupFileOmission = kind === 1 ? 'unavailable' : kind === 2 ? 'expired'
    : kind === 3 ? 'unsupported' : kind === 4 ? 'aboveProfile' : replyError();
  return { kind: 'omitted', slot, reason };
}

function readContentPage(reader: Reader): BackupContentPage {
  const fields = reader.list(6); reader.finish();
  if (fields.length !== 6) return replyError();
  const backupId = exact(field(fields, 0), 32), kind = readByte(field(fields, 1)), scopeId = field(fields, 2), offset = readU32(field(fields, 3));
  if ((kind !== 1 && kind !== 2) || scopeId.length !== (kind === 1 ? 16 : 32) || offset > 256) return replyError();
  const rows = listOf(field(fields, 5), 16);
  if (offset + rows.length > 256) return replyError();
  const next = new Reader(field(fields, 4), 5), tag = next.byte();
  let nextOffset: number | null = null;
  if (tag === 1) {
    nextOffset = readU32(next.fixed(4));
    if (nextOffset <= offset || nextOffset > 255 || nextOffset !== offset + rows.length) return replyError();
  } else if (tag !== 0) return replyError();
  next.finish();
  const raw: BackupContentRecord[] = [];
  const seen = new Set<string>();
  let textBytes = 0;
  for (const row of rows) {
    const values = fieldsOf(row, 8), ordinal = view(exact(field(values, 0), 2)).getUint16(0), direction = readByte(field(values, 1));
    const messageId = field(values, 2), senderAccount = exact(field(values, 3), 32), senderDevice = exact(field(values, 4), 16);
    const timestamp = readU64(field(values, 5)), text = field(values, 6), slots = listOf(field(values, 7), 10);
    const previous = raw[raw.length - 1];
    if (ordinal > 255 || (direction !== 1 && direction !== 2) || (previous !== undefined && previous.ordinal >= ordinal)
      || (kind === 1 ? messageId.length !== 16 || text.length > 32768 : (messageId.length !== 0 && messageId.length !== 32) || text.length > 65346)
      || (text.length === 0 && slots.length === 0)) return replyError();
    if (messageId.length > 0) {
      const key = hex(messageId);
      if (seen.has(key)) return replyError();
      seen.add(key);
    }
    textBytes += text.length;
    if (textBytes > 131072) return replyError();
    raw.push({ ordinal, direction, messageId, senderAccount, senderDevice, timestamp,
      text: decoder.decode(text), attachments: slots.map(readContentSlot) });
  }
  const entries = raw.map(row => ({ ...row, messageId: new Uint8Array(row.messageId),
    senderAccount: new Uint8Array(row.senderAccount), senderDevice: new Uint8Array(row.senderDevice),
    attachments: row.attachments.map(slot => slot.kind === 'included' ? { ...slot, token: new Uint8Array(slot.token) } : slot) }));
  const result = { backupId: new Uint8Array(backupId), scopeId: new Uint8Array(scopeId), offset, nextOffset, entries };
  return kind === 1 ? { ...result, kind: 'direct' } : { ...result, kind: 'group' };
}

function readContentChunk(reader: Reader): BackupContentChunk {
  const fields = reader.list(9); reader.finish();
  if (fields.length !== 9) return replyError();
  const backupId = exact(field(fields, 0), 32), kind = readByte(field(fields, 1)), scopeId = field(fields, 2);
  const ordinal = view(exact(field(fields, 3), 2)).getUint16(0), slot = readByte(field(fields, 4)), chunk = readByte(field(fields, 5));
  const totalSize = readU32(field(fields, 6)), token = exact(field(fields, 7), 32), data = field(fields, 8);
  if ((kind !== 1 && kind !== 2) || scopeId.length !== (kind === 1 ? 16 : 32) || ordinal > 255 || slot > 9
    || totalSize < 1 || totalSize > 16777216 || chunk * 65536 >= totalSize
    || data.length !== Math.min(65536, totalSize - chunk * 65536)) return replyError();
  return { backupId: new Uint8Array(backupId), kind: kind === 1 ? 'direct' : 'group', scopeId: new Uint8Array(scopeId),
    ordinal, slot, chunk, totalSize, token: new Uint8Array(token), bytes: new Uint8Array(data) };
}

export function decodeReadonlyBackupPageReply(input: Uint8Array): BackupReadonlyPage {
  return decode(() => {
    if (!(input instanceof Uint8Array)) return replyError();
    if (input[0] === 1) return { kind: 'text', value: decodeBackupPageReply(input) };
    const reader = start(input, 135168, 2), tag = reader.byte();
    if (tag === 0) return { kind: 'content', value: readContentPage(reader) };
    if (tag === 1) return { kind: 'chunk', value: readContentChunk(reader) };
    return replyError();
  });
}

export type BackupContentCreateRequest = { selections: BackupSelection[]; policy: BackupAttachmentPolicy };
export function encodeBackupContentCreateRequest(action: BackupAction, request: BackupContentCreateRequest): Uint8Array {
  try {
    const tag = request.policy === 'require' ? 2 : request.policy === 'allowOmissions' ? 3 : requestError();
    const encoded = encodeBackupRequest(action, { kind: 'create', selections: request.selections });
    encoded[0] = tag;
    return encoded;
  } catch { return requestError(); }
}
