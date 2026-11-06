import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import {
  credit_attachment_prepare_export, credit_attachment_recover_export,
  credit_attachment_grant_export, credit_attachment_upload_export,
  credit_attachment_complete_export, credit_attachment_delete_export, credit_attachment_part_export,
  credit_attachment_part_recover_export, credit_attachment_prune_export,
  attachment_fetch_chunk_export, credit_attachment_preview_export, credit_attachments_export,
  attachment_download_plan_export,
} from '../modules/mesh-messenger';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const CHUNK = 65_536;
const MAX_SIZE = 536_870_912;
const hex = (b: Uint8Array) => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((n, i) => n === b[i]);
function u32(n: number) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error('invalid_paid_attachment');
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b;
}
function vectors(parts: Uint8Array[]) {
  const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length + 4, 0));
  let at = 0;
  for (const part of parts) { bytes.set(u32(part.length), at); bytes.set(part, at + 4); at += 4 + part.length; }
  return bytes;
}
function packet(database: string, ...values: Uint8Array[]) {
  const parts = [encoder.encode(database), ...values];
  const body = vectors(parts); const bytes = new Uint8Array(body.length + 4);
  bytes.set(u32(parts.length)); bytes.set(body, 4); return bytes;
}
function origin(value: string) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value) throw new Error('invalid_paid_attachment');
  return value;
}
function validSize(size: number) {
  if (!Number.isSafeInteger(size) || size <= 16_777_216 || size > MAX_SIZE) throw new Error('invalid_paid_attachment_size');
}
export type PaidAttachmentPlan = {
  nonce: Uint8Array; operationId: Uint8Array; status: number; revision: bigint;
  origin: string; path: string; body: Uint8Array; reference: Uint8Array;
  manifest: Uint8Array; complete: Uint8Array; remove: Uint8Array;
  objectId: Uint8Array; uploadCapability: Uint8Array;
};
export // This only unwraps the native transport plan. Mesh authenticates the saved
// grant, computes the price, chooses tokens and validates every signed receipt.
function parsePaidAttachmentPlan(input: Uint8Array): PaidAttachmentPlan {
  if (input.length < 4 || input.length > 100_000) throw new Error('invalid_paid_attachment');
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  if (view.getUint32(0) !== 12) throw new Error('invalid_paid_attachment');
  const parts: Uint8Array[] = []; let at = 4;
  for (let i = 0; i < 12; i++) {
    if (at + 4 > input.length) throw new Error('invalid_paid_attachment');
    const size = view.getUint32(at); at += 4;
    if (size > input.length - at) throw new Error('invalid_paid_attachment');
    parts.push(input.slice(at, at + size)); at += size;
  }
  const [tag, nonce, id, status, revision, host, path, body, reference, manifest, complete, remove] = parts as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  if (at !== input.length || decoder.decode(tag) !== '\u0001MCA' || nonce.length !== 32 || id.length !== 32 ||
      status.length !== 1 || status[0]! > 2 || revision.length !== 8 || body.length > 88_355 ||
      reference.length < 1 || reference.length > 1_024 || manifest.length < 1 || manifest.length > 514 ||
      complete.length !== 68 || remove.length !== 68 || decoder.decode(complete.subarray(0, 4)) !== '\u0001OCP' ||
      decoder.decode(remove.subarray(0, 4)) !== '\u0001ODL' || !equal(complete.subarray(4), remove.subarray(4)) ||
      (status[0] === 2 ? path.length !== 0 || body.length !== 0 : decoder.decode(path) !== '/v1/attachments/paid-grant' || body.length === 0)) {
    throw new Error('invalid_paid_attachment');
  }
  return { nonce, operationId: id, status: status[0]!, revision: new DataView(revision.buffer).getBigUint64(0),
    origin: origin(decoder.decode(host)), path: decoder.decode(path), body, reference, manifest, complete, remove,
    objectId: complete.slice(4, 36), uploadCapability: complete.slice(36) };
}
export type AttachmentRangeSource = { size: number; read(offset: number, length: number): Promise<Uint8Array> };
export type AttachmentRangeSink = {
  write(offset: number, bytes: Uint8Array): Promise<void>;
  finish(): Promise<void>;
  abort(): Promise<void>;
};
function completionStatus(bytes: Uint8Array): boolean {
  if (bytes.length !== 1 || bytes[0]! > 1) throw new Error('invalid_paid_attachment');
  return bytes[0] === 1;
}
function fields(input: Uint8Array, maximum: number): Uint8Array[] {
  if (input.length < 4 || input.length > 200_000) throw new Error('invalid_paid_attachment');
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const count = view.getUint32(0);
  if (count > maximum) throw new Error('invalid_paid_attachment');
  const output: Uint8Array[] = []; let at = 4;
  for (let index = 0; index < count; index++) {
    if (at + 4 > input.length) throw new Error('invalid_paid_attachment');
    const size = view.getUint32(at); at += 4;
    if (size > input.length - at) throw new Error('invalid_paid_attachment');
    output.push(input.slice(at, at + size)); at += size;
  }
  if (at !== input.length) throw new Error('invalid_paid_attachment');
  return output;
}
const numberField = (bytes: Uint8Array): number => {
  if (bytes.length !== 4) throw new Error('invalid_paid_attachment');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
};
const wideField = (bytes: Uint8Array): bigint => {
  if (bytes.length !== 8) throw new Error('invalid_paid_attachment');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0);
};
const nonzeroKey = (bytes: Uint8Array): boolean => bytes.length === 32 && bytes.some(byte => byte !== 0);
export type PaidAttachmentPreview = {
  nonce: Uint8Array; purpose: 'live' | 'test'; size: number; price: number;
  available: number; delayed: number; reserved: number; revision: bigint;
};
export type PaidAttachmentRecord = {
  nonce: Uint8Array; operationId: Uint8Array; status: 0 | 1 | 2 | 3; filename: string; mimeType: string;
  size: number; price: number; actionExpiresAt: bigint; objectExpiresAt: bigint; cleanupCursor: number; chunkCount: number;
};
export type PaidAttachmentInventory = { revision: bigint; items: PaidAttachmentRecord[] };
export type AttachmentDownloadPlan = {
  version: 1 | 2 | 4; origin: string; pathPrefix: string; reference: Uint8Array; objectId: Uint8Array;
  downloadCapability: Uint8Array; filename: string; mimeType: string; size: number; chunkCount: number; chunkSize: number;
};
export function createPaidAttachmentServices(deps: Pick<ScopedClient, 'runPrivate' | 'attachment_download_plan_export' | 'attachment_fetch_chunk_export' | 'credit_attachment_complete_export' | 'credit_attachment_delete_export' | 'credit_attachment_grant_export' | 'credit_attachment_part_export' | 'credit_attachment_part_recover_export' | 'credit_attachment_prepare_export' | 'credit_attachment_preview_export' | 'credit_attachment_prune_export' | 'credit_attachment_recover_export' | 'credit_attachment_upload_export' | 'credit_attachments_export' | 'onDispose'>) {
const { credit_attachment_prepare_export, credit_attachment_recover_export, credit_attachment_grant_export, credit_attachment_upload_export, credit_attachment_complete_export, credit_attachment_delete_export, credit_attachment_part_export, credit_attachment_part_recover_export, credit_attachment_prune_export, attachment_fetch_chunk_export, credit_attachment_preview_export, credit_attachments_export, attachment_download_plan_export } = deps;
async function preparePaidAttachment(database: string, nonce: Uint8Array, filename: string, mime: string, size: number, authorization: Uint8Array) {
  validSize(size);
  const plan = parsePaidAttachmentPlan(await credit_attachment_prepare_export(packet(database, nonce, encoder.encode(filename), encoder.encode(mime), u32(size), authorization)));
  if (!equal(plan.nonce, nonce)) throw new Error('invalid_paid_attachment');
  return plan;
}
async function recoverPaidAttachment(database: string, nonce: Uint8Array) {
  const plan = parsePaidAttachmentPlan(await credit_attachment_recover_export(packet(database, nonce)));
  if (!equal(plan.nonce, nonce)) throw new Error('invalid_paid_attachment');
  return plan;
}
async function deletePaidAttachment(database: string, nonce: Uint8Array) {
  for (let step = 0; step < 66; step++) {
    if (completionStatus(await credit_attachment_delete_export(packet(database, nonce)))) return;
  }
  throw new Error('paid_attachment_cleanup_pending');
}
// Only a newly selected, still-held source may fill missing parts. The UI
// never calls this after restart or substitutes a reselected same-size file.
async function stagePaidAttachment(database: string, nonce: Uint8Array, source: AttachmentRangeSource,
  progress?: (completed: number, total: number) => void): Promise<void> {
  validSize(source.size);
  const saved = (await readPaidAttachments(database)).items.find(item => equal(item.nonce, nonce));
  if (!saved || saved.size !== source.size) throw new Error('paid_attachment_source_changed');
  if (saved.status === 3) throw new Error('paid_attachment_not_reserved');
  if (saved.status === 2) throw new Error('paid_attachment_cancelled');
  const plan = await recoverPaidAttachment(database, nonce);
  if (plan.status === 2) throw new Error('paid_attachment_cancelled');
  const total = Math.ceil(source.size / CHUNK);
  for (let index = 0; index < total; index++) {
    const expected = Math.min(CHUNK, source.size - index * CHUNK);
    let sealed: Uint8Array;
    try { sealed = await credit_attachment_part_recover_export(packet(database, nonce, u32(index))); }
    catch (error) {
      if (!/\blocal_state_not_found\b/.test(String(error))) throw error;
      const plaintext = await source.read(index * CHUNK, expected);
      if (plaintext.length !== expected) throw new Error('paid_attachment_source_changed');
      sealed = await credit_attachment_part_export(packet(database, nonce, u32(index), plaintext));
    }
    if (sealed.length !== expected + 40) throw new Error('invalid_paid_attachment_part');
    progress?.(index + 1, total);
  }
}
async function savedPart(database: string, nonce: Uint8Array, index: number, expected: number): Promise<Uint8Array> {
  let sealed: Uint8Array;
  try { sealed = await credit_attachment_part_recover_export(packet(database, nonce, u32(index))); }
  catch (error) {
    if (/\blocal_state_not_found\b/.test(String(error))) throw new Error('paid_attachment_staging_incomplete');
    throw error;
  }
  if (sealed.length !== expected + 40) throw new Error('invalid_paid_attachment_part');
  return sealed;
}
// Recovery accepts no plaintext source. Scan each bounded saved part before
// any network call, so an interrupted staging pass cannot consume credits.
async function uploadStagedPaidAttachment(database: string, nonce: Uint8Array, size: number, authorization: Uint8Array,
  progress?: (completed: number, total: number) => void) {
  validSize(size);
  const saved = (await readPaidAttachments(database)).items.find(item => equal(item.nonce, nonce));
  if (!saved || saved.size !== size) throw new Error('invalid_paid_attachment_size');
  if (saved.status === 3) throw new Error('paid_attachment_not_reserved');
  if (saved.status === 2) throw new Error('paid_attachment_cancelled');
  let plan = await recoverPaidAttachment(database, nonce);
  if (plan.status === 2) throw new Error('paid_attachment_cancelled');
  const total = Math.ceil(size / CHUNK);
  for (let index = 0; index < total; index++) {
    await savedPart(database, nonce, index, Math.min(CHUNK, size - index * CHUNK));
  }
  // A signed central grant can precede a lost object-store commit. Status1
  // reposts the same CAP to repair that object without another reservation.
  const accepted = parsePaidAttachmentPlan(await credit_attachment_grant_export(packet(database, nonce, authorization)));
  if (accepted.status !== 1 || !equal(accepted.nonce, nonce) || !equal(accepted.operationId, plan.operationId)) throw new Error('invalid_paid_attachment');
  plan = accepted;
  await credit_attachment_upload_export(packet(database, nonce, u32(0)));
  for (let index = 0; index < total; index++) {
    await credit_attachment_upload_export(packet(database, nonce, u32(index + 1)));
    progress?.(index + 1, total);
  }
  for (let step = 0; step < 66; step++) {
    if (completionStatus(await credit_attachment_complete_export(packet(database, nonce)))) {
      return { reference: plan.reference, objectId: plan.objectId, discard: () => deletePaidAttachment(database, nonce) };
    }
  }
  throw new Error('paid_attachment_verification_pending');
}
async function uploadPaidAttachment(database: string, nonce: Uint8Array, source: AttachmentRangeSource, authorization: Uint8Array,
  progress?: (completed: number, total: number) => void) {
  await stagePaidAttachment(database, nonce, source);
  return uploadStagedPaidAttachment(database, nonce, source.size, authorization, progress);
}
async function downloadPaidAttachment(database: string,
  attachment: { reference: Uint8Array; objectId: Uint8Array; downloadCapability: Uint8Array; size: number; chunkCount: number; chunkSize: number },
  sink: AttachmentRangeSink, progress?: (completed: number, total: number) => void) {
  try {
    validSize(attachment.size);
    if (attachment.objectId.length !== 32 || attachment.chunkSize !== CHUNK ||
        attachment.chunkCount !== Math.ceil(attachment.size / CHUNK)) throw new Error('invalid_paid_attachment');
    for (let index = 0; index < attachment.chunkCount; index++) {
      const plaintext = await attachment_fetch_chunk_export(packet(database, attachment.reference, u32(index)));
      if (plaintext.length !== Math.min(CHUNK, attachment.size - index * CHUNK)) throw new Error('invalid_paid_attachment_part');
      await sink.write(index * CHUNK, plaintext);
      progress?.(index + 1, attachment.chunkCount);
    }
    await sink.finish();
  } catch (error) { await sink.abort().catch(() => {}); throw error; }
}
async function prunePaidAttachment(database: string, nonce: Uint8Array, cursor: number): Promise<number> {
  const result = await credit_attachment_prune_export(packet(database, nonce, u32(cursor)));
  if (result.length !== 4) throw new Error('invalid_paid_attachment_cleanup');
  return new DataView(result.buffer, result.byteOffset, result.byteLength).getUint32(0);
}
async function previewPaidAttachment(database: string, size: number): Promise<PaidAttachmentPreview> {
  validSize(size);
  const value = fields(await credit_attachment_preview_export(packet(database, u32(size))), 9);
  if (value.length !== 9 || decoder.decode(value[0]) !== '\u0001APV' || !nonzeroKey(value[1]!) ||
      value[2]!.length !== 1 || value[2]![0]! > 1) throw new Error('invalid_paid_attachment');
  const result = { nonce: value[1]!, purpose: value[2]![0] === 0 ? 'live' as const : 'test' as const,
    size: numberField(value[3]!), price: numberField(value[4]!), available: numberField(value[5]!),
    delayed: numberField(value[6]!), reserved: numberField(value[7]!), revision: wideField(value[8]!) };
  if (result.size !== size || result.price < 1) throw new Error('invalid_paid_attachment');
  return result;
}
async function readPaidAttachments(database: string): Promise<PaidAttachmentInventory> {
  const value = fields(await credit_attachments_export(packet(database)), 130);
  if (value.length < 2 || decoder.decode(value[0]) !== '\u0001AIV') throw new Error('invalid_paid_attachment');
  const items = value.slice(2).map(encoded => {
    const row = fields(encoded, 11);
    if (row.length !== 11 || !nonzeroKey(row[0]!) || !nonzeroKey(row[1]!) || row[2]!.length !== 1 ||
        row[2]![0]! > 3 || row[3]!.length > 255 || row[4]!.length < 1 || row[4]!.length > 127) throw new Error('invalid_paid_attachment');
    const item: PaidAttachmentRecord = { nonce: row[0]!, operationId: row[1]!, status: row[2]![0] as 0 | 1 | 2 | 3,
      filename: decoder.decode(row[3]), mimeType: decoder.decode(row[4]), size: numberField(row[5]!), price: numberField(row[6]!),
      actionExpiresAt: wideField(row[7]!), objectExpiresAt: wideField(row[8]!), cleanupCursor: numberField(row[9]!), chunkCount: numberField(row[10]!) };
    validSize(item.size);
    if (item.price < 1 || item.chunkCount !== Math.ceil(item.size / CHUNK) || item.cleanupCursor > item.chunkCount ||
        item.cleanupCursor % 128 !== 0) throw new Error('invalid_paid_attachment');
    return item;
  });
  if (new Set(items.map(item => hex(item.nonce))).size !== items.length) throw new Error('invalid_paid_attachment');
  return { revision: wideField(value[1]!), items };
}
async function readAttachmentDownloadPlan(database: string, reference: Uint8Array): Promise<AttachmentDownloadPlan> {
  if (reference.length < 1 || reference.length > 1_024) throw new Error('invalid_paid_attachment');
  const value = fields(await attachment_download_plan_export(packet(database, reference)), 11);
  if (value.length !== 11 || decoder.decode(value[0]) !== '\u0001ADP' || value[1]!.length !== 1 ||
      ![1, 2, 4].includes(value[1]![0]!) || !equal(value[4]!, reference) || !nonzeroKey(value[5]!) || !nonzeroKey(value[6]!) ||
      value[7]!.length > 255 || value[8]!.length < 1 || value[8]!.length > 127) throw new Error('invalid_paid_attachment');
  const plan: AttachmentDownloadPlan = { version: value[1]![0] as 1 | 2 | 4, origin: decoder.decode(value[2]), pathPrefix: decoder.decode(value[3]),
    reference: value[4]!, objectId: value[5]!, downloadCapability: value[6]!, filename: decoder.decode(value[7]), mimeType: decoder.decode(value[8]),
    size: numberField(value[9]!), chunkCount: numberField(value[10]!), chunkSize: CHUNK };
  if (plan.version === 2 || (plan.version === 4 && plan.size > 16_777_216)) {
    validSize(plan.size);
    origin(plan.origin);
    if (plan.pathPrefix !== `/v2/objects/${hex(plan.objectId)}/parts/`) throw new Error('invalid_paid_attachment');
  } else if (plan.origin !== '' || plan.pathPrefix !== '' || plan.size < 1 || plan.size > 16_777_216) throw new Error('invalid_paid_attachment');
  if (plan.chunkCount !== Math.ceil(plan.size / CHUNK)) throw new Error('invalid_paid_attachment');
  return plan;
}
return Object.freeze({
  preparePaidAttachment: (...args: Parameters<typeof preparePaidAttachment>) => deps.runPrivate(() => preparePaidAttachment(...args)),
  recoverPaidAttachment: (...args: Parameters<typeof recoverPaidAttachment>) => deps.runPrivate(() => recoverPaidAttachment(...args)),
  stagePaidAttachment: (...args: Parameters<typeof stagePaidAttachment>) => deps.runPrivate(() => stagePaidAttachment(...args)),
  uploadStagedPaidAttachment: (...args: Parameters<typeof uploadStagedPaidAttachment>) => deps.runPrivate(() => uploadStagedPaidAttachment(...args)),
  uploadPaidAttachment: (...args: Parameters<typeof uploadPaidAttachment>) => deps.runPrivate(() => uploadPaidAttachment(...args)),
  downloadPaidAttachment: (...args: Parameters<typeof downloadPaidAttachment>) => deps.runPrivate(() => downloadPaidAttachment(...args)),
  prunePaidAttachment: (...args: Parameters<typeof prunePaidAttachment>) => deps.runPrivate(() => prunePaidAttachment(...args)),
  previewPaidAttachment: (...args: Parameters<typeof previewPaidAttachment>) => deps.runPrivate(() => previewPaidAttachment(...args)),
  readPaidAttachments: (...args: Parameters<typeof readPaidAttachments>) => deps.runPrivate(() => readPaidAttachments(...args)),
  readAttachmentDownloadPlan: (...args: Parameters<typeof readAttachmentDownloadPlan>) => deps.runPrivate(() => readAttachmentDownloadPlan(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createPaidAttachmentServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createPaidAttachmentServices({ runPrivate: operation => operation(), onDispose: () => () => {}, credit_attachment_prepare_export, credit_attachment_recover_export, credit_attachment_grant_export, credit_attachment_upload_export, credit_attachment_complete_export, credit_attachment_delete_export, credit_attachment_part_export, credit_attachment_part_recover_export, credit_attachment_prune_export, attachment_fetch_chunk_export, credit_attachment_preview_export, credit_attachments_export, attachment_download_plan_export });
}
export const preparePaidAttachment: ReturnType<typeof createPaidAttachmentServices>['preparePaidAttachment'] = (...args) => desktopCompatibility().preparePaidAttachment(...args);
export const recoverPaidAttachment: ReturnType<typeof createPaidAttachmentServices>['recoverPaidAttachment'] = (...args) => desktopCompatibility().recoverPaidAttachment(...args);
export const stagePaidAttachment: ReturnType<typeof createPaidAttachmentServices>['stagePaidAttachment'] = (...args) => desktopCompatibility().stagePaidAttachment(...args);
export const uploadStagedPaidAttachment: ReturnType<typeof createPaidAttachmentServices>['uploadStagedPaidAttachment'] = (...args) => desktopCompatibility().uploadStagedPaidAttachment(...args);
export const uploadPaidAttachment: ReturnType<typeof createPaidAttachmentServices>['uploadPaidAttachment'] = (...args) => desktopCompatibility().uploadPaidAttachment(...args);
export const downloadPaidAttachment: ReturnType<typeof createPaidAttachmentServices>['downloadPaidAttachment'] = (...args) => desktopCompatibility().downloadPaidAttachment(...args);
export const prunePaidAttachment: ReturnType<typeof createPaidAttachmentServices>['prunePaidAttachment'] = (...args) => desktopCompatibility().prunePaidAttachment(...args);
export const previewPaidAttachment: ReturnType<typeof createPaidAttachmentServices>['previewPaidAttachment'] = (...args) => desktopCompatibility().previewPaidAttachment(...args);
export const readPaidAttachments: ReturnType<typeof createPaidAttachmentServices>['readPaidAttachments'] = (...args) => desktopCompatibility().readPaidAttachments(...args);
export const readAttachmentDownloadPlan: ReturnType<typeof createPaidAttachmentServices>['readAttachmentDownloadPlan'] = (...args) => desktopCompatibility().readAttachmentDownloadPlan(...args);
