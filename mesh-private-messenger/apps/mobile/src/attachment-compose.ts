import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { encodeAttachmentReferences } from './codec.ts';
import { uploadAttachment, type UploadedAttachment } from './network';
import { preparePaidAttachment, previewPaidAttachment, stagePaidAttachment, uploadStagedPaidAttachment,
  type PaidAttachmentRecord } from './paid-attachments';
import type { AttachmentSelection } from './attachment-selections.ts';
export type AttachmentUpload = {
  filename: string; mimeType: string; size: number; price: number;
  purpose?: 'live' | 'test'; nonce?: Uint8Array; smallBytes?: Uint8Array; available?: number;
  transfer(database: string, authorization: Uint8Array, progress?: (completed: number, total: number, staging?: boolean) => void): Promise<UploadedAttachment>;
  dispose(): void;
};
export async function sendAttachmentUploads(database: string, files: AttachmentUpload[],
  authorize: () => Promise<Uint8Array>,
  send: (reference?: Uint8Array) => Promise<void>, progress?: (completed: number, total: number, staging?: boolean) => void) {
  const uploaded: UploadedAttachment[] = [];
  try {
    const authorization = files.length ? await authorize() : new Uint8Array();
    for (const file of files) uploaded.push(await file.transfer(database, authorization, (done, total, staging) =>
      progress?.(uploaded.length + done / total, files.length, staging)));
  } catch (error) {
    await Promise.allSettled(uploaded.flatMap((file, index) => files[index]!.nonce ? [] : [file.discard()]));
    throw error;
  }
  // A failed send can already be durable in the outbox. Keep every object.
  await send(uploaded.length ? encodeAttachmentReferences(uploaded.map(file => file.reference)) : undefined);
  return uploaded;
}
export function createAttachmentComposeServices(deps: Pick<ScopedClient, 'assertCurrent' | 'runPrivate'> & { uploadAttachment: typeof uploadAttachment; preparePaidAttachment: typeof preparePaidAttachment; previewPaidAttachment: typeof previewPaidAttachment; stagePaidAttachment: typeof stagePaidAttachment; uploadStagedPaidAttachment: typeof uploadStagedPaidAttachment }) {
const { uploadAttachment, preparePaidAttachment, previewPaidAttachment, stagePaidAttachment, uploadStagedPaidAttachment } = deps;
// The source belongs only to this selection. Once staged, retries can only use
// the saved encrypted parts; a replacement file never enters this intent.
async function previewAttachmentSelections(database: string, selections: AttachmentSelection[]): Promise<AttachmentUpload[]> {
  const uploads: AttachmentUpload[] = [];
  try {
    for (const selection of selections) {
      if (selection.kind === 'small') {
        uploads.push({ ...selection, price: 0, smallBytes: selection.bytes,
          transfer: (db, authorization, progress) => deps.runPrivate(() => uploadAttachment(db, selection, authorization, progress)) });
        continue;
      }
      const preview = await previewPaidAttachment(database, selection.size);
      let prepared = false; let staged = false; let disposed = false;
      const dispose = () => { if (!disposed) { disposed = true; selection.dispose(); } };
      uploads.push({ filename: selection.filename, mimeType: selection.mimeType, size: selection.size,
        price: preview.price, purpose: preview.purpose, nonce: preview.nonce, available: preview.available, dispose,
        transfer(db, authorization, progress) { return deps.runPrivate(async () => {
          if (!staged) {
            if (disposed) throw new Error('paid_attachment_staging_incomplete');
            if (!prepared) {
              await preparePaidAttachment(db, preview.nonce, selection.filename, selection.mimeType, selection.size, authorization);
              prepared = true;
            }
            await stagePaidAttachment(db, preview.nonce, selection.source, (done, total) => progress?.(done, total, true));
            staged = true; dispose();
          }
          return uploadStagedPaidAttachment(db, preview.nonce, selection.size, authorization, progress);
        }); } });
    }
    return uploads;
  } catch (error) {
    for (const selection of selections) selection.dispose();
    throw error;
  }
}
function savedAttachmentUpload(row: PaidAttachmentRecord): AttachmentUpload {
  // Construct a local handle from already-held metadata. Every later transfer
  // performs its own asynchronous native admission and completion checks.
  deps.assertCurrent();
  return { filename: row.filename, mimeType: row.mimeType, size: row.size, price: 0, nonce: row.nonce,
    dispose() {}, transfer(database, authorization, progress) { return deps.runPrivate(async () => {
      if (row.status !== 0 && row.status !== 1) throw new Error('paid_attachment_not_reserved');
      return uploadStagedPaidAttachment(database, row.nonce, row.size, authorization, progress);
    }); } };
}
return Object.freeze({
  previewAttachmentSelections: (...args: Parameters<typeof previewAttachmentSelections>) => deps.runPrivate(() => previewAttachmentSelections(...args)),
  savedAttachmentUpload,
});
}
let legacyScopeServices: ReturnType<typeof createAttachmentComposeServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createAttachmentComposeServices({ assertCurrent: () => {}, runPrivate: operation => operation(), uploadAttachment, preparePaidAttachment, previewPaidAttachment, stagePaidAttachment, uploadStagedPaidAttachment });
}
export const previewAttachmentSelections: ReturnType<typeof createAttachmentComposeServices>['previewAttachmentSelections'] = (...args) => desktopCompatibility().previewAttachmentSelections(...args);
export const savedAttachmentUpload: ReturnType<typeof createAttachmentComposeServices>['savedAttachmentUpload'] = (...args) => desktopCompatibility().savedAttachmentUpload(...args);
