import { runPrivateOwned } from './private-resource';
import { protectedHandle, protectedMetadata } from './app-lock';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { attachmentFileName, attachmentSelectionError } from './attachments.ts';
import type { OutgoingAttachment } from './network.ts';
import { attachmentSelectionLimit, MAXIMUM_ATTACHMENT_SIZE, smallAttachmentSelection, type AttachmentSelection } from './attachment-selections.ts';
import type { createAttachmentRangeServices } from './attachment-range-io';
export type IncomingFileHandlers = {
  onDragging: (dragging: boolean) => void;
  onFiles: (files: OutgoingAttachment[]) => void;
  onSelections?: (files: AttachmentSelection[]) => void;
  onError: (message: string) => void;
};
export type IncomingAttachmentReader = (subscription: string) => Promise<AttachmentSelection[]>;
type AttachmentFileOptions = {
  previewTransport: 'native-file' | 'desktop';
  incoming?: { listen(handlers: IncomingFileHandlers, read: IncomingAttachmentReader): () => void };
};
type SelectedSource = { selectionId: string; filename: string; mimeType: string; size: number };
export function createAttachmentFileServices(deps: Pick<ScopedClient, 'assertCurrent' | 'runPrivate' | 'onDispose' | 'protectedFile' | 'cleanupProtectedFile'> & ReturnType<typeof createAttachmentRangeServices>,
  { previewTransport, incoming }: AttachmentFileOptions = { previewTransport: 'native-file' }) {
  const previews = new Map<string, string>();
  function closePreview(uri: string): void {
    const handle = previews.get(uri); if (!handle) return; previews.delete(uri);
    void deps.cleanupProtectedFile('releasePreview', { version: 1, handle }).catch(() => {});
  }
  // Native startup/revoke owns orphan cleanup. Old React cleanup can discard
  // only handles belonging to this immutable epoch, never a fresh tree's files.
  function discardPreviews(): void {
    previews.clear(); void deps.cleanupProtectedFile('discardPreviews', { version: 1 }).catch(() => {});
  }
  deps.onDispose(discardPreviews);
  async function attachmentPreviewUri(key: string, mimeType: string, bytes: Uint8Array): Promise<string> {
    if (bytes.length < 1 || bytes.length > MAXIMUM_ATTACHMENT_SIZE || !key || key.length > 256) throw Error('invalid_preview');
    const row = protectedMetadata(await deps.protectedFile('writePreview', { version: 1, key, mimeType }, bytes), ['handle', 'uri']);
    const handle = protectedHandle(row.handle);
    if (typeof row.uri !== 'string' || row.uri.length > 4096 ||
        (previewTransport === 'desktop' ? row.uri !== `morse-private://preview/${handle}` : !row.uri.startsWith('file:///'))) {
      void deps.cleanupProtectedFile('releasePreview', { version: 1, handle }).catch(() => {}); throw Error('invalid_file_response');
    }
    previews.set(row.uri, handle); return row.uri;
  }
  async function fileToAttachmentSelection(choiceId: string, file: SelectedSource): Promise<AttachmentSelection> {
    const error = attachmentSelectionLimit([file.size]); if (error) throw new Error(error);
    const filename = attachmentFileName(file.filename, file.mimeType);
    const source = await deps.openAttachmentRangeSource(choiceId, file.selectionId, file.size);
    if (file.size > MAXIMUM_ATTACHMENT_SIZE) return { kind: 'large', filename, mimeType: file.mimeType, size: file.size, source, dispose: () => source.close() };
    const bytes = new Uint8Array(file.size);
    try {
      for (let offset = 0; offset < file.size; offset += 65_536) {
        const chunk = await source.read(offset, Math.min(65_536, file.size - offset));
        bytes.set(chunk, offset); chunk.fill(0);
      }
      deps.assertCurrent();
      return { ...smallAttachmentSelection({ filename, mimeType: file.mimeType, bytes }), dispose: () => bytes.fill(0) };
    } catch (error) { bytes.fill(0); throw error; }
    finally { source.close(); }
  }
  // Reads only a native-owned picker choice through current epoch-bound IO.
  // An old picker action cannot read it or resume itself after relock.
  async function pickAttachmentSelections(): Promise<AttachmentSelection[]> {
    const context = { version: 1, purpose: 'attachment' };
    let row = protectedMetadata(await deps.protectedFile('pendingChoice', context), ['choiceId', 'files']);
    if (row.choiceId === undefined) {
      row = protectedMetadata(await deps.protectedFile('chooseSource', context), ['choiceId', 'files', 'cancelled']);
      if (row.cancelled === true) return [];
    }
    return readSelectionChoice(row);
  }
  async function readSelectionChoice(row: ReturnType<typeof protectedMetadata>): Promise<AttachmentSelection[]> {
    const choiceId = protectedHandle(row.choiceId);
    if (!Array.isArray(row.files) || row.files.length < 1 || row.files.length > 10) throw Error('invalid_file_response');
    const ids = new Set<string>();
    const files = row.files.map(value => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('invalid_file_response');
      const file = value as Record<string, unknown>;
      if (Object.keys(file).some(key => !['selectionId','filename','mimeType','size'].includes(key)) ||
          typeof file.filename !== 'string' || file.filename.length > 255 || typeof file.mimeType !== 'string' || file.mimeType.length > 255 ||
          typeof file.size !== 'number' || !Number.isSafeInteger(file.size)) throw Error('invalid_file_response');
      const selectionId = protectedHandle(file.selectionId); if (ids.has(selectionId)) throw Error('invalid_file_response'); ids.add(selectionId);
      return { selectionId, filename: file.filename, mimeType: file.mimeType, size: file.size };
    });
    const error = attachmentSelectionLimit(files.map(file => file.size)); if (error) throw new Error(error);
    const selected: AttachmentSelection[] = [];
    try { for (const file of files) selected.push(await fileToAttachmentSelection(choiceId, file)); return selected; }
    catch (error) { selected.forEach(file => file.dispose()); throw error; }
  }
  async function readIncomingSelections(subscription: string): Promise<AttachmentSelection[]> {
    protectedHandle(subscription);
    const row = protectedMetadata(await deps.protectedFile('pendingChoice', { version: 1, purpose: 'attachment', subscription }), ['choiceId', 'files']);
    if (row.choiceId === undefined) {
      if (row.files !== undefined) throw Error('invalid_file_response');
      return [];
    }
    return readSelectionChoice(row);
  }
  async function pickAttachmentFiles(): Promise<OutgoingAttachment[]> {
    const selected = await pickAttachmentSelections();
    const error = attachmentSelectionError(selected.map(file => file.size));
    if (error || selected.some(file => file.kind !== 'small')) { selected.forEach(file => file.dispose()); throw Error(error ?? 'attachment_too_large'); }
    return selected.map(file => { if (file.kind !== 'small') throw Error('attachment_too_large'); return { filename: file.filename, mimeType: file.mimeType, bytes: file.bytes }; });
  }
  // No bytes cross the document picker boundary. The fresh explicit Save
  // reacquires its bytes; native stages, verifies, and fences each output chunk.
  async function saveAttachmentFile(filename: string, mimeType: string, bytes: Uint8Array, signal?: AbortSignal, sourceContext?: string): Promise<boolean> {
    if (signal?.aborted) return false;
    if (bytes.length < 1 || bytes.length > MAXIMUM_ATTACHMENT_SIZE) throw Error('invalid_attachment_size');
    if (!sourceContext) {
      const row = protectedMetadata(await deps.protectedFile('digest', { version: 1 }, bytes), ['digest']);
      if (typeof row.digest !== 'string' || !/^[0-9a-f]{64}$/.test(row.digest)) throw Error('invalid_file_response');
      sourceContext = `digest/${row.digest}`;
    }
    const sink = await deps.createAttachmentRangeSink(filename, mimeType, bytes.length, sourceContext);
    if (!sink) return false;
    try {
      for (let offset = 0; offset < bytes.length; offset += 65_536) {
        if (signal?.aborted) { await sink.abort(); return false; }
        await sink.write(offset, bytes.subarray(offset, Math.min(bytes.length, offset + 65_536)));
      }
      if (signal?.aborted) { await sink.abort(); return false; }
      await sink.finish(); return true;
    } catch (error) { await sink.abort().catch(() => {}); throw error; }
  }
  // Desktop supplies native intake; mobile keeps its explicit picker flow.
  function listenForIncomingFiles(handlers: IncomingFileHandlers): () => void {
    return incoming?.listen(handlers, subscription => runPrivateOwned({ scope: deps, operation: () => readIncomingSelections(subscription), discard: files => { for (const file of files) file.dispose(); } })) ?? (() => {});
  }
  return Object.freeze({
    pickAttachmentFiles: () => runPrivateOwned({ scope: deps, operation: pickAttachmentFiles, discard: files => { for (const file of files) file.bytes.fill(0); } }),
    pickAttachmentSelections: () => runPrivateOwned({ scope: deps, operation: pickAttachmentSelections, discard: files => { for (const file of files) file.dispose(); } }),
    saveAttachmentFile: (...args: Parameters<typeof saveAttachmentFile>) => deps.runPrivate(() => saveAttachmentFile(...args)),
    attachmentPreviewUri: (...args: Parameters<typeof attachmentPreviewUri>) => runPrivateOwned({ scope: deps, operation: () => attachmentPreviewUri(...args), discard: closePreview }),
    listenForIncomingFiles: (...args: Parameters<typeof listenForIncomingFiles>) => { deps.assertCurrent(); return listenForIncomingFiles(...args); },
    releasePreviewUri: closePreview, discardPreviews,
  });
}
// Desktop resolves attachment-io.web.ts and retains its existing system adapter.
export const pickAttachmentFiles: ReturnType<typeof createAttachmentFileServices>['pickAttachmentFiles'] = () => { throw Error('scoped_client_required'); };
export const pickAttachmentSelections: ReturnType<typeof createAttachmentFileServices>['pickAttachmentSelections'] = () => { throw Error('scoped_client_required'); };
export const saveAttachmentFile: ReturnType<typeof createAttachmentFileServices>['saveAttachmentFile'] = () => { throw Error('scoped_client_required'); };
export const discardPreviews: ReturnType<typeof createAttachmentFileServices>['discardPreviews'] = () => { throw Error('scoped_client_required'); };
export const attachmentPreviewUri: ReturnType<typeof createAttachmentFileServices>['attachmentPreviewUri'] = () => { throw Error('scoped_client_required'); };
export const releasePreviewUri: ReturnType<typeof createAttachmentFileServices>['releasePreviewUri'] = () => { throw Error('scoped_client_required'); };
export const listenForIncomingFiles: ReturnType<typeof createAttachmentFileServices>['listenForIncomingFiles'] = () => { throw Error('scoped_client_required'); };
