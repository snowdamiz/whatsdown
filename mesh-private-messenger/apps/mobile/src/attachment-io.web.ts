import { invoke } from '@tauri-apps/api/core';

import { attachmentFileName, attachmentSelectionError } from './attachments.ts';
import type { OutgoingAttachment } from './network.ts';
import { attachmentSelectionLimit, MAXIMUM_ATTACHMENT_SIZE, smallAttachmentSelection, type AttachmentSelection } from './attachment-selections.ts';
import { openAttachmentRangeSource } from './attachment-range-io.web.ts';

export async function fileToAttachment(file: File): Promise<OutgoingAttachment> {
  const mimeType = file.type || 'application/octet-stream';
  return { filename: attachmentFileName(file.name, mimeType), mimeType, bytes: new Uint8Array(await file.arrayBuffer()) };
}

export async function fileToAttachmentSelection(file: File): Promise<AttachmentSelection> {
  const error = attachmentSelectionLimit([file.size]);
  if (error) throw new Error(error);
  if (file.size <= MAXIMUM_ATTACHMENT_SIZE) return smallAttachmentSelection(await fileToAttachment(file));
  const source = openAttachmentRangeSource(file);
  const mimeType = file.type || 'application/octet-stream';
  return { kind: 'large', filename: attachmentFileName(file.name, mimeType), mimeType, size: file.size, source,
    dispose() { source.close(); } };
}
async function filesToSelections(files: File[]): Promise<AttachmentSelection[]> {
  const error = attachmentSelectionLimit(files.map(file => file.size));
  if (error) throw new Error(error);
  const selected: AttachmentSelection[] = [];
  try { for (const file of files) selected.push(await fileToAttachmentSelection(file)); return selected; }
  catch (error) { selected.forEach(file => file.dispose()); throw error; }
}

export function pickAttachmentSelections(): Promise<AttachmentSelection[]> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file'; input.multiple = true; input.style.display = 'none';
    input.onchange = () => { const files = Array.from(input.files ?? []); input.remove(); filesToSelections(files).then(resolve, reject); };
    input.oncancel = () => { input.remove(); resolve([]); };
    document.body.append(input); input.click();
  });
}

async function filesToAttachments(files: File[]): Promise<OutgoingAttachment[]> {
  const error = attachmentSelectionError(files.map((file) => file.size));
  if (error) throw new Error(error);
  return Promise.all(files.map(fileToAttachment));
}

// The browser's file dialog, through an input element that never joins the layout.
export function pickAttachmentFiles(): Promise<OutgoingAttachment[]> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.style.display = 'none';
    const finish = (result: Promise<OutgoingAttachment[]>) => {
      input.remove();
      result.then(resolve, reject);
    };
    input.onchange = () => {
      finish(filesToAttachments(Array.from(input.files ?? [])));
    };
    input.oncancel = () => finish(Promise.resolve([]));
    document.body.append(input);
    input.click();
  });
}

// The desktop shell writes the bytes where the system save dialog points. The
// suggested name is percent-encoded so any filename survives the header.
export function saveAttachmentFile(filename: string, _mimeType: string, bytes: Uint8Array, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return Promise.resolve(false);
  return invoke<boolean>('save_attachment', bytes, { headers: { 'X-File-Name': encodeURIComponent(filename) } })
    .catch((error) => { throw new Error(String(error)); });
}

const previews = new Set<string>();

export function attachmentPreviewUri(_key: string, mimeType: string, bytes: Uint8Array): string {
  const uri = URL.createObjectURL(new Blob([bytes as BlobPart], { type: mimeType }));
  previews.add(uri);
  return uri;
}

export function releasePreviewUri(uri: string): void {
  if (previews.delete(uri)) URL.revokeObjectURL(uri);
}

// Account-wide cleanup also releases any remaining object URLs. Thread close
// uses releasePreviewUri for only that opening's previews.
export function discardPreviews(): void {
  for (const uri of previews) releasePreviewUri(uri);
}

export type IncomingFileHandlers = {
  // A file is being dragged over the window, or has left it.
  onDragging: (dragging: boolean) => void;
  onFiles: (files: OutgoingAttachment[]) => void;
  onSelections?: (files: AttachmentSelection[]) => void;
  onError: (message: string) => void;
};

const carriesFiles = (transfer: DataTransfer | null): boolean =>
  transfer !== null && Array.from(transfer.types).includes('Files');

// A drag that crosses from one element to another fires leave before the
// next over; a drag that has really left the window fires leave and nothing
// after. Waiting this long tells them apart without a flicker.
export const DRAG_LEAVE_GRACE = 120;

// Files dropped or pasted anywhere in the window are offered to the open
// composer. The window only lights up for drags that carry files, so text
// dragged between fields keeps its normal behaviour.
export function listenForIncomingFiles(handlers: IncomingFileHandlers): () => void {
  let leaving: ReturnType<typeof setTimeout> | undefined;
  const accept = (files: File[]) => {
    if (!files.length) return;
    const error = handlers.onSelections ? attachmentSelectionLimit(files.map(file => file.size)) : attachmentSelectionError(files.map(file => file.size));
    if (error) { handlers.onError(error); return; }
    if (handlers.onSelections) filesToSelections(files).then(handlers.onSelections, () => handlers.onError('Those files could not be read.'));
    else filesToAttachments(files).then(handlers.onFiles, () => handlers.onError('Those files could not be read.'));
  };
  const onDragOver = (event: DragEvent) => {
    if (!carriesFiles(event.dataTransfer)) return;
    event.preventDefault();
    event.dataTransfer!.dropEffect = 'copy';
    clearTimeout(leaving);
    handlers.onDragging(true);
  };
  const onDragLeave = () => {
    clearTimeout(leaving);
    leaving = setTimeout(() => handlers.onDragging(false), DRAG_LEAVE_GRACE);
  };
  const onDrop = (event: DragEvent) => {
    if (!carriesFiles(event.dataTransfer)) return;
    event.preventDefault();
    clearTimeout(leaving);
    handlers.onDragging(false);
    accept(Array.from(event.dataTransfer!.files));
  };
  const onPaste = (event: ClipboardEvent) => {
    const files = Array.from(event.clipboardData?.files ?? []);
    if (!files.length) return;
    event.preventDefault();
    accept(files);
  };
  window.addEventListener('dragover', onDragOver);
  window.addEventListener('dragleave', onDragLeave);
  window.addEventListener('drop', onDrop);
  window.addEventListener('paste', onPaste);
  return () => {
    clearTimeout(leaving);
    window.removeEventListener('dragover', onDragOver);
    window.removeEventListener('dragleave', onDragLeave);
    window.removeEventListener('drop', onDrop);
    window.removeEventListener('paste', onPaste);
  };
}
