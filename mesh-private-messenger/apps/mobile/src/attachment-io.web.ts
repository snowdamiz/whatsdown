import { invoke } from '@tauri-apps/api/core';

import { attachmentFileName, attachmentSelectionError, memoryAttachment } from './attachments.ts';
import { FREE_ATTACHMENT_SIZE } from './codec.ts';
import type { OutgoingAttachment } from './network.ts';

// Files up to 16 MB are read at once; a larger one is read a chunk at a time as
// it uploads.
export async function fileToAttachment(file: File): Promise<OutgoingAttachment> {
  const mimeType = file.type || 'application/octet-stream';
  const filename = attachmentFileName(file.name, mimeType);
  if (file.size <= FREE_ATTACHMENT_SIZE) return memoryAttachment(filename, mimeType, new Uint8Array(await file.arrayBuffer()));
  return {
    filename, mimeType, size: file.size,
    read: async (offset, length) => new Uint8Array(await file.slice(offset, offset + length).arrayBuffer()),
  };
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
export function saveAttachmentFile(filename: string, _mimeType: string, bytes: Uint8Array): Promise<boolean> {
  return invoke<boolean>('save_attachment', bytes, { headers: { 'X-File-Name': encodeURIComponent(filename) } })
    .catch((error) => { throw new Error(String(error)); });
}

// A large download goes where the save dialog points as it arrives: the shell
// opens the file, appends each chunk, and removes it if the download fails.
export async function saveAttachmentStream(
  filename: string,
  _mimeType: string,
  stream: (write: (chunk: Uint8Array) => Promise<void>) => Promise<void>,
): Promise<boolean> {
  const id = await invoke<number | null>('save_attachment_start', {}, { headers: { 'X-File-Name': encodeURIComponent(filename) } })
    .catch((error) => { throw new Error(String(error)); });
  if (id === null) return false;
  let complete = false;
  try {
    await stream(async (chunk) => {
      await invoke('save_attachment_chunk', chunk, { headers: { 'X-Save-Id': String(id) } });
    });
    complete = true;
  } finally {
    await invoke('save_attachment_finish', { id, complete });
  }
  return true;
}

export function attachmentPreviewUri(_key: string, mimeType: string, bytes: Uint8Array): string {
  return URL.createObjectURL(new Blob([bytes as BlobPart], { type: mimeType }));
}

export function releasePreviewUri(uri: string): void {
  URL.revokeObjectURL(uri);
}

// Previews here are object URLs, which leave nothing on disk.
export function discardPreviews(): void {}

export type IncomingFileHandlers = {
  // A file is being dragged over the window, or has left it.
  onDragging: (dragging: boolean) => void;
  onFiles: (files: OutgoingAttachment[]) => void;
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
    const error = attachmentSelectionError(files.map((file) => file.size));
    if (error) { handlers.onError(error); return; }
    filesToAttachments(files).then(handlers.onFiles, () => handlers.onError('Those files could not be read.'));
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
