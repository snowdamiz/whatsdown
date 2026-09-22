import { Directory, File, Paths } from 'expo-file-system';

import { attachmentFileName, attachmentSelectionError } from './attachments.ts';
import type { OutgoingAttachment } from './network.ts';

// Reads files chosen in the system picker; the core encrypts each one.
export async function pickAttachmentFiles(): Promise<OutgoingAttachment[]> {
  const picked = await File.pickFileAsync({ multipleFiles: true });
  if (picked.canceled || !picked.result) return [];
  const files = picked.result;
  try {
    const error = attachmentSelectionError(files.map((file) => file.size));
    if (error) throw new Error(error);
    return await Promise.all(files.map(async (file) => {
      const mimeType = file.type || 'application/octet-stream';
      return { filename: attachmentFileName(file.name, mimeType), mimeType, bytes: await file.bytes() };
    }));
  } finally {
    for (const file of files) {
      if (file.uri.startsWith(Paths.cache.uri)) file.delete();
    }
  }
}

// Saving writes into a folder the person picks, through the system's own
// document UI. Both platforms report a dismissed picker as a rejection.
export async function saveAttachmentFile(filename: string, mimeType: string, bytes: Uint8Array): Promise<boolean> {
  let directory: Directory;
  try {
    directory = await Directory.pickDirectoryAsync();
  } catch (error) {
    if (/cancel/i.test(String(error))) return false;
    throw error;
  }
  directory.createFile(filename, mimeType).write(bytes);
  return true;
}

const previews = new Directory(Paths.cache, 'morse-attachment-previews');
let previewsPrepared = false;

// A decrypted picture is shown from a cache file, and previews live for one
// session. Whatever an earlier run left behind is removed as soon as the app
// starts, not when it next happens to show a picture: otherwise decrypted
// pictures outlive the session for as long as nobody opens another one. They
// also go with an erased account.
export function discardPreviews(): void {
  previewsPrepared = false;
  try {
    if (previews.exists) previews.delete();
  } catch {
    // Retried before the first preview of this session is written.
  }
}
discardPreviews();

export function attachmentPreviewUri(key: string, mimeType: string, bytes: Uint8Array): string {
  if (!previewsPrepared) {
    discardPreviews();
    previews.create({ intermediates: true });
    previewsPrepared = true;
  }
  const extension = mimeType.split('/')[1] ?? 'bin';
  const file = new File(previews, `${key}.${extension}`);
  if (file.exists) file.delete();
  file.create();
  file.write(bytes);
  return file.uri;
}

export function releasePreviewUri(uri: string): void {
  const file = new File(uri);
  if (file.exists) file.delete();
}

export type IncomingFileHandlers = {
  onDragging: (dragging: boolean) => void;
  onFiles: (files: OutgoingAttachment[]) => void;
  onError: (message: string) => void;
};

// Nothing is dragged or pasted into a phone's window; files come from the picker.
export function listenForIncomingFiles(_handlers: IncomingFileHandlers): () => void {
  return () => {};
}
