import { Directory, File, FileMode, Paths } from 'expo-file-system';

import { attachmentFileName, attachmentSelectionError, memoryAttachment } from './attachments.ts';
import { FREE_ATTACHMENT_SIZE } from './codec.ts';
import type { OutgoingAttachment } from './network.ts';

function readRange(file: File, offset: number, length: number): Uint8Array {
  const handle = file.open(FileMode.ReadOnly);
  try {
    handle.offset = offset;
    return handle.readBytes(length);
  } finally {
    handle.close();
  }
}

// Reads files chosen in the system picker; the core encrypts each one. Files up
// to 16 MB are read at once. A larger one stays where the picker put it and is
// read a chunk at a time as it uploads; its copy goes once it is sent or dropped.
export async function pickAttachmentFiles(): Promise<OutgoingAttachment[]> {
  const picked = await File.pickFileAsync({ multipleFiles: true });
  if (picked.canceled || !picked.result) return [];
  const files = picked.result;
  const copied = (file: File) => file.uri.startsWith(Paths.cache.uri);
  const kept = new Set<File>();
  try {
    const error = attachmentSelectionError(files.map((file) => file.size));
    if (error) throw new Error(error);
    return await Promise.all(files.map(async (file): Promise<OutgoingAttachment> => {
      const mimeType = file.type || 'application/octet-stream';
      const filename = attachmentFileName(file.name, mimeType);
      if (file.size <= FREE_ATTACHMENT_SIZE) return memoryAttachment(filename, mimeType, await file.bytes());
      kept.add(file);
      return {
        filename, mimeType, size: file.size,
        read: async (offset, length) => readRange(file, offset, length),
        release: () => { if (copied(file) && file.exists) file.delete(); },
      };
    }));
  } catch (error) {
    kept.clear();
    throw error;
  } finally {
    for (const file of files) {
      if (!kept.has(file) && copied(file)) file.delete();
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

// A large file is written where the person picks as it downloads, one chunk at
// a time; a failed download leaves nothing behind.
export async function saveAttachmentStream(
  filename: string,
  mimeType: string,
  stream: (write: (chunk: Uint8Array) => Promise<void>) => Promise<void>,
): Promise<boolean> {
  let directory: Directory;
  try {
    directory = await Directory.pickDirectoryAsync();
  } catch (error) {
    if (/cancel/i.test(String(error))) return false;
    throw error;
  }
  const file = directory.createFile(filename, mimeType);
  const handle = file.open(FileMode.Truncate);
  try {
    await stream(async (chunk) => { handle.writeBytes(chunk); });
  } catch (error) {
    handle.close();
    file.delete();
    throw error;
  }
  handle.close();
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
