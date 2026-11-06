import { invoke } from '@tauri-apps/api/core';
import type { AttachmentRangeSource, AttachmentRangeSink } from './paid-attachments.ts';

export type OpenAttachmentRangeSource = AttachmentRangeSource & { close(): void };

// Blob slicing reads only the requested range; arrayBuffer on the original
// selected file would allocate the entire attachment in the web view.
export function openAttachmentRangeSource(file: Blob): OpenAttachmentRangeSource {
  if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 536_870_912) throw new Error('invalid_attachment_size');
  let closed = false;
  return { size: file.size,
    async read(offset, length) {
      if (closed) throw new Error('attachment_source_closed');
      if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || length > 65_536 || offset + length > file.size) throw new Error('invalid_attachment_range');
      const bytes = new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
      if (bytes.length !== length) throw new Error('attachment_source_changed');
      return bytes;
    },
    close() { closed = true; },
  };
}

export async function createAttachmentRangeSink(filename: string, _mimeType: string, size: number): Promise<AttachmentRangeSink | null> {
  if (!Number.isSafeInteger(size) || size < 1 || size > 536_870_912) throw new Error('invalid_attachment_size');
  const body = new Uint8Array(4); new DataView(body.buffer).setUint32(0, size);
  const id = await invoke<number | null>('begin_attachment_save', body, { headers: { 'X-File-Name': encodeURIComponent(filename) } });
  if (id === null) return null;
  if (!Number.isSafeInteger(id) || id < 1) throw new Error('invalid_attachment_save');
  let closed = false; let written = 0;
  return {
    async write(offset, bytes) {
      if (closed || offset !== written || bytes.length < 1 || bytes.length > 65_536 || written + bytes.length > size) throw new Error('invalid_attachment_range');
      await invoke('write_attachment_range', bytes, { headers: { 'X-Attachment-Id': String(id), 'X-Attachment-Offset': String(offset) } });
      written += bytes.length;
    },
    async finish() {
      if (closed || written !== size) throw new Error('attachment_incomplete');
      await invoke('finish_attachment_save', { id }); closed = true;
    },
    async abort() { if (!closed) { closed = true; await invoke('abort_attachment_save', { id }); } },
  };
}
