import { runPrivateOwned } from './private-resource';
import { protectedHandle, protectedMetadata } from './app-lock';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import type { AttachmentRangeSource, AttachmentRangeSink } from './paid-attachments.ts';
export type OpenAttachmentRangeSource = AttachmentRangeSource & { close(): void };
const validSize = (size: number) => Number.isSafeInteger(size) && size > 0 && size <= 536_870_912;
export function createAttachmentRangeServices(deps: Pick<ScopedClient, 'assertCurrent' | 'runPrivate' | 'protectedFile' | 'cleanupProtectedFile'>) {
  async function openAttachmentRangeSource(choiceId: string, selectionId: string, size: number): Promise<OpenAttachmentRangeSource> {
    if (!validSize(size)) throw new Error('invalid_attachment_size');
    const result = protectedMetadata(await deps.protectedFile('claimSource', { version: 1,
      choiceId: protectedHandle(choiceId), selectionId: protectedHandle(selectionId), size }), ['handle', 'size']);
    const handle = protectedHandle(result.handle);
    if (result.size !== size) { void deps.cleanupProtectedFile('closeSource', { version: 1, handle }).catch(() => {}); throw new Error('attachment_source_changed'); }
    let closed = false; let reading = false;
    return {
      size,
      read(offset, length) {
        return deps.runPrivate(async () => {
          if (closed) throw new Error('attachment_source_closed');
          if (reading || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) ||
              length < 1 || length > 65_536 || offset + length > size) throw new Error('invalid_attachment_range');
          reading = true;
          try {
            const bytes = await deps.protectedFile('readSource', { version: 1, handle, offset, length });
            if (!(bytes instanceof Uint8Array)) throw new Error('attachment_source_changed');
            if (bytes.length !== length) { bytes.fill(0); throw new Error('attachment_source_changed'); }
            return bytes;
          } finally { reading = false; }
        });
      },
      close() { if (closed) return; closed = true; void deps.cleanupProtectedFile('closeSource', { version: 1, handle }).catch(() => {}); },
    };
  }
  async function createAttachmentRangeSink(filename: string, mimeType: string, size: number, sourceContext: string): Promise<AttachmentRangeSink | null> {
    if (!validSize(size)) throw new Error('invalid_attachment_size');
    if (!filename.trim() || filename === '.' || filename === '..' || /[\/\\\x00-\x1f\x7f]/.test(filename) ||
        new TextEncoder().encode(filename).length > 255) throw new Error('invalid_attachment_name');
    if (!sourceContext || sourceContext.length > 4096) throw new Error('invalid_attachment_source');
    const context = { version: 1, purpose: 'export', filename, mimeType, size, sourceContext };
    let choice = protectedMetadata(await deps.protectedFile('pendingChoice', context), ['choiceId']);
    if (choice.choiceId === undefined) {
      // The chooser owns no decrypted export bytes. If it deactivates Morse,
      // native retains only a non-authority choice. The old action refuses;
      // a fresh explicit Save can claim it after the ordinary OS unlock.
      choice = protectedMetadata(await deps.protectedFile('chooseDestination', context), ['choiceId', 'cancelled']);
      if (choice.cancelled === true) return null;
    }
    const started = protectedMetadata(await deps.protectedFile('beginExport', { ...context, choiceId: protectedHandle(choice.choiceId) }), ['handle']);
    const handle = protectedHandle(started.handle);
    let written = 0; let closed = false; let writing = false; let finished = false;
    return {
      write(offset, bytes) {
        return deps.runPrivate(async () => {
          if (closed || writing || offset !== written || bytes.length < 1 || bytes.length > 65_536 || written + bytes.length > size) throw new Error('invalid_attachment_range');
          writing = true;
          try { await deps.protectedFile('writeExport', { version: 1, handle, offset }, bytes); written += bytes.length; }
          finally { writing = false; }
        });
      },
      finish() {
        return deps.runPrivate(async () => {
          if (closed || writing || written !== size) throw new Error('attachment_incomplete');
          closed = true; await deps.protectedFile('commitExport', { version: 1, handle }); finished = true;
        });
      },
      async abort() { if (finished) return; closed = true; await deps.cleanupProtectedFile('abortExport', { version: 1, handle }); },
    };
  }
  return Object.freeze({
    openAttachmentRangeSource: (...args: Parameters<typeof openAttachmentRangeSource>) => runPrivateOwned({ scope: deps, operation: () => openAttachmentRangeSource(...args), discard: source => source.close() }),
    createAttachmentRangeSink: (...args: Parameters<typeof createAttachmentRangeSink>) => runPrivateOwned({ scope: deps, operation: () => createAttachmentRangeSink(...args), discard: async sink => { await sink?.abort(); } }),
  });
}
// Desktop resolves attachment-range-io.web.ts and keeps its existing adapter.
export const openAttachmentRangeSource: ReturnType<typeof createAttachmentRangeServices>['openAttachmentRangeSource'] = () => { throw new Error('scoped_client_required'); };
export const createAttachmentRangeSink: ReturnType<typeof createAttachmentRangeServices>['createAttachmentRangeSink'] = () => { throw new Error('scoped_client_required'); };
