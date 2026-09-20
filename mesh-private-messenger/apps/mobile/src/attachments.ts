import { MAXIMUM_ATTACHMENTS, MAXIMUM_ATTACHMENT_SIZE, type AttachmentSummary } from './codec.ts';

// Pictures the thread can show inline on every platform; everything else is a file card.
export const isImageAttachment = (mimeType: string): boolean =>
  /^image\/(jpeg|png|gif|webp)$/.test(mimeType);

// Pictures up to this size are fetched as soon as they appear, like a photo in any messenger.
export const AUTO_DOWNLOAD_LIMIT = 5 * 1_048_576;

export const shouldAutoDownload = (attachment: AttachmentSummary): boolean =>
  isImageAttachment(attachment.mimeType) && attachment.size <= AUTO_DOWNLOAD_LIMIT;

export function formatBytes(size: number): string {
  if (size < 1_000) return `${size} B`;
  if (size < 1_000_000) return `${Math.round(size / 1_000)} KB`;
  const megabytes = size / 1_000_000;
  return `${megabytes < 10 ? megabytes.toFixed(1) : Math.round(megabytes)} MB`;
}

// A dropped or pasted file may arrive unnamed; give it a name that keeps its kind.
export function attachmentFileName(name: string, mimeType: string): string {
  const trimmed = name.trim();
  if (trimmed) return trimmed.slice(0, 255);
  const extension = mimeType.split('/')[1]?.replace(/^x-/, '').split(/[+;]/)[0];
  return extension && /^[a-z0-9]{1,8}$/i.test(extension) ? `attachment.${extension}` : 'attachment';
}

export function attachmentPreviewText(message: { body: string; attachments?: AttachmentSummary[] }): string {
  if (message.body) return message.body;
  const files = message.attachments ?? [];
  if (!files.length) return '';
  if (files.length > 1) return `${files.length} ${files.every((file) => isImageAttachment(file.mimeType)) ? 'photos' : 'attachments'}`;
  return files[0]!.filename || (isImageAttachment(files[0]!.mimeType) ? 'Photo' : 'Attachment');
}

// A staged file belongs to the thread whose composer took it, so switching
// threads can never send it somewhere else. Only screens with a composer
// have a scope.
export function composerScope(
  screen: string,
  selectedConversation: string | null,
  selectedGroup: string | null,
): string | null {
  if (screen === 'chat') return selectedConversation && `chat/${selectedConversation}`;
  if (screen === 'group') return selectedGroup && `group/${selectedGroup}`;
  if (screen === 'new-chat') return 'new-chat';
  return null;
}

export type AttachmentState =
  | { status: 'downloading'; completed: number; total: number; previewUri?: string }
  | { status: 'ready'; previewUri?: string }
  | { status: 'saved'; previewUri?: string }
  | { status: 'error'; message: string; previewUri?: string };

export function describeAttachmentState(attachment: AttachmentSummary, state: AttachmentState | undefined): string {
  const size = formatBytes(attachment.size);
  if (!state) return `${size} · Download`;
  switch (state.status) {
    case 'downloading':
      return `Downloading… ${Math.round((state.completed / Math.max(state.total, 1)) * 100)}%`;
    case 'ready':
      return `${size} · Save`;
    case 'saved':
      return `${size} · Saved`;
    case 'error':
      return state.message;
  }
}

export function attachmentSelectionError(sizes: number[], existingCount = 0): string | undefined {
  if (existingCount + sizes.length > MAXIMUM_ATTACHMENTS) return 'You can attach up to 10 files per message.';
  if (sizes.some((size) => size === 0)) return 'This file is empty.';
  if (sizes.some((size) => size > MAXIMUM_ATTACHMENT_SIZE)) return `Attachments can be up to ${MAXIMUM_ATTACHMENT_SIZE / 1_048_576} MB.`;
  return undefined;
}
