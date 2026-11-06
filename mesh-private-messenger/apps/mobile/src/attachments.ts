import { MAXIMUM_ATTACHMENTS, MAXIMUM_ATTACHMENT_SIZE, type AttachmentSummary, type MessageContent, type ViewOnceStatus } from './codec.ts';
import { t } from './i18n.ts';

// Pictures the thread can show inline on every platform; everything else is a file card.
export const isImageAttachment = (mimeType: string): boolean =>
  /^image\/(jpeg|png|gif|webp)$/.test(mimeType);

// Pictures up to this size are fetched as soon as they appear, like a photo in any messenger.
export const AUTO_DOWNLOAD_LIMIT = 5 * 1_048_576;

export const shouldAutoDownload = (attachment: AttachmentSummary): boolean =>
  isImageAttachment(attachment.mimeType) && attachment.size <= AUTO_DOWNLOAD_LIMIT;

export function formatBytes(size: number): string {
  if (size < 1_000) return t('{size} B', { size });
  if (size < 1_000_000) return t('{size} KB', { size: Math.round(size / 1_000) });
  const megabytes = size / 1_000_000;
  return t('{size} MB', { size: megabytes < 10 ? megabytes.toFixed(1) : Math.round(megabytes) });
}

// A dropped or pasted file may arrive unnamed; give it a name that keeps its kind.
export function attachmentFileName(name: string, mimeType: string): string {
  const trimmed = name.trim();
  if (trimmed) return trimmed.slice(0, 255);
  const extension = mimeType.split('/')[1]?.replace(/^x-/, '').split(/[+;]/)[0];
  return extension && /^[a-z0-9]{1,8}$/i.test(extension) ? `attachment.${extension}` : 'attachment';
}

export function viewOncePlaceholder(status: ViewOnceStatus): string {
  switch (status) {
    case 'pending': return t('View-once photo · Waiting');
    case 'ready': return t('View-once photo · Ready');
    case 'opened': return t('View-once photo · Opened');
    case 'expired': return t('View-once photo · Expired');
    case 'unavailable': return t('View-once photo · Unavailable');
    default: { const exhaustive: never = status; return exhaustive; }
  }
}

export function messageBodyText(message: MessageContent): string {
  if (message.kind !== 'view-once') return message.body;
  const placeholder = viewOncePlaceholder(message.status);
  return message.body ? `${placeholder}\n${message.body}` : placeholder;
}

export function attachmentPreviewText(message: MessageContent): string {
  if (message.kind === 'view-once') return messageBodyText(message);
  if (message.body) return message.body;
  const files = message.attachments ?? [];
  if (!files.length) return '';
  if (files.length > 1) {
    return files.every((file) => isImageAttachment(file.mimeType))
      ? t.plural('{count} photo', '{count} photos', files.length)
      : t.plural('{count} attachment', '{count} attachments', files.length);
  }
  return files[0]!.filename || (isImageAttachment(files[0]!.mimeType) ? t('Photo') : t('Attachment'));
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
  if (!state) return t('{size} · Download', { size });
  switch (state.status) {
    case 'downloading':
      return t('Downloading… {percent}%', { percent: Math.round((state.completed / Math.max(state.total, 1)) * 100) });
    case 'ready':
      return t('{size} · Save', { size });
    case 'saved':
      return t('{size} · Saved', { size });
    case 'error':
      return state.message;
  }
}

export function attachmentSelectionError(sizes: number[], existingCount = 0): string | undefined {
  if (existingCount + sizes.length > MAXIMUM_ATTACHMENTS) return t('You can attach up to 10 files per message.');
  if (sizes.some((size) => size === 0)) return t('This file is empty.');
  if (sizes.some((size) => size > MAXIMUM_ATTACHMENT_SIZE)) return t('Attachments can be up to {size} MB.', { size: MAXIMUM_ATTACHMENT_SIZE / 1_048_576 });
  return undefined;
}
