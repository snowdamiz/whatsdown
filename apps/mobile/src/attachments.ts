import {
  ATTACHMENT_CHUNK_SIZE,
  FREE_ATTACHMENT_SIZE,
  MAXIMUM_ATTACHMENTS,
  MAXIMUM_ATTACHMENT_SIZE,
  type AttachmentSummary,
} from './codec.ts';
import type { OutgoingAttachment } from './network.ts';

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

export function attachmentPreviewText(message: {
  body: string;
  attachments?: AttachmentSummary[];
  viewOnce?: 'unopened' | 'gone';
  timerNotice?: number;
}): string {
  // A view-once message's content never shows outside its one look.
  if (message.viewOnce) return 'View once message';
  if (message.timerNotice !== undefined) {
    return message.timerNotice ? 'Changed the disappearing-message timer' : 'Turned off disappearing messages';
  }
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

// A decrypted picture is shown from a cache file (an object URL on the desktop).
// When its conversation closes the file goes, with the picture's state, so the
// picture is drawn again, from the bytes still in memory, when it opens again.
export function closedPreviews(states: Record<string, AttachmentState>): {
  kept: Record<string, AttachmentState>;
  released: string[];
} {
  const kept: Record<string, AttachmentState> = {};
  const released: string[] = [];
  for (const [id, state] of Object.entries(states)) {
    if (state.previewUri) released.push(state.previewUri);
    else kept[id] = state;
  }
  return { kept, released };
}

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

// Version 2 attachments pad to a size bucket: one 64 KiB chunk, then four
// steps per doubling (attachment-wire-v1.md). The core pads; the app needs the
// bucket only to price a file before it is sent.
export function attachmentPaddedSize(size: number): number {
  if (size <= ATTACHMENT_CHUNK_SIZE) return ATTACHMENT_CHUNK_SIZE;
  const step = 2 ** (31 - Math.clz32(size)) / 4;
  return Math.ceil(size / step) * step;
}

// Up to 16 MiB is free; each extra 16 MiB of the bucket costs a credit (plan §6.10).
export const attachmentCreditCost = (size: number): number =>
  Math.ceil(attachmentPaddedSize(size) / FREE_ATTACHMENT_SIZE) - 1;

const fileKind = (mimeType: string): string =>
  mimeType.startsWith('video/') ? 'video' : isImageAttachment(mimeType) ? 'photo' : 'file';

type PricedFile = { mimeType: string; size: number };

// Asked before files that cost credits are staged, never elsewhere.
export function creditSpendPrompt(files: PricedFile[]): string | undefined {
  const cost = files.reduce((total, file) => total + attachmentCreditCost(file.size), 0);
  if (!cost) return undefined;
  const credits = `${cost} ${cost === 1 ? 'credit' : 'credits'}`;
  if (files.length > 1) return `Sending these files uses ${credits}`;
  return `Sending this ${formatBytes(files[0]!.size)} ${fileKind(files[0]!.mimeType)} uses ${credits}`;
}

// Buying lives with the wallet.
export function creditShortfall(cost: number, balance: number): string | undefined {
  if (balance >= cost) return undefined;
  return `This needs ${cost} credits and you have ${balance || 'none'}. ` +
    'Files over 16 MB use 1 credit for every extra 16 MB; buy credits in You → Wallet.';
}

// A file already in memory, read like any other: small files are, so their
// pictures preview and reopen after sending without another download.
export function memoryAttachment(filename: string, mimeType: string, bytes: Uint8Array): OutgoingAttachment {
  return { filename, mimeType, size: bytes.length, bytes, read: async (offset, length) => bytes.subarray(offset, offset + length) };
}

export function attachmentSelectionError(sizes: number[], existingCount = 0): string | undefined {
  if (existingCount + sizes.length > MAXIMUM_ATTACHMENTS) return 'You can attach up to 10 files per message.';
  if (sizes.some((size) => size === 0)) return 'This file is empty.';
  if (sizes.some((size) => size > MAXIMUM_ATTACHMENT_SIZE)) return `Attachments can be up to ${MAXIMUM_ATTACHMENT_SIZE / 1_048_576} MB.`;
  return undefined;
}
