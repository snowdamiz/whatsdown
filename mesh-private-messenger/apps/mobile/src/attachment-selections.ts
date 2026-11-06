import { MAXIMUM_ATTACHMENTS, MAXIMUM_ATTACHMENT_SIZE } from './codec.ts';
import { t } from './i18n.ts';
import type { OutgoingAttachment } from './network.ts';
import type { OpenAttachmentRangeSource } from './attachment-range-io';

export const MAXIMUM_PAID_ATTACHMENT_SIZE = 536_870_912;
export { MAXIMUM_ATTACHMENT_SIZE };
export type SmallAttachmentSelection = OutgoingAttachment & { kind: 'small'; size: number; dispose(): void };
export type LargeAttachmentSelection = {
  kind: 'large'; filename: string; mimeType: string; size: number;
  source: OpenAttachmentRangeSource; dispose(): void;
};
export type AttachmentSelection = SmallAttachmentSelection | LargeAttachmentSelection;

export function attachmentSelectionLimit(sizes: number[], existing = 0): string | undefined {
  if (sizes.length + existing > MAXIMUM_ATTACHMENTS) return t('You can attach up to 10 files per message.');
  if (sizes.some(size => !Number.isSafeInteger(size) || size < 1)) return t('This file is empty.');
  if (sizes.some(size => size > MAXIMUM_PAID_ATTACHMENT_SIZE)) return t('Attachments can be up to {size} MB.', { size: 512 });
  return undefined;
}
export function smallAttachmentSelection(file: OutgoingAttachment): SmallAttachmentSelection {
  return { ...file, kind: 'small', size: file.bytes.length, dispose() {} };
}
