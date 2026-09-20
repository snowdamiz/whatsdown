import assert from 'node:assert/strict';
import test from 'node:test';

import {
  attachmentFileName,
  attachmentPreviewText,
  composerScope,
  describeAttachmentState,
  formatBytes,
  isImageAttachment,
  shouldAutoDownload,
} from './attachments.ts';

test('a staged file is scoped to the thread whose composer is open', () => {
  assert.equal(composerScope('chat', '1.2.3', null), 'chat/1.2.3');
  assert.equal(composerScope('chat', null, null), null);
  assert.equal(composerScope('group', null, 'abcd'), 'group/abcd');
  assert.equal(composerScope('new-chat', '1.2.3', 'abcd'), 'new-chat');
  assert.equal(composerScope('home', '1.2.3', 'abcd'), null);
  assert.equal(composerScope('chat-info', '1.2.3', null), null);
});

const summary = (size: number, mimeType = 'image/jpeg', filename = 'photo.jpg') => ({
  reference: new Uint8Array(), objectId: new Uint8Array(32), downloadCapability: new Uint8Array(32),
  filename, mimeType, size, chunkCount: Math.ceil(size / 65_536), chunkSize: 65_536, expiresAt: 0,
});

test('only inline-renderable pictures within the limit download on sight', () => {
  assert.equal(isImageAttachment('image/png'), true);
  assert.equal(isImageAttachment('image/svg+xml'), false);
  assert.equal(isImageAttachment('application/pdf'), false);
  assert.equal(shouldAutoDownload(summary(5 * 1_048_576)), true);
  assert.equal(shouldAutoDownload(summary(5 * 1_048_576 + 1)), false);
  assert.equal(shouldAutoDownload(summary(10, 'application/pdf', 'a.pdf')), false);
});

test('sizes and states read as short labels', () => {
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(65_536), '66 KB');
  assert.equal(formatBytes(2_500_000), '2.5 MB');
  assert.equal(formatBytes(16_777_216), '17 MB');
  const attachment = summary(2_500_000);
  assert.equal(describeAttachmentState(attachment, undefined), '2.5 MB · Download');
  assert.equal(describeAttachmentState(attachment, { status: 'downloading', completed: 1, total: 4 }), 'Downloading… 25%');
  assert.equal(describeAttachmentState(attachment, { status: 'ready' }), '2.5 MB · Save');
  assert.equal(describeAttachmentState(attachment, { status: 'saved' }), '2.5 MB · Saved');
  assert.equal(describeAttachmentState(attachment, { status: 'error', message: 'Expired' }), 'Expired');
});

test('unnamed files take a name from their type and previews fall back to the attachment', () => {
  assert.equal(attachmentFileName('  report.pdf ', 'application/pdf'), 'report.pdf');
  assert.equal(attachmentFileName('', 'image/png'), 'attachment.png');
  assert.equal(attachmentFileName('', 'image/svg+xml'), 'attachment.svg');
  assert.equal(attachmentFileName('', 'application/octet-stream'), 'attachment');
  assert.equal(attachmentFileName('x'.repeat(300), 'text/plain').length, 255);
  assert.equal(attachmentPreviewText({ body: 'hi', attachments: [summary(1)] }), 'hi');
  assert.equal(attachmentPreviewText({ body: '', attachments: [summary(1)] }), 'photo.jpg');
  assert.equal(attachmentPreviewText({ body: '', attachments: [summary(1, 'image/png', '')] }), 'Photo');
  assert.equal(attachmentPreviewText({ body: '', attachments: [summary(1, 'text/plain', '')] }), 'Attachment');
  assert.equal(attachmentPreviewText({ body: '' }), '');
});
