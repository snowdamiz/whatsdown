import assert from 'node:assert/strict';
import test from 'node:test';

import {
  attachmentCreditCost,
  attachmentFileName,
  attachmentPreviewText,
  attachmentSelectionError,
  closedPreviews,
  composerScope,
  creditShortfall,
  creditSpendPrompt,
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

// The same ladder as the core (attachment-wire-v1.md "Large files"): free to
// 16 MiB, then one credit per extra 16 MiB of the file's bucket, to 512 MiB.
test('files over 16 MB cost one credit per extra 16 MB of their padded size', () => {
  const MiB = 1_048_576;
  assert.equal(attachmentCreditCost(1), 0);
  assert.equal(attachmentCreditCost(16 * MiB), 0);
  assert.equal(attachmentCreditCost(16 * MiB + 1), 1);
  assert.equal(attachmentCreditCost(40_000_000), 2);
  const rungs: [number, number][] = [[20, 1], [24, 1], [28, 1], [32, 1], [40, 2], [48, 2], [56, 3], [64, 3], [80, 4], [96, 5],
    [112, 6], [128, 7], [160, 9], [192, 11], [224, 13], [256, 15], [320, 19], [384, 23], [448, 27], [512, 31]];
  for (const [mebibytes, credits] of rungs) {
    assert.equal(attachmentCreditCost(mebibytes * MiB), credits, `${mebibytes} MiB`);
    // One byte more is the next bucket up.
    if (mebibytes < 512) assert.ok(attachmentCreditCost(mebibytes * MiB + 1) >= credits);
  }
  assert.equal(attachmentSelectionError([512 * MiB]), undefined);
  assert.equal(attachmentSelectionError([512 * MiB + 1]), 'Attachments can be up to 512 MB.');
});

test('the spend prompt names what is sent and what it uses; a shortfall says how to get credits', () => {
  const MiB = 1_048_576;
  const video = { filename: 'launch.mov', mimeType: 'video/quicktime', size: 40_000_000 };
  const photo = { filename: 'a.jpg', mimeType: 'image/jpeg', size: 20 * MiB };
  const note = { filename: 'n.txt', mimeType: 'text/plain', size: 10 };
  assert.equal(creditSpendPrompt([video]), 'Sending this 40 MB video uses 2 credits');
  assert.equal(creditSpendPrompt([photo]), 'Sending this 21 MB photo uses 1 credit');
  assert.equal(creditSpendPrompt([{ ...note, size: 100 * MiB }]), 'Sending this 105 MB file uses 6 credits');
  assert.equal(creditSpendPrompt([video, photo, note]), 'Sending these files uses 3 credits');
  assert.equal(creditSpendPrompt([note]), undefined);
  assert.equal(creditShortfall(2, 0),
    'This needs 2 credits and you have none. Files over 16 MB use 1 credit for every extra 16 MB; buy credits in You → Wallet.');
  assert.equal(creditShortfall(3, 1),
    'This needs 3 credits and you have 1. Files over 16 MB use 1 credit for every extra 16 MB; buy credits in You → Wallet.');
  assert.equal(creditShortfall(1, 1), undefined);
});

test('a closing conversation releases every decrypted picture it showed and keeps the other files\' states', () => {
  const { kept, released } = closedPreviews({
    shown: { status: 'ready', previewUri: 'file:///cache/morse-attachment-previews/a.jpeg' },
    saved: { status: 'saved', previewUri: 'blob:morse/b' },
    file: { status: 'saved' },
    fetching: { status: 'downloading', completed: 1, total: 4 },
  });
  assert.deepEqual(released.sort(), ['blob:morse/b', 'file:///cache/morse-attachment-previews/a.jpeg']);
  assert.deepEqual(kept, { file: { status: 'saved' }, fetching: { status: 'downloading', completed: 1, total: 4 } });
});
