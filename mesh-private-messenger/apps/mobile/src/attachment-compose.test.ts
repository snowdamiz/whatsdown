import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const calls: string[] = [];
let failUpload = true;
let freeFailure = false;
let closes = 0;
let paidDiscards = 0;
const authorization = Uint8Array.of(71, 72, 73);
const nonce = new Uint8Array(32).fill(8);
const paidResult = { reference: Uint8Array.of(2), objectId: new Uint8Array(32).fill(7), discard: async () => { paidDiscards++; } };
Object.assign(globalThis, {
  __composePreview: async () => { calls.push('preview'); return { nonce, purpose: 'test', size: 16_777_217, price: 2, available: 20, delayed: 0, reserved: 0, revision: 1n }; },
  __composePrepare: async (_db: string, id: Uint8Array) => { calls.push('prepare'); assert.deepEqual(id, nonce); },
  __composeStage: async () => { calls.push('stage'); },
  __composeUpload: async (_db: string, id: Uint8Array) => { calls.push('upload-staged'); assert.deepEqual(id, nonce); if (failUpload) throw Error('unknown upload'); return paidResult; },
  __composeFree: async () => { calls.push('free-upload'); if (freeFailure) throw Error('free upload failed'); return { reference: Uint8Array.of(1), objectId: new Uint8Array(32).fill(1), discard: async () => { calls.push('free-discard'); } }; },
});
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,export const isLegacyDesktopBridge=false;' };
  if (specifier === './paid-attachments') return { shortCircuit: true, url: 'data:text/javascript,export const previewPaidAttachment=globalThis.__composePreview;export const preparePaidAttachment=globalThis.__composePrepare;export const stagePaidAttachment=globalThis.__composeStage;export const uploadStagedPaidAttachment=globalThis.__composeUpload;' };
  if (specifier === './network') return { shortCircuit: true, url: 'data:text/javascript,export const uploadAttachment=globalThis.__composeFree;' };
  return next(specifier, context);
} });
const composeModule = await import('./attachment-compose.ts');
const { scope } = scopeFixture();
const compose = { ...composeModule, ...composeModule.createAttachmentComposeServices({ ...scope,
  uploadAttachment: globalThis.__composeFree, previewPaidAttachment: globalThis.__composePreview,
  preparePaidAttachment: globalThis.__composePrepare, stagePaidAttachment: globalThis.__composeStage,
  uploadStagedPaidAttachment: globalThis.__composeUpload,
}) };
const source = { size: 16_777_217, read: async () => { throw Error('controller must use bounded native staging'); }, close() { closes++; } };

test('file price preview does not reserve, and unknown upload retries never reopen the source or choose a new intent', async () => {
  const [upload] = await compose.previewAttachmentSelections('/db', [{ kind: 'large', filename: 'large.bin', mimeType: 'application/octet-stream', size: source.size, source, dispose: () => source.close() }]);
  assert.deepEqual(calls, ['preview']);
  assert.equal(upload!.price, 2);
  await assert.rejects(upload!.transfer('/db', authorization), /unknown upload/);
  assert.deepEqual(calls, ['preview', 'prepare', 'stage', 'upload-staged']);
  assert.equal(closes, 1);
  failUpload = false;
  await upload!.transfer('/db', authorization);
  assert.deepEqual(calls.slice(-1), ['upload-staged']);
  assert.equal(calls.filter(value => value === 'prepare').length, 1);
  assert.equal(calls.filter(value => value === 'stage').length, 1);
  upload!.dispose(); assert.equal(closes, 1);
});

test('saved uploads have no plaintext-source API and failed mixed batches do not delete paid grants', async () => {
  const saved = compose.savedAttachmentUpload({ nonce, operationId: new Uint8Array(32).fill(9), status: 1, filename: 'large.bin', mimeType: 'application/octet-stream', size: source.size, price: 2, actionExpiresAt: 100n, objectExpiresAt: 1000000n, cleanupCursor: 0, chunkCount: 257 });
  const before = calls.length;
  await saved.transfer('/db', authorization);
  assert.deepEqual(calls.slice(before), ['upload-staged']);
  const [small] = await compose.previewAttachmentSelections('/db', [{ kind: 'small', filename: 'a.txt', mimeType: 'text/plain', size: 1, bytes: Uint8Array.of(1), dispose() {} }]);
  freeFailure = true;
  let sent = false;
  await assert.rejects(compose.sendAttachmentUploads('/db', [saved, small!], async () => authorization, async () => { sent = true; }), /free upload failed/);
  assert.equal(sent, false); assert.equal(paidDiscards, 0);
});


test('recipient refusal precedes every upload and preserves staged files for retry', async () => {
  const [small] = await compose.previewAttachmentSelections('/db', [{ kind: 'small', filename: 'a.txt', mimeType: 'text/plain', size: 1, bytes: Uint8Array.of(1), dispose() {} }]);
  const before = calls.length;
  await assert.rejects(compose.sendAttachmentUploads('/db', [small!], async () => { throw Error('attachment_recipient_upgrade_required'); }, async () => assert.fail('sent unsupported attachment')), /upgrade_required/);
  assert.equal(calls.length, before);
});
