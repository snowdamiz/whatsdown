import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { utf8, vectors, writeU32 } from './codec.ts';

const exportNames = [
  'credit_attachment_prepare_export', 'credit_attachment_recover_export',
  'credit_attachment_grant_export', 'credit_attachment_upload_export',
  'credit_attachment_complete_export', 'credit_attachment_delete_export',
  'credit_attachment_part_export', 'credit_attachment_part_recover_export',
  'credit_attachment_prune_export', 'attachment_fetch_chunk_export',
  'credit_attachment_preview_export', 'credit_attachments_export', 'attachment_download_plan_export',
  'credit_postage_candidate_export', 'credit_postage_preview_export',
  'credit_postage_prepare_export', 'credit_postage_recover_export',
  'credit_postage_continue_export', 'credit_postage_inventory_export',
  'postage_policy_view_export', 'postage_policy_prepare_export', 'postage_policy_publish_export',
];
registerHooks({ resolve(specifier, context, next) {
  if (context.parentURL?.endsWith('/src/paid-attachments.ts') || context.parentURL?.endsWith('/src/postage.ts') || context.parentURL?.endsWith('/src/attachment-compose.ts')) {
    if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(
      'export const isLegacyDesktopBridge=false;' + exportNames.map(name => `export const ${name}=()=>{throw Error("global_bridge_called")};`).join('')) };
    if (specifier === './network') return { shortCircuit: true, url: 'data:text/javascript,export const resolveDeviceSet=()=>{throw Error("global_network_called")};export const uploadAttachment=resolveDeviceSet;' };
  }
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createPaidAttachmentServices } = await import('./paid-attachments.ts');
const { createPostageServices } = await import('./postage.ts');
const { createAttachmentComposeServices } = await import('./attachment-compose.ts');
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function deferred() {
  let resolve: () => void = () => { throw Error('resolver_not_initialized'); };
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
const inventory = (...parts: Uint8Array[]) => Uint8Array.from([...writeU32(parts.length), ...vectors(...parts)]);

function fixture(kind: 'attachments' | 'postage', pendingCheck: number) {
  const gate = deferred(); let checks = 0, reads = 0;
  const scope = createDesktopPrivateSession({
    async check() { if (++checks === pendingCheck) await gate.promise; },
    invoke: unused, invokeWallet: unused, copyProtectedText: unused,
  });
  const paid = createPaidAttachmentServices({ ...scope,
    credit_attachment_prepare_export: unused, credit_attachment_recover_export: unused,
    credit_attachment_grant_export: unused, credit_attachment_upload_export: unused,
    credit_attachment_complete_export: unused, credit_attachment_delete_export: unused,
    credit_attachment_part_export: unused, credit_attachment_part_recover_export: unused,
    credit_attachment_prune_export: unused, attachment_fetch_chunk_export: unused,
    credit_attachment_preview_export: unused, attachment_download_plan_export: unused,
    async credit_attachments_export() { reads++; return inventory(utf8('\u0001AIV'), new Uint8Array(8)); },
  });
  const postage = createPostageServices({ ...scope,
    credit_postage_candidate_export: unused, credit_postage_preview_export: unused,
    credit_postage_prepare_export: unused, credit_postage_recover_export: unused,
    credit_postage_continue_export: unused, postage_policy_view_export: unused,
    postage_policy_prepare_export: unused, postage_policy_publish_export: unused, resolveDeviceSet: unused,
    async credit_postage_inventory_export() { reads++; return inventory(utf8('\u0001MPI'), new Uint8Array(8), Uint8Array.of(0)); },
  });
  return { scope, gate, reads: () => reads,
    read: () => kind === 'attachments' ? paid.readPaidAttachments('/captured/db') : postage.readPostages('/captured/db') };
}

for (const kind of ['attachments', 'postage'] as const) {
  test(`${kind} inventory waits for enclosing native authority before dispatch`, async () => {
    const f = fixture(kind, 1); let published = false;
    const reading = f.read().then(value => { published = true; return value; });
    await tick(); const earlyReads = f.reads(), earlyPublication = published;
    f.gate.resolve(); const result = await reading; await tick(); f.scope.dispose();
    assert.deepEqual(result.items, []); assert.equal(f.reads(), 1);
    assert.equal(earlyReads, 0); assert.equal(earlyPublication, false);
  });
  test(`${kind} parsed inventory waits for the native completion check`, async () => {
    const f = fixture(kind, 2); let published = false;
    const reading = f.read().then(value => { published = true; return value; });
    await tick(); const earlyPublication = published;
    f.gate.resolve(); const result = await reading; await tick(); f.scope.dispose();
    assert.deepEqual(result.items, []); assert.equal(f.reads(), 1);
    assert.equal(earlyPublication, false);
  });
}

function composeFixture() {
  const gate = deferred(); let blocked = false, uploads = 0;
  const scope = createDesktopPrivateSession({
    async check() { if (blocked) await gate.promise; },
    invoke: unused, invokeWallet: unused, copyProtectedText: unused,
  });
  const upload = async () => { uploads++; return { reference: Uint8Array.of(4), objectId: new Uint8Array(32), discard: async () => {} }; };
  const service = createAttachmentComposeServices({ ...scope,
    uploadAttachment: upload, previewPaidAttachment: unused, preparePaidAttachment: unused,
    stagePaidAttachment: unused, uploadStagedPaidAttachment: upload,
  });
  return { scope, service, uploads: () => uploads, block() { blocked = true; }, gate };
}
const smallSelection = () => ({ kind: 'small' as const, filename: 'private.txt', mimeType: 'text/plain',
  bytes: Uint8Array.of(42), size: 1, dispose() {} });
const savedAttachment = () => ({ nonce: new Uint8Array(32).fill(1), operationId: new Uint8Array(32).fill(2),
  status: 1 as const, filename: 'private.bin', mimeType: 'application/octet-stream', size: 16_777_217,
  price: 2, actionExpiresAt: 10n, objectExpiresAt: 20n, cleanupCursor: 0, chunkCount: 257 });

for (const kind of ['selected', 'saved'] as const) {
  test(`${kind} upload handle refuses a transfer after its session retires`, async () => {
    const f = composeFixture();
    const handle = kind === 'selected'
      ? (await f.service.previewAttachmentSelections('/captured/db', [smallSelection()]))[0]
      : f.service.savedAttachmentUpload(savedAttachment());
    assert(handle); await tick(); f.scope.dispose();
    await assert.rejects(handle.transfer('/captured/db', Uint8Array.of(1)), /stale_epoch/);
    assert.equal(f.uploads(), 0); handle.dispose();
  });
}
test('small selection preview cannot expose file metadata before native admission', async () => {
  const f = composeFixture(); f.block(); let published = false;
  const selecting = f.service.previewAttachmentSelections('/captured/db', [smallSelection()])
    .then(value => { published = true; return value; });
  await tick(); const early = published; f.gate.resolve(); const selected = await selecting; await tick();
  f.scope.dispose(); selected.forEach(item => item.dispose());
  assert.equal(selected[0]?.filename, 'private.txt'); assert.equal(early, false);
});
