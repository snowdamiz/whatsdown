import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const text = (s: string) => new TextEncoder().encode(s);
const nonce = new Uint8Array(32).fill(7);
const objectId = new Uint8Array(32).fill(8);
const capability = new Uint8Array(32).fill(9);
const cap = Uint8Array.of(1, 2, 3);
const reference = Uint8Array.of(2, 4, 6);
const size = 16_777_217;
const calls: { name: string; parts: Uint8Array[] }[] = [];
const requests: { name: string; bytes: Uint8Array }[] = [];
const staged = new Map<number, Uint8Array>();
let status = 0;
let failPut = false;
let failedPut: Uint8Array | undefined;
let completion = 0;
let rejectReceipt = false;
let corruptPlan = false;
let badResponse = false;
let presentationBad = false;
let inventoryStatus = 0;
let downloadVersion = 2;
let downloadSize = size;
const word = (n: number) => { const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, n); return bytes; };
const wide = (n: bigint) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, n); return bytes; };
function packet(parts: Uint8Array[]) {
  const out = new Uint8Array(4 + parts.reduce((n, p) => n + p.length + 4, 0));
  const v = new DataView(out.buffer); v.setUint32(0, parts.length);
  let at = 4; for (const p of parts) { v.setUint32(at, p.length); out.set(p, at + 4); at += p.length + 4; }
  return out;
}
function unpack(bytes: Uint8Array) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: Uint8Array[] = []; let at = 4;
  for (let i = 0; i < v.getUint32(0); i++) { const n = v.getUint32(at); out.push(bytes.slice(at + 4, at + 4 + n)); at += n + 4; }
  assert.equal(at, bytes.length); return out;
}
const control = (magic: string) => Uint8Array.from([...text(`\u0001${magic}`), ...objectId, ...capability]);
function plan() {
  return packet([text('\u0001MCA'), nonce, new Uint8Array(32).fill(10), Uint8Array.of(status), new Uint8Array(8),
    text(corruptPlan ? 'https://edge.example/escape' : 'https://edge.example'),
    text(status === 2 ? '' : '/v1/attachments/paid-grant'), status === 2 ? new Uint8Array() : cap,
    reference, Uint8Array.of(2, 69, 65, 77), control('OCP'), control('ODL')]);
}
Object.assign(globalThis, {
  __paidNative: async (name: string, body: Uint8Array) => {
    const parts = name === 'open' ? [] : unpack(body); calls.push({ name, parts });
    if (name === 'preview') return packet([text(presentationBad ? '\u0002APV' : '\u0001APV'), nonce, Uint8Array.of(1), word(size), word(2), word(10), word(20), word(30), wide(18446744073709551615n)]);
    if (name === 'inventory') return packet([text('\u0001AIV'), wide(19n), packet([nonce, new Uint8Array(32).fill(10), Uint8Array.of(inventoryStatus), text('large.bin'), text('application/octet-stream'), word(size), word(2), wide(100n), wide(1000000n), word(0), word(presentationBad ? 1 : Math.ceil(size / 65_536))])]);
    if (name === 'download_plan') return packet([text('\u0001ADP'), Uint8Array.of(downloadVersion), text(downloadSize > 16_777_216 ? 'https://edge.example' : ''), text(downloadSize > 16_777_216 ? `/v2/objects/${Array.from(objectId, b => b.toString(16).padStart(2, '0')).join('')}/parts/` : ''), reference, objectId, capability, text('large.bin'), text('application/octet-stream'), word(downloadSize), word(presentationBad ? 0 : Math.ceil(downloadSize / 65_536))]);
    if (name === 'prepare') assert.deepEqual(parts[5], authorization);
    if (name === 'grant') {
      assert.deepEqual(parts[2], authorization);
      assert.equal(staged.size, Math.ceil(size / 65_536), 'all ciphertext is staged before native grant');
      requests.push({ name, bytes: cap });
      if (rejectReceipt) throw new Error('unverified_credit_receipt');
      status = 1; return plan();
    }
    if (name === 'upload') {
      const index = new DataView(parts[2]!.buffer).getUint32(0);
      const bytes = index === 0 ? Uint8Array.of(2, 69, 65, 77) : staged.get(index - 1)!;
      requests.push({ name: `upload/${index}`, bytes });
      if (index === 1 && failPut) { failedPut = bytes.slice(); failPut = false; throw new Error('lost PUT response'); }
      return new Uint8Array();
    }
    if (name === 'complete') { requests.push({name, bytes: new Uint8Array()}); return Uint8Array.of(++completion < 3 ? 0 : 1); }
    if (name === 'delete') { requests.push({name, bytes: new Uint8Array()}); return Uint8Array.of(1); }
    if (name === 'download') {
      if (badResponse) throw new Error('paid_attachment_response_too_large');
      const index = new DataView(parts[2]!.buffer).getUint32(0);
      return new Uint8Array(Math.min(65_536, size - index * 65_536));
    }
    if (name === 'part_recover') {
      const index = new DataView(parts[2]!.buffer).getUint32(0);
      const existing = staged.get(index); if (!existing) throw new Error('local_state_not_found'); return existing;
    }
    if (name === 'part') {
      const index = new DataView(parts[2]!.buffer).getUint32(0);
      const wire = new Uint8Array(parts[3]!.length + 40).fill(index % 251);
      staged.set(index, wire); return wire;
    }
    if (name === 'open') return new Uint8Array(body[body.length - 1] === 1 ? 1 : 65_536);
    return plan();
  },
  __paidFetch: async () => { throw new Error('JavaScript paid attachment HTTP is forbidden'); },
});
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,export const isLegacyDesktopBridge=false;' +
    ['prepare', 'recover', 'receipt', 'part', 'part_recover', 'prune', 'grant', 'upload', 'complete', 'delete'].map(name => `export const credit_attachment_${name}_export = body => globalThis.__paidNative('${name}', body);`).join('') +
    `export const attachment_fetch_chunk_export = body => globalThis.__paidNative('download', body); export const attachment_open_chunk_export = body => globalThis.__paidNative('open', body); export const credit_attachment_preview_export = body => globalThis.__paidNative('preview', body); export const credit_attachments_export = body => globalThis.__paidNative('inventory', body); export const attachment_download_plan_export = body => globalThis.__paidNative('download_plan', body);` };
  if (specifier === './transport') return { shortCircuit: true, url: 'data:text/javascript,export const fetch = globalThis.__paidFetch;' };
  return next(specifier, context);
} });
const authorization = Uint8Array.of(71, 72, 73);
const paidModule = await import('./paid-attachments.ts');
const { scope } = scopeFixture();
const paid = { ...paidModule, ...paidModule.createPaidAttachmentServices({ ...await import('../modules/mesh-messenger'), ...scope }) };

test('large upload stages before PUT and retries exact ciphertext without rereading, recharging, or deleting', async () => {
  const reads: number[] = [];
  const source = { size, read: async (offset: number, length: number) => { reads.push(offset); assert(length <= 65_536); return new Uint8Array(length); } };
  await paid.preparePaidAttachment('/db', nonce, 'large.bin', 'application/octet-stream', size, authorization);
  failPut = true;
  await assert.rejects(paid.uploadPaidAttachment('/db', nonce, source, authorization), /lost PUT response/);
  assert.equal(reads.length, Math.ceil(size / 65_536));
  assert.equal(calls.filter(c => c.name === 'part').length, Math.ceil(size / 65_536));
  assert(!requests.some(r => r.name === 'delete'));
  const uploaded = await paid.uploadPaidAttachment('/db', nonce, source, authorization);
  assert.deepEqual(uploaded.reference, reference);
  assert.deepEqual(uploaded.objectId, objectId);
  assert.equal(reads.filter(offset => offset === 0).length, 1);
  assert.equal(calls.filter(c => c.name === 'prepare').length, 1);
  assert.deepEqual(requests.filter(r => r.name === 'grant').map(r => Array.from(r.bytes)), [[1, 2, 3], [1, 2, 3]]);
  assert.deepEqual(requests.filter(r => r.name === 'upload/1').at(-1)!.bytes, failedPut);
  assert.equal(completion, 3);
  for (const call of calls.filter(call => ['grant','upload','complete'].includes(call.name))) {
    assert.deepEqual(call.parts[0], text('/db'));
    assert.deepEqual(call.parts[1], nonce);
    assert.equal(call.parts.length, call.name === 'complete' ? 2 : 3);
  }
  await uploaded.discard();
  assert.equal(calls.at(-1)?.name, 'delete');
  assert.deepEqual(calls.at(-1)?.parts, [text('/db'), nonce]);
});

test('cancelled, malformed, and unauthenticated grants cannot start file I/O', async () => {
  let reads = 0;
  const source = { size, read: async (_: number, length: number) => { reads++; return new Uint8Array(length); } };
  status = 2; const before = requests.length;
  await assert.rejects(paid.uploadPaidAttachment('/db', nonce, source, authorization), /cancelled/);
  assert.equal(requests.length, before);
  status = 0; corruptPlan = true;
  await assert.rejects(paid.uploadPaidAttachment('/db', nonce, source, authorization), /invalid_paid_attachment/);
  corruptPlan = false; rejectReceipt = true;
  await assert.rejects(paid.uploadPaidAttachment('/db', nonce, source, authorization), /unverified_credit_receipt/);
  rejectReceipt = false; assert.equal(reads, 0);
});

test('large download writes bounded chunks and aborts its partial output on oversized response', async () => {
  let total = 0; let committed = false; let aborted = false;
  const sink = { write: async (offset: number, chunk: Uint8Array) => { assert.equal(offset, total); assert(chunk.length <= 65_536); total += chunk.length; },
    finish: async () => { committed = true; }, abort: async () => { aborted = true; } };
  const summary = { reference, objectId, downloadCapability: capability, size, chunkCount: Math.ceil(size / 65_536), chunkSize: 65_536 };
  await paid.downloadPaidAttachment('/db', summary, sink);
  assert.equal(total, size); assert(committed); assert(!aborted);
  total = 0; committed = false; badResponse = true;
  await assert.rejects(paid.downloadPaidAttachment('/db', summary, sink), /too_large/);
  assert.equal(total, 0); assert(!committed); assert(aborted);
});


test('restarted uploads cannot consume with a missing staged suffix or read a replacement source', async () => {
  badResponse = false; status = 0; completion = 0;
  const last = Math.ceil(size / 65_536) - 1;
  const original = staged.get(last)!;
  staged.delete(last);
  const sent = requests.length;
  const sealed = calls.filter(call => call.name === 'part').length;
  await assert.rejects(paid.uploadStagedPaidAttachment('/db', nonce, size, authorization), /staging_incomplete/);
  assert.equal(requests.length, sent, 'even the grant request must wait for complete local staging');
  assert.equal(calls.filter(call => call.name === 'part').length, sealed);
  staged.set(last, original);
  const recovered = await paid.uploadStagedPaidAttachment('/db', nonce, size, authorization);
  assert.deepEqual(recovered.reference, reference);
  assert.equal(calls.filter(call => call.name === 'part').length, sealed, 'restart only recovers exact saved ciphertext');
});


test('native previews and durable inventory display exact values without preparing or reserving', async () => {
  const before = calls.filter(call => call.name === 'prepare').length;
  const preview = await paid.previewPaidAttachment('/db', size);
  assert.deepEqual(preview, { nonce, purpose: 'test', size, price: 2, available: 10, delayed: 20, reserved: 30, revision: 18446744073709551615n });
  assert.deepEqual(calls.at(-1)?.parts, [text('/db'), word(size)]);
  inventoryStatus = 3;
  const beforeRecover = calls.filter(call => call.name === 'recover').length;
  const beforeNetwork = requests.length;
  await assert.rejects(paid.uploadStagedPaidAttachment('/db', nonce, size, authorization), /not_reserved/);
  assert.equal(calls.filter(call => call.name === 'recover').length, beforeRecover);
  assert.equal(requests.length, beforeNetwork);
  const list = await paid.readPaidAttachments('/db');
  assert.equal(list.revision, 19n);
  assert.equal(list.items[0]?.status, 3);
  assert.equal(list.items[0]?.filename, 'large.bin');
  assert.equal(list.items[0]?.size, size);
  assert.equal(calls.filter(call => call.name === 'prepare').length, before);
  presentationBad = true;
  await assert.rejects(paid.previewPaidAttachment('/db', size), /invalid_paid_attachment/);
  await assert.rejects(paid.readPaidAttachments('/db'), /invalid_paid_attachment/);
  presentationBad = false;
});

test('recipient routing comes only from the native authenticated download plan', async () => {
  const plan = await paid.readAttachmentDownloadPlan('/db', reference);
  assert.equal(plan.version, 2);
  assert.equal(plan.origin, 'https://edge.example');
  assert.equal(plan.size, size);
  assert.deepEqual(plan.reference, reference);
  assert.deepEqual(calls.at(-1)?.parts, [text('/db'), reference]);
  presentationBad = true;
  await assert.rejects(paid.readAttachmentDownloadPlan('/db', reference), /invalid_paid_attachment/);
  presentationBad = false;
});


test('profile4 plans preserve exact unpadded sink sizes and explicitly select the native free or paid route', async () => {
  try {
    downloadVersion = 4;
    for (const original of [1, 65_536, 16_777_216, 16_777_217, 536_870_912]) {
      downloadSize = original;
      const result = await paid.readAttachmentDownloadPlan('/db', reference);
      assert.equal(result.version, 4); assert.equal(result.size, original);
      assert.equal(result.chunkCount, Math.ceil(original / 65_536));
      assert.equal(result.origin, original > 16_777_216 ? 'https://edge.example' : '');
    }
    downloadVersion = 3;
    await assert.rejects(paid.readAttachmentDownloadPlan('/db', reference), /invalid_paid_attachment/);
    downloadVersion = 4; presentationBad = true;
    await assert.rejects(paid.readAttachmentDownloadPlan('/db', reference), /invalid_paid_attachment/);
  } finally { downloadVersion = 2; downloadSize = size; presentationBad = false; }
});
