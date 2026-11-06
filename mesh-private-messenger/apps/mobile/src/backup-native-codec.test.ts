import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loaded } from '../scripts/backup-native-test-fixture.mjs';
const { c } = await loaded();
const bytes = (n, value = 1) => new Uint8Array(n).fill(value);
const utf8 = text => new TextEncoder().encode(text);
const cat = (...parts) => Uint8Array.from(parts.flatMap(part => [...part]));
const u = (value, size) => { let n = BigInt(value); const out = new Uint8Array(size); for (let i = size - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; } return out; };
const vec = value => cat(u(value.length, 4), value);
const list = values => cat(vec(u(values.length, 4)), ...values.map(vec));
const reply = body => cat([1], body);
const action = { databasePath: '/owned/db', expectedProfile: bytes(3, 4) };
const baseFrame = cat([1], vec(utf8(action.databasePath)), vec(action.expectedProfile));
const id = bytes(32, 9), direct = { kind: 'direct', id: bytes(16, 2) }, group = { kind: 'group', id: bytes(32, 3) };
const max = '18446744073709551615';
const createFrame = body => cat([2], id, body);
const badRequest = fn => assert.throws(fn, { message: 'invalid_backup_native_request' });
const badReply = fn => assert.throws(fn, { message: 'invalid_backup_native_reply' });
const row = (kind, ordinal = 2, text = utf8('hé'), messageId = bytes(kind === 1 ? 16 : 32, ordinal)) => list([u(ordinal, 2), [1], messageId, bytes(32, 7), bytes(16, 8), u(max, 8), [0], text]);
const page = (kind, rows, offset = 0, next = [0], scopeId = kind === 1 ? direct.id : group.id) => reply(list([id, [kind], scopeId, u(offset, 4), next, list(rows)]));
const conversation = (kind, count, name = utf8('café'), scopeId = kind === 1 ? direct.id : group.id) => list([[kind], scopeId, kind === 1 ? bytes(32, 5) : [], name, u(count, 4)]);
const overview = (counts = [3, 8, 1, 1, 1, 2, 2], scopes = [conversation(1, 2), conversation(2, 1)]) => reply(list([id, u(max, 8), ...counts.map(n => u(n, 4)), list(scopes)]));

test('all seven requests use exact native framing and preserve full U64 times', () => {
  assert.deepEqual(c.encodeBackupRequest(action, { kind: 'list' }), baseFrame);
  for (const kind of ['remove', 'overview']) assert.deepEqual(c.encodeBackupRequest(action, { kind, backupId: id }), cat(baseFrame, id));
  const portable = { wire: bytes(3, 10), recoveryCode: 'TEST-ONLY' };
  const expected = cat(baseFrame, vec(portable.wire), vec(utf8(portable.recoveryCode)));
  assert.deepEqual(c.encodeBackupRequest(action, { kind: 'preview', ...portable }), expected);
  assert.deepEqual(c.encodeBackupRequest(action, { kind: 'import', ...portable, confirmedId: id }), cat(expected, id));
  assert.deepEqual(c.encodeBackupRequest(action, { kind: 'create', selections: [{ scope: group, fromTime: '9007199254740993', throughTime: max }] }), cat(baseFrame, vec(cat([1, 2], vec(group.id), [1], u('9007199254740993', 8), [1], u(max, 8)))));
  assert.deepEqual(c.encodeBackupRequest(action, { kind: 'page', backupId: id, scope: direct, offset: 256, limit: 16 }), cat(baseFrame, id, [1], vec(direct.id), u(256, 4), [16]));
});

test('request validation rejects ambiguous time ranges identities and duplicate selection custody', () => {
  for (const time of ['', '00', '+1', '-1', ' 1', '1.0', '18446744073709551616']) badRequest(() => c.encodeBackupRequest(action, { kind: 'create', selections: [{ scope: direct, fromTime: time, throughTime: null }] }));
  badRequest(() => c.encodeBackupRequest(action, { kind: 'create', selections: [{ scope: direct, fromTime: '2', throughTime: '1' }] }));
  for (const selections of [[], Array(33).fill({ scope: direct, fromTime: null, throughTime: null }), Array(2).fill({ scope: direct, fromTime: null, throughTime: null })]) badRequest(() => c.encodeBackupRequest(action, { kind: 'create', selections }));
  for (const scope of [{ kind: 'direct', id: bytes(32) }, { kind: 'group', id: bytes(16) }, { kind: 'other', id: bytes(32) }]) badRequest(() => c.encodeBackupRequest(action, { kind: 'page', backupId: id, scope, offset: 0, limit: 1 }));
  for (const value of [{ ...action, databasePath: '' }, { ...action, databasePath: '\0db' }, { ...action, databasePath: '\ud800' }, { ...action, expectedProfile: bytes(0) }, { ...action, expectedProfile: bytes(36135) }]) badRequest(() => c.encodeBackupRequest(value, { kind: 'list' }));
  for (const [offset, limit] of [[-1,1],[257,1],[0,0],[0,17],[0.5,1],[0,NaN]]) badRequest(() => c.encodeBackupRequest(action, { kind: 'page', backupId: id, scope: group, offset, limit }));
});

test('request byte and recovery-code codepoint limits are inclusive and refuse before encoding', () => {
  const wire = bytes(16796864), recoveryCode = '😀'.repeat(1024);
  const encoded = c.encodeBackupRequest({ databasePath: 'd'.repeat(4096), expectedProfile: bytes(36134) }, { kind: 'preview', wire, recoveryCode });
  assert.equal(encoded.length, 16841207);
  for (const code of ['', 'x'.repeat(1025), '\udc00']) badRequest(() => c.encodeBackupRequest(action, { kind: 'preview', wire: bytes(1), recoveryCode: code }));
  for (const size of [0,16796865]) badRequest(() => c.encodeBackupRequest(action, { kind: 'preview', wire: bytes(size), recoveryCode: 'x' }));
  badRequest(() => c.encodeBackupRequest({ ...action, databasePath: 'd'.repeat(4097) }, { kind: 'list' }));
});

test('create reply decodes bounded UTF8 without losing BOM or transferring mutable source ownership', () => {
  const frame = createFrame(cat(vec(bytes(3, 6)), vec(utf8('\ufeffTEST-ONLY😀'))));
  const decoded = c.decodeBackupCreateReply(frame);
  assert.deepEqual(decoded.wire, bytes(3, 6)); assert.equal(decoded.recoveryCode, '\ufeffTEST-ONLY😀');
  frame.fill(0); assert.deepEqual(decoded.wire, bytes(3, 6));
  for (const code of [new Uint8Array([0xc0,0xaf]), utf8('a'.repeat(1025))]) badReply(() => c.decodeBackupCreateReply(createFrame(cat(vec(bytes(1)), vec(code)))));
  badReply(() => c.decodeBackupCreateReply(createFrame(cat(vec(bytes(0)), vec(utf8('x'))))));
});

test('list and receipts retain exact U64 decimal strings and only finite disposition tags', () => {
  const decoded = c.decodeBackupListReply(reply(list([list([id,u(max,8)]),list([bytes(32,8),u(0,8)])])));
  assert.equal(decoded[0].createdAt, max); assert.equal(decoded[1].createdAt, '0');
  assert.deepEqual(c.decodeBackupListReply(reply(list([]))), []);
  for (const disposition of [1,2]) assert.equal(c.decodeBackupImportReply(reply(cat(id,[disposition]))).disposition, disposition);
  assert.deepEqual(c.decodeBackupRemoveReply(reply(cat(id,[1]))).backupId, id);
  for (const disposition of [0,3]) badReply(() => c.decodeBackupImportReply(reply(cat(id,[disposition]))));
  badReply(() => c.decodeBackupRemoveReply(reply(cat(id,[2]))));
  badReply(() => c.decodeBackupListReply(reply(list(Array(9).fill(list([id,u(0,8)]))))));
});

test('overview preserves scope discriminants and checks count conservation and scope identities', () => {
  const decoded = c.decodeBackupOverviewReply(overview());
  assert.equal(decoded.createdAt, max); assert.equal(decoded.candidateCount, 8);
  assert.deepEqual(decoded.conversations.map(s => [s.kind,s.id.length,s.peer.length,s.messageCount]), [['direct',16,32,2],['group',32,0,1]]);
  for (const counts of [[3,7,1,1,1,2,2],[3,8,1,1,1,2,9],[4097,4097,0,0,0,0,0],[3,8193,1,1,1,2,2]]) badReply(() => c.decodeBackupOverviewReply(overview(counts)));
  badReply(() => c.decodeBackupOverviewReply(overview(undefined,[conversation(1,3,utf8('bad\0name'))])));
  badReply(() => c.decodeBackupOverviewReply(overview(undefined,[conversation(2,3,utf8('g'),bytes(16))])));
});

test('pages preserve sparse original ordinals legacy empty group IDs UTF8 text and exact times', () => {
  const directPage = c.decodeBackupPageReply(page(1,[row(1)],0,cat([1],u(1,4))));
  assert.equal(directPage.kind,'direct');assert.equal(directPage.nextOffset,1);assert.equal(directPage.entries[0].timestamp,max);assert.equal(directPage.entries[0].text,'hé');
  const groupPage = c.decodeBackupPageReply(page(2,[row(2,2,utf8('\ufeffold'),bytes(0)),row(2,255)],254));
  assert.equal(groupPage.kind,'group');assert.equal(groupPage.nextOffset,null);
  assert.deepEqual(groupPage.entries.map(r => [r.ordinal,r.messageId.length]),[[2,0],[255,32]]);assert.equal(groupPage.entries[0].text,'\ufeffold');
  for (const next of [[2],cat([1],u(0,4)),cat([1],u(2,4)),cat([1],u(256,4))]) badReply(() => c.decodeBackupPageReply(page(1,[row(1)],0,next)));
  badReply(() => c.decodeBackupPageReply(page(1,[row(1,2),row(1,1)])));
  badReply(() => c.decodeBackupPageReply(page(2,[row(2,2,utf8('a'),id),row(2,3,utf8('b'),id)])));
  badReply(() => c.decodeBackupPageReply(page(1,[row(1,2,bytes(0))])));
});

test('page text and frame quotas refuse aggregate excess and malformed UTF8 before output', () => {
  const full = c.decodeBackupPageReply(page(1,[0,1,2,3].map(n => row(1,n,bytes(32768,97)))));
  assert.equal(full.entries.reduce((n,r)=>n+r.text.length,0),131072);
  badReply(() => c.decodeBackupPageReply(page(1,[0,1,2,3].map(n=>row(1,n,bytes(32768,97))).concat(row(1,4,utf8('x'))))));
  badReply(() => c.decodeBackupPageReply(page(1,[row(1,0,bytes(32769,97))])));
  badReply(() => c.decodeBackupPageReply(page(2,[row(2,0,bytes(65347,97))])));
  badReply(() => c.decodeBackupPageReply(page(1,[row(1,0,new Uint8Array([0xff]))])));
  badReply(() => c.decodeBackupPageReply(bytes(135169)));
});

test('every reply decoder rejects changed version trailing bytes and hostile length prefixes', () => {
  const cases = [[c.decodeBackupCreateReply,createFrame(cat(vec(bytes(1)),vec(utf8('x'))))],[c.decodeBackupListReply,reply(list([]))],[c.decodeBackupOverviewReply,overview()],[c.decodeBackupPageReply,page(1,[])],[c.decodeBackupImportReply,reply(cat(id,[1]))],[c.decodeBackupRemoveReply,reply(cat(id,[1]))]];
  for (const [decode,frame] of cases) {
    const version=frame.slice();version[0]=frame[0]===1?2:1;badReply(()=>decode(version));
    badReply(()=>decode(cat(frame,[0])));badReply(()=>decode(frame.subarray(0,frame.length-1)));
  }
  for (const decode of [c.decodeBackupCreateReply,c.decodeBackupListReply,c.decodeBackupOverviewReply,c.decodeBackupPageReply]) badReply(()=>decode(new Uint8Array([1,255,255,255,255])));
});

test('decoded byte fields never borrow mutable Buffer-backed native frames', () => {
  const cases = [[c.decodeBackupCreateReply,createFrame(cat(vec(bytes(3,6)),vec(utf8('TEST-ONLY'))))],[c.decodeBackupListReply,reply(list([list([id,u(max,8)])]))],[c.decodeBackupOverviewReply,overview()],[c.decodeBackupPageReply,page(1,[row(1)])],[c.decodeBackupImportReply,reply(cat(id,[1]))],[c.decodeBackupRemoveReply,reply(cat(id,[1]))]];
  const leaves = value => ArrayBuffer.isView(value) && value.BYTES_PER_ELEMENT === 1 ? [value] : value !== null && typeof value === 'object' ? Object.values(value).flatMap(leaves) : [];
  for (const [decode,bytes] of cases) {
    const input = Buffer.from(bytes), output = decode(input), fields = leaves(output), originals = fields.map(field => Uint8Array.from(field));
    assert.ok(fields.length > 0); input.fill(0);
    fields.forEach((field,index) => assert.deepEqual(Uint8Array.from(field), originals[index]));
  }
});

{
const { loaded, bytes, draftId, otherId, utf8, concat, uint, vector, list, action, common, code, maximumWire, originalWire, createReply, stateReply, resumeReply, discardReply, equalBytes, badRequest, badReply } = await import('../scripts/backup-native-test-fixture.mjs');
test('create v2 carries its own required draft ID and refuses the old unshipped reply', async () => {
  const { c } = await loaded(); const input = Buffer.from(createReply());
  const output = c.decodeBackupCreateReply(input);
  equalBytes(output.draftId, draftId); equalBytes(output.wire, originalWire); assert.equal(output.recoveryCode, code);
  input.fill(0); equalBytes(output.draftId, draftId); equalBytes(output.wire, originalWire);
  badReply(() => c.decodeBackupCreateReply(concat([1], vector(originalWire), vector(utf8(code)))));
  badReply(() => c.decodeBackupCreateReply(concat(createReply(), [0])));
});

test('the four pending requests preserve exact common framing and bound code and confirmed ID', async () => {
  const { c } = await loaded();
  for (const kind of ['pending_state', 'pending_repair']) equalBytes(c.encodeBackupRequest(action, { kind }), common);
  equalBytes(c.encodeBackupRequest(action, { kind: 'pending_discard', draftId }), concat(common, draftId));
  equalBytes(c.encodeBackupRequest(action, { kind: 'pending_resume', draftId, recoveryCode: code }), concat(common, draftId, vector(utf8(code))));
  for (const kind of ['pending_resume','pending_discard']) for (const id of [bytes(0),bytes(31),bytes(33)]) badRequest(() => c.encodeBackupRequest(action, { kind, draftId: id, recoveryCode: code }));
  for (const recoveryCode of ['', 'x'.repeat(1025), '\ud800']) badRequest(() => c.encodeBackupRequest(action, { kind: 'pending_resume', draftId, recoveryCode }));
  const maximum = c.encodeBackupRequest({ databasePath: 'd'.repeat(4096), expectedProfile: bytes(36134) }, { kind: 'pending_resume', draftId, recoveryCode: '😀'.repeat(1024) });
  assert.equal(maximum.length, 44371);
});

test('pending state is finite, exact length, owns its ID and preserves maximum U64 time', async () => {
  const { c } = await loaded();
  assert.equal(c.decodeBackupPendingStateReply(Uint8Array.of(1,0)).kind, 'empty');
  assert.equal(c.decodeBackupPendingStateReply(Uint8Array.of(1,2)).kind, 'repairRequired');
  const input = Buffer.from(stateReply()), state = c.decodeBackupPendingStateReply(input);
  assert.equal(state.kind, 'pending'); assert.equal(state.createdAt, '18446744073709551615'); assert.equal(state.wireSize, maximumWire);
  input.fill(0); equalBytes(state.draftId, draftId);
  for (const size of [0,maximumWire+1]) badReply(() => c.decodeBackupPendingStateReply(concat([1,1],draftId,uint(0,8),uint(size,4))));
  for (const input of [Uint8Array.of(1,3),Uint8Array.of(2,0),Uint8Array.of(1,0,0),stateReply().subarray(0,45)]) badReply(() => c.decodeBackupPendingStateReply(input));
});

test('resume returns only owned bounded wire and cleanup replies expose no status distinction', async () => {
  const { c } = await loaded(); const input = Buffer.from(resumeReply()), wire = c.decodeBackupResumeReply(input);
  equalBytes(wire, originalWire); input.fill(0); equalBytes(wire, originalWire);
  assert.equal(c.decodeBackupResumeReply(concat([1],vector(bytes(maximumWire)))).length, maximumWire);
  for (const size of [0,maximumWire+1]) badReply(() => c.decodeBackupResumeReply(concat([1],vector(bytes(size)))));
  badReply(() => c.decodeBackupResumeReply(concat(resumeReply(),vector(utf8(code)))));
  for (const status of [1,2]) {
    equalBytes(c.decodeBackupDiscardReply(discardReply(draftId,status)).draftId,draftId);
    assert.equal(c.decodeBackupRepairReply(Uint8Array.of(1,status)),undefined);
  }
  for (const status of [0,3,255]) {
    badReply(() => c.decodeBackupDiscardReply(discardReply(draftId,status)));
    badReply(() => c.decodeBackupRepairReply(Uint8Array.of(1,status)));
  }
  badReply(() => c.decodeBackupDiscardReply(concat(discardReply(),[0])));
  badReply(() => c.decodeBackupRepairReply(Uint8Array.of(1,1,0)));
});

test('malformed page UTF8 leaves no uncleared owned record identity copies', async () => {
  const { c, ownedCopies } = await loaded({ track: true });
  const row = list(uint(0,2),[1],bytes(16,4),bytes(32,5),bytes(16,6),uint(0,8),[0],Uint8Array.of(255));
  const reply = concat([1],list(draftId,[1],bytes(16,2),uint(0,4),[0],list(row)));
  badReply(()=>c.decodeBackupPageReply(reply));
  assert.ok(ownedCopies.every(value=>value.every(byte=>byte===0)),'Invalid text cannot strand copied private record IDs');
});

test('all recovery-code branches clear actual encoder-owned temporary bytes on success and late validation failure', async () => {
  const { c, allocations, encodedTexts } = await loaded({ track: true }); const leaks = [];
  for (const kind of ['preview','import','pending_resume','invalid_import']) {
    const firstAllocation = allocations.length, firstText = encodedTexts.length;
    let output;
    const request = kind === 'pending_resume' ? {kind,draftId,recoveryCode:code}
      : {kind:kind==='invalid_import'?'import':kind,wire:originalWire,recoveryCode:code,confirmedId:kind==='invalid_import'?bytes(31):draftId};
    if (kind==='invalid_import') badRequest(()=>c.encodeBackupRequest(action,request));
    else { output=c.encodeBackupRequest(action,request);assert.ok(Buffer.from(output).includes(utf8(code))); }
    const encodedCode = encodedTexts.slice(firstText).filter(entry=>entry.text===code);
    assert.equal(encodedCode.length,1);
    if(encodedCode.some(entry=>entry.bytes.some(byte=>byte!==0))) leaks.push(kind+':TextEncoder-owned-code');
    if(allocations.slice(firstAllocation).some(value=>value!==output&&Buffer.from(value).includes(utf8(code)))) leaks.push(kind+':owned-code-vector');
    output?.fill(0);
  }
  assert.deepEqual(leaks,[],'Only the returned request may own encoded code after the encoder completes');
  equalBytes(action.expectedProfile,bytes(3,3));equalBytes(originalWire,utf8('SYNTHETIC-CIPHERTEXT-ONLY'));
});

}


// Authored synthetic frames emitted by the actual Mesh encoder and consumed by
// its strict request parser. This checks framing, not account or native authority.
{
const { readFile } = await import('node:fs/promises');
const fixture = JSON.parse(await readFile(new URL('../scripts/fixtures/backup-native-v175.json', import.meta.url), 'utf8'));
const k = fixture.known, vectors = fixture.vectors;
const fromHex = hex => Uint8Array.from(Buffer.from(hex, 'hex'));
const frame = name => { const value = fromHex(vectors[name].hex); assert.equal(value.length, vectors[name].bytes); return value; };
const hex = value => Buffer.from(value).toString('hex');
const portable = { wire: utf8(k.wireUtf8), recoveryCode: k.recoveryCode };

test('all eleven TS requests match actual Mesh 175 strict-parser-consumed frames', () => {
  const action = { databasePath: k.requestPath, expectedProfile: utf8(k.requestProfileUtf8) };
  const requests = {
    create: { kind: 'create', selections: k.requestSelections.map(s => ({ scope: { kind: s.kind === 1 ? 'direct' : 'group', id: fromHex(s.scopeIdHex) }, fromTime: s.from, throughTime: s.through })) },
    preview: { kind: 'preview', ...portable }, import: { kind: 'import', ...portable, confirmedId: fromHex(k.backupIdHex) },
    list: { kind: 'list' }, remove: { kind: 'remove', backupId: fromHex(k.backupIdHex) }, overview: { kind: 'overview', backupId: fromHex(k.backupIdHex) },
    page: { kind: 'page', backupId: fromHex(k.backupIdHex), scope: { kind: 'group', id: fromHex(k.requestPage.scopeIdHex) }, offset: k.requestPage.offset, limit: k.requestPage.limit },
    pending_state: { kind: 'pending_state' }, pending_repair: { kind: 'pending_repair' },
    pending_resume: { kind: 'pending_resume', draftId: fromHex(k.draftIdHex), recoveryCode: k.recoveryCode },
    pending_discard: { kind: 'pending_discard', draftId: fromHex(k.draftIdHex) },
  };
  assert.equal(Object.keys(vectors).filter(name => name.startsWith('request_')).length, Object.keys(requests).length);
  for (const [name, request] of Object.entries(requests)) assert.deepEqual(c.encodeBackupRequest(action, request), frame('request_' + name), name);
});

test('all seventeen actual Mesh 175 replies retain canonical fields and independent byte ownership', () => {
  const decoders = {
    create: c.decodeBackupCreateReply, import_new: c.decodeBackupImportReply, import_identical: c.decodeBackupImportReply,
    remove: c.decodeBackupRemoveReply, list: c.decodeBackupListReply, overview: c.decodeBackupOverviewReply,
    page_direct: c.decodeBackupPageReply, page_group_legacy: c.decodeBackupPageReply, page_group_continuation: c.decodeBackupPageReply,
    pending_state_empty: c.decodeBackupPendingStateReply, pending_state_pending: c.decodeBackupPendingStateReply, pending_state_repair: c.decodeBackupPendingStateReply,
    pending_resume: c.decodeBackupResumeReply, pending_discard_removed: c.decodeBackupDiscardReply, pending_discard_absent: c.decodeBackupDiscardReply,
    pending_repair_repaired: c.decodeBackupRepairReply, pending_repair_empty: c.decodeBackupRepairReply,
  };
  const leaves = value => value instanceof Uint8Array ? [value] : value !== null && typeof value === 'object' ? Object.values(value).flatMap(leaves) : [];
  const decoded = {};
  assert.equal(Object.keys(vectors).filter(name => !name.startsWith('request_')).length, Object.keys(decoders).length);
  for (const [name, decode] of Object.entries(decoders)) {
    const input = Buffer.from(frame(name)), output = decode(input), owned = leaves(output), originals = owned.map(value => new Uint8Array(value));
    input.fill(0); owned.forEach((value, index) => assert.deepEqual(value, originals[index], name)); decoded[name] = output;
  }
  assert.deepEqual(Object.keys(decoded.create).sort(), ['draftId','recoveryCode','wire']);
  assert.equal(hex(decoded.create.draftId), k.draftIdHex); assert.deepEqual(decoded.create.wire, portable.wire); assert.equal(decoded.create.recoveryCode, k.recoveryCode);
  for (const [name, disposition] of [['import_new',1],['import_identical',2]]) { assert.equal(hex(decoded[name].backupId), k.backupIdHex); assert.equal(decoded[name].disposition, disposition); }
  assert.equal(hex(decoded.remove.backupId), k.backupIdHex);
  assert.deepEqual(decoded.list.map(row => [hex(row.backupId), row.createdAt]), [[k.backupIdHex,k.maximumU64],[k.secondBackupIdHex,k.zeroU64]]);
  const overview = decoded.overview; assert.equal(overview.createdAt, k.maximumU64); assert.equal(hex(overview.backupId), k.backupIdHex);
  for (const [field, expected] of Object.entries({includedCount:k.overviewCounts.included,candidateCount:k.overviewCounts.candidate,omittedTimed:k.overviewCounts.omittedTimed,omittedUnknown:k.overviewCounts.omittedUnknown,omittedNontext:k.overviewCounts.omittedNontext,omittedEmpty:k.overviewCounts.omittedEmpty,attachmentMessages:k.overviewCounts.attachmentMessages})) assert.equal(overview[field], expected);
  assert.deepEqual(overview.conversations.map(row => [row.kind,hex(row.id),hex(row.peer),row.name,row.messageCount]), [['direct',k.directIdHex,k.peerHex,'',1],['group',k.groupIdHex,'',k.groupName,2]]);
  const direct = decoded.page_direct; assert.equal(direct.kind,'direct'); assert.equal(hex(direct.scopeId),k.directIdHex); assert.equal(hex(direct.backupId),k.backupIdHex);
  assert.equal(direct.entries[0].text,k.directText); assert.equal(direct.entries[0].timestamp,k.maximumU64); assert.equal(hex(direct.entries[0].messageId),k.directMessageIdHex);
  const group = decoded.page_group_legacy; assert.equal(group.kind,'group'); assert.equal(hex(group.scopeId),k.groupIdHex); assert.deepEqual(group.entries.map(row=>row.ordinal),k.groupSparseOrdinals);
  assert.equal(hex(group.entries[0].messageId),k.groupLegacyFirstMessageIdHex); assert.equal(group.entries[0].text,k.legacyGroupText);
  assert.equal(hex(group.entries[1].messageId),k.groupMessageIdHex); assert.equal(group.entries[1].attachmentOmitted,k.groupSecondAttachmentOmitted); assert.equal(group.entries[1].text,k.groupSecondText); assert.equal(group.entries[1].timestamp,k.groupSecondTimestamp);
  for (const page of [direct,group,decoded.page_group_continuation]) for (const row of page.entries) { assert.equal(hex(row.senderAccount),k.senderAccountHex); assert.equal(hex(row.senderDevice),k.senderDeviceHex); }
  assert.equal(decoded.page_group_continuation.nextOffset,k.continuationNextOffset);
  assert.deepEqual(decoded.pending_state_empty,{kind:'empty'}); assert.deepEqual(decoded.pending_state_repair,{kind:'repairRequired'});
  assert.equal(decoded.pending_state_pending.kind,'pending'); assert.equal(hex(decoded.pending_state_pending.draftId),k.draftIdHex); assert.equal(decoded.pending_state_pending.createdAt,k.pendingCreatedAt); assert.equal(decoded.pending_state_pending.wireSize,k.pendingWireSize);
  assert.ok(decoded.pending_resume instanceof Uint8Array); assert.deepEqual(decoded.pending_resume,portable.wire);
  for (const name of ['pending_discard_removed','pending_discard_absent']) { assert.deepEqual(Object.keys(decoded[name]),['draftId']); assert.equal(hex(decoded[name].draftId),k.draftIdHex); }
  assert.equal(decoded.pending_repair_repaired,undefined); assert.equal(decoded.pending_repair_empty,undefined);
});
}
