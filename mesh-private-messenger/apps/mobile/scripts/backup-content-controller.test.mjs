import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixture, active, previewed, parseRequest, deferred, id, idText, group } from './backup-archive-fixture.mjs';
const bytes = (n, v) => new Uint8Array(n).fill(v), utf8 = s => new TextEncoder().encode(s);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(p => Uint8Array.from(p))));
const u = (n, size = 4) => { let v = BigInt(n); const a = new Uint8Array(size); for (let i = size - 1; i >= 0; i--) { a[i] = Number(v & 255n); v >>= 8n; } return a; };
const vec = p => concat(u(p.length), p), list = (...p) => concat(vec(u(p.length)), ...p.map(vec));
const token = bytes(32, 7);
const overview = backupId => concat([2], list(backupId, u(9, 8), ...[1, 1, 0, 0, 0, 0, 1].map(n => u(n)), [1], list(...[2, 1, 0, 0, 1, 0].map(n => u(n))), list(list([2], group, [], utf8('Files'), u(1)))));
const page = (backupId, name, mime) => concat([2, 0], list(backupId, [2], group, u(0), [0], list(list(u(23, 2), [2], [], bytes(32, 4), bytes(16, 5), u(9, 8), [], list(list([0], [0], utf8(name), utf8(mime), u(65537), token), list([1], [3]))))));
const chunk = (backupId, n) => concat([2, 1], list(backupId, [2], group, u(23, 2), [0], [n], u(65537), token, bytes(n ? 1 : 65536, n ? 43 : 42)));
function contentFixture({ intercept, save, name = 'notes.bin', mime = 'application/octet-stream' } = {}) {
  return fixture({ save, reply(symbol, encoded) {
    const rest = parseRequest(encoded).rest(), backupId = rest.slice(0, 32);
    const fallback = () => symbol.endsWith('_preview') ? overview(id) : symbol.endsWith('_overview') ? overview(backupId)
      : symbol.endsWith('_page') ? rest[32] === 4 ? chunk(backupId, rest.at(-1)) : page(backupId, name, mime) : undefined;
    return intercept ? intercept({ symbol, encoded, rest, fallback }) : fallback();
  } });
}
async function opened(f) {
  await f.client.refreshArchives(); await f.client.openArchive(idText);
  const overview = active(f).reader; assert.equal(overview.kind, 'overview');
  await f.client.openConversation(overview.overview.conversations[0]);
  const reader = active(f).reader; assert.equal(reader.kind, 'page');
  assert.equal(reader.page.entries[0].kind, 'content');
  const file = reader.page.entries[0].attachments[0]; assert.equal(file.kind, 'included'); return file;
}

test('content archive controller presents separate file counts and explicit omissions without exposing tokens', async () => {
  const f = contentFixture(); const preview = await previewed(f);
  assert.equal(preview.overview.files?.kind, 'content');
  assert.deepEqual(preview.overview.files.counts, { total: 2, included: 1, unavailable: 0, expired: 0, unsupported: 1, aboveProfile: 0 });
  assert.equal(preview.overview.files.policy, 'allowOmissions');
  const file = await opened(f); assert.equal(file.filename, 'notes.bin'); assert.equal(file.size, 65537);
  assert.deepEqual(active(f).reader.page.entries[0].attachments[1], { kind: 'omitted', slot: 1, reason: 'unsupported' });
  assert.equal('token' in file, false); assert.equal('bytes' in file, false); assert.ok(Object.isFrozen(file)); f.client.dispose();
});

test('archive save assembles exact original-slot chunks and clears its one file buffer after guarded output', async () => {
  let saved, signal, context, count = 0;
  const f = contentFixture({ save(name, mime, data, abort, source) {
    count++; assert.equal(name, 'notes.bin'); assert.equal(mime, 'application/octet-stream');
    assert.equal(data.length, 65537); assert.ok(data.subarray(0, 65536).every(n => n === 42)); assert.equal(data[65536], 43);
    saved = data; signal = abort; context = source; return true;
  } });
  const file = await opened(f); await f.client.saveAttachment(file);
  assert.equal(count, 1); assert.equal(signal.aborted, false); assert.match(context, /^backup-file\//);
  assert.equal(active(f).file.kind, 'saved'); assert.ok(saved.every(n => n === 0));
  const calls = f.calls.filter(c => c.symbol.endsWith('_page')).slice(1);
  assert.equal(calls.length, 2); assert.deepEqual(calls.map(c => [...c.encoded.slice(-3)]), [[23, 0, 0], [23, 0, 1]]);
  for (const call of calls) { assert.ok(call.request.every(n => n === 0)); assert.ok(call.response.every(n => n === 0)); }
  f.client.dispose();
});

test('copied and retired same-name attachment controls cannot dispatch or save a newer page file', async () => {
  let count = 0; const f = contentFixture({ save() { count++; return true; } });
  const file = await opened(f); const calls = f.calls.length;
  await assert.rejects(f.client.saveAttachment({ ...file }), /stale_backup_attachment/); assert.equal(f.calls.length, calls);
  const current = active(f).reader; await f.client.openConversation(current.conversation);
  await assert.rejects(f.client.saveAttachment(file), /stale_backup_attachment/);
  assert.equal(count, 0); f.client.dispose();
});

test('reader cancellation discards a late native chunk without issuing another chunk or publishing output', async () => {
  const pending = deferred(); let saves = 0;
  const f = contentFixture({ intercept({ symbol, rest, fallback }) { return symbol.endsWith('_page') && rest[32] === 4 ? pending.promise : fallback(); }, save() { saves++; return true; } });
  const file = await opened(f); const saving = f.client.saveAttachment(file);
  assert.equal(active(f).file.kind, 'loading'); const count = f.calls.length;
  f.client.closeReader(); const late = chunk(id, 0); pending.resolve(late); await saving;
  assert.equal(active(f).reader.kind, 'closed'); assert.equal(active(f).file.kind, 'idle');
  assert.equal(f.calls.length, count); assert.equal(saves, 0); assert.ok(late.every(n => n === 0)); f.client.dispose();
});

test('scope retirement and explicit cancellation clear a file held by a pending save and refuse late success', async () => {
  for (const retire of [false, true]) {
    const pending = deferred(), reached = deferred(); let held, signal;
    const f = contentFixture({ save(_name, _mime, data, abort) { held = data; signal = abort; reached.resolve(); return pending.promise; } });
    const file = await opened(f); const saving = f.client.saveAttachment(file); await reached.promise;
    assert.equal(held[65536], 43);
    if (retire) f.disposeScope(); else f.client.cancelAttachment();
    assert.equal(signal.aborted, true); assert.ok(held.every(n => n === 0)); pending.resolve(true); await saving;
    if (retire) assert.equal(f.client.getSnapshot().kind, 'closed'); else assert.equal(active(f).file.kind, 'idle');
    f.client.dispose();
  }
});

test('archive chunk refusal never saves partial bytes and unsafe archive metadata becomes a safe export name', async () => {
  let saves = 0;
  const bad = contentFixture({ intercept({ symbol, rest, fallback }) { if (symbol.endsWith('_page') && rest[32] === 4 && rest.at(-1) === 1) throw Error('backup_operation_refused'); return fallback(); }, save() { saves++; return true; } });
  await bad.client.saveAttachment(await opened(bad)); assert.equal(active(bad).file.kind, 'failed'); assert.equal(saves, 0); bad.client.dispose();
  for (const [name, mime, safeName] of [['../unsafe\nname', 'bad\nMIME', 'attachment.bin'], ['notes.bin', 'application/vnd.foo_bar', 'notes.bin']]) {
    const good = contentFixture({ name, mime, save(exportedName, exportedMime, data) { saves++; assert.equal(exportedName, safeName); assert.equal(exportedMime, 'application/octet-stream'); assert.equal(data.length, 65537); return false; } });
    const file = await opened(good); assert.equal(file.filename, name); assert.equal(file.mimeType, mime);
    await good.client.saveAttachment(file); assert.equal(active(good).file.kind, 'idle'); good.client.dispose();
  }
  assert.equal(saves, 2);
});


test('abort callbacks see cleared plaintext and may start a fresh file job without losing its state', async () => {
  const pending = deferred(), reached = deferred(); let calls = 0, clearedAtAbort = false, replacement;
  const f = contentFixture({ save(_name, _mime, data, signal) {
    calls++; if (calls > 1) return false;
    signal.addEventListener('abort', () => { clearedAtAbort = data.every(n => n === 0); replacement = f.client.saveAttachment(file); void replacement.catch(() => {}); }, { once: true });
    reached.resolve(); return pending.promise;
  } });
  const file = await opened(f), first = f.client.saveAttachment(file); await reached.promise;
  f.client.cancelAttachment(); const replacementState = active(f).file.kind;
  pending.resolve(false); await first; await replacement;
  f.client.dispose(); assert.equal(clearedAtAbort, true); assert.equal(replacementState, 'loading'); assert.equal(calls, 2);
});

test('closing a reader retires its file controls before an abort callback can reuse them', async () => {
  const pending = deferred(), reached = deferred(); let replacement, failure, saves = 0;
  const f = contentFixture({ save(_name, _mime, _data, signal) {
    saves++; if (saves > 1) return false;
    signal.addEventListener('abort', () => { replacement = f.client.saveAttachment(file).catch(error => { failure = error.message; }); }, { once: true });
    reached.resolve(); return pending.promise;
  } });
  const file = await opened(f), first = f.client.saveAttachment(file); await reached.promise;
  const count = f.calls.length; f.client.closeReader(); const immediately = f.calls.length;
  pending.resolve(false); await first; await replacement;
  assert.equal(active(f).reader.kind, 'closed'); f.client.dispose();
  assert.equal(immediately, count); assert.equal(saves, 1); assert.equal(failure, 'stale_backup_attachment');
});
