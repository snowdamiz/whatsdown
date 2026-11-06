// Run against a fresh desktop web export. Only platform/native I/O is replaced.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
const dist = new URL(process.env.MORSE_ATTACHMENT_DIST || '../../desktop/dist/', import.meta.url);
const png = [...await readFile(new URL('../assets/adaptive-icon.png', import.meta.url))];
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(png => {
    const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = n => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(n)); return [...bytes]; };
    const text = value => [...new TextEncoder().encode(value)];
    const decode = value => new TextDecoder().decode(new Uint8Array(value));
    const id = (n, size = 32) => Array(size).fill(n);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const fields = bytes => { const out = []; let at = 0; while (at < bytes.length) { const size = new DataView(new Uint8Array(bytes.slice(at, at + 4)).buffer).getUint32(0); at += 4; out.push(bytes.slice(at, at + size)); at += size; } return out; };
    const album = (...refs) => { const rows = refs.map(ref => list([ref], id(ref === 3 ? 1 : ref), id(9), text(`photo-${ref}.png`), text('image/png'), u32(png.length), u32(1), u32(65536), u64(Date.now() + 86400000))); return rows.length === 1 ? rows[0] : [1, 65, 84, 66, ...u32(rows.length), ...vectors(...rows)]; };
    const state = window.cleanupTest = { created: [], revoked: [], fetches: [], completed: [], pending: {}, saves: 0 };
    const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = blob => { const uri = create(blob); state.created.push(uri); return uri; };
    URL.revokeObjectURL = uri => { state.revoked.push(uri); revoke(uri); };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/cleanup.db';
      if (command === 'appearance') return 'dark';
      if (command === 'save_attachment') { state.saves++; return true; }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return id(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
      if (symbol === 'mesh_messenger_directory_resolve') return [1];
      if (symbol === 'mesh_messenger_transparency_fork') return [];
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(2, 16), text('alex'), id(2), id(2, 16), text('1234567890'.repeat(6)), [1], [0], [0], [0], u32(0)));
      if (['mesh_messenger_group_invitations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_group_list') return list(...[80,81].map(n => list([1], id(n), u64(1), u32(2))));
      if (symbol === 'mesh_messenger_presentation_load') {
        const key = decode(fields(Array.from(args))[1]);
        return key.startsWith('group/') ? vectors(text(key.includes('50'.repeat(32)) ? 'First files' : 'Other files'), []) : [];
      }
      if (symbol === 'mesh_messenger_group_policy') return list([1], fields(Array.from(args))[1], u32(0));
      if (symbol === 'mesh_messenger_group_inspect') return list([1], fields(Array.from(args))[1], u64(1), u32(0), id(4), id(5), list(...[1,2].map(n => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n,16), u64(1), [2]))));
      if (symbol === 'mesh_messenger_group_history') {
        const first = fields(Array.from(args))[1][0] === 80;
        return list(list([1], [2], u64(1), id(2), id(2,16), u64(Date.now()), text(first ? 'First group' : 'Other group'), first ? album(1,2) : album(3), id(first ? 100 : 101)));
      }
      if (symbol === 'mesh_messenger_load_history') return list(vectors([2], id(6,16), u64(Date.now()), text('Direct files'), u32(0), album(4,5), [0]));
      if (symbol === 'mesh_messenger_attachment_fetch_chunk') {
        const ref = fields(Array.from(args).slice(4))[1][0]; // counted request: database, reference, index
        state.fetches.push(ref);
        if ((ref === 2 || ref === 5) && state.fetches.filter(n => n === ref).length === 1) await new Promise(resolve => { state.pending[ref] = resolve; });
        state.completed.push(ref);
        return png;
      }
      if (['mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound'].includes(symbol)) {
        const parts = fields(Array.from(args)); const label = `sealed/${decode(parts[2])}`;
        if (symbol.includes('_load')) return text(localStorage.getItem(label) ?? '');
        if (parts[3].length === 1 && parts[3][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, decode(parts[3]));
        return [];
      }
      throw Error('Offline cleanup fixture boundary');
    } };
  }, png);
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  const active = () => page.evaluate(() => window.cleanupTest.created.filter(uri => !window.cleanupTest.revoked.includes(uri)));
  const openGroup = async name => { await page.getByRole('tab', { name: /^Groups/ }).click(); await page.getByRole('button', { name: new RegExp(`^${name}`) }).click(); };
  await openGroup('First files');
  await page.getByRole('button', { name: 'View photo-1.png', exact: true }).waitFor();
  await page.waitForFunction(() => window.cleanupTest.pending[2]);
  const first = await active(); assert.equal(first.length, 1);
  await page.getByRole('tab', { name: /^Groups/ }).click();
  assert.deepEqual(await active(), [], 'Leaving the first group must release its completed preview');
  await page.getByRole('button', { name: /^Other files/ }).click();
  await page.getByRole('button', { name: 'View photo-3.png', exact: true }).waitFor().catch(async error => { console.error(await page.locator('body').innerText()); console.error(await page.evaluate(() => ({fetches:window.cleanupTest.fetches,created:window.cleanupTest.created,revoked:window.cleanupTest.revoked}))); console.error(errors); throw error; });
  assert.equal((await active()).length, 1, 'Closing one group must revoke its preview without erasing the newly open group');
  assert.ok(!(await active()).includes(first[0]), 'Closed group preview must be revoked');
  const other = await active();
  await page.evaluate(() => window.cleanupTest.pending[2]());
  await page.waitForFunction(() => window.cleanupTest.completed.includes(2));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.deepEqual(await active(), other, 'Late group download must not recreate a closed preview or erase an unrelated one');
  await openGroup('First files');
  await page.getByRole('button', { name: 'View photo-2.png', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => window.cleanupTest.fetches.filter(n => n === 1).length), 2, 'Reopening must refetch bytes discarded on close');
  assert.equal(await page.evaluate(() => window.cleanupTest.fetches.filter(n => n === 2).length), 2, 'A previous late completion must not rescue a new session');
  await page.getByRole('tab', { name: /^Chats/ }).click();
  await page.getByRole('button', { name: /^Conversation with @?alex/ }).locator('..').click();
  await page.getByRole('button', { name: 'View photo-4.png', exact: true }).waitFor();
  await page.waitForFunction(() => window.cleanupTest.pending[5]);
  const direct = await active(); assert.equal(direct.length, 1);
  await openGroup('Other files');
  await page.getByRole('button', { name: 'View photo-3.png', exact: true }).waitFor().catch(async error => { console.error(await page.locator('body').innerText()); console.error(await page.evaluate(() => ({fetches:window.cleanupTest.fetches,created:window.cleanupTest.created,revoked:window.cleanupTest.revoked}))); console.error(errors); throw error; });
  assert.ok(!(await active()).includes(direct[0]), 'Direct conversation closure must revoke its preview');
  await page.getByRole('tab', {name:/^Chats/}).click();
  await page.getByRole('button', {name:/^Conversation with @?alex/}).locator('..').click();
  await page.getByRole('button', {name:'View photo-5.png',exact:true}).waitFor();
  const reopened = await active(); assert.equal(reopened.length, 2);
  assert.equal(await page.evaluate(() => window.cleanupTest.fetches.filter(n => n === 5).length), 2);
  await page.evaluate(() => window.cleanupTest.pending[5]());
  await page.waitForFunction(() => window.cleanupTest.completed.filter(n => n === 5).length === 2);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.deepEqual(await active(), reopened, 'Old completion must not overwrite or release the reopened direct session');
  await openGroup('Other files');
  await page.getByRole('button', {name:'View photo-3.png',exact:true}).waitFor();
  // Selected unsent files keep their composer, but their generated previews do not
  // survive closure. Reopening recreates them without selecting the file again.
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Attach files (0 of 10)', exact: true }).click();
  await (await chooser).setFiles([{name:'draft.png', mimeType:'image/png', buffer:Buffer.from(png)}]);
  await page.getByRole('button', {name:'Remove draft.png',exact:true}).waitFor();
  assert.equal((await active()).length, 2);
  await page.getByRole('tab', { name: /^Chats/ }).click();
  assert.deepEqual(await active(), [], 'Leaving a thread must release all its object URLs');
  await openGroup('Other files');
  await page.getByRole('button', {name:'Remove draft.png',exact:true}).waitFor();
  await page.getByRole('button', {name:'View photo-3.png',exact:true}).waitFor();
  assert.equal((await active()).length, 2, 'Reopened composer restores only its selected draft and new received preview');
  await page.getByRole('button', {name:'Remove draft.png',exact:true}).click();
  assert.equal((await active()).length, 1);
  await page.getByRole('tab', { name: /^Chats/ }).click();
  assert.deepEqual(await active(), []);
  assert.equal(await page.evaluate(() => window.cleanupTest.saves), 0, 'Cleanup must not implicitly save files');
  assert.deepEqual(errors, []);
  console.log('Attachment cleanup: actual direct/group navigation, scoped same-ID previews, close/reopen refetch, and late native completions passed');
} finally { await browser?.close(); server.close(); }
