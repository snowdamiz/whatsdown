// Real React download flow and parser; replace only native/platform I/O.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
const dist = new URL('../../desktop/dist/', import.meta.url);
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
  const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(10000);
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    const text = value => [...new TextEncoder().encode(value)];
    const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
    const u64 = value => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(value)); return [...b]; };
    const id = (value, length = 32) => Array(length).fill(value);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const packet = (...fields) => [...u32(fields.length), ...vectors(...fields)];
    const fields = bytes => {
      const data = new Uint8Array(bytes), view = new DataView(data.buffer); let at = 4; const result = [];
      while (at < data.length) { const size = view.getUint32(at); at += 4; result.push(data.slice(at, at + size)); at += size; }
      return result;
    };
    const size = 16_777_217, count = 257;
    const state = window.paidDownloadTest = { version: 2, planSize: size, plans: 0, begins: [], saves: [], writes: [], fetched: [], aborts: 0 };
    const summary = () => list([2], id(7), id(4), text('large.bin'), text('application/octet-stream'), u32(size), u32(count), u32(65536), u64(Date.now() + 86400000));
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = { metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback() {}, invoke: async (command, args, options) => {
      if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
      if (command === 'database_path') return '/test/paid-downloads.db';
      if (command === 'appearance') return 'dark';
      if (command === 'mailbox_connect' || command === 'mailbox_disconnect') return;
      if (command === 'begin_attachment_save') { state.begins.push(new DataView(new Uint8Array(args).buffer).getUint32(0)); state.writes = []; state.fetched = []; return 1; }
      if (command === 'write_attachment_range') { state.writes.push({ offset: Number(options.headers['X-Attachment-Offset']), length: args.length }); return; }
      if (command === 'finish_attachment_save') { if (state.writes.reduce((n, row) => n + row.length, 0) !== size) throw Error('incomplete sink'); state.saves.push(state.version); return; }
      if (command === 'abort_attachment_save') { state.aborts++; return; }
      if (command === 'binary_request') throw Error('JavaScript attachment HTTP is forbidden');
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_attachment_download_plan') { state.plans++; return packet(text('\u0001ADP'), [state.version], text('https://edge.example'), text(`/v2/objects/${'07'.repeat(32)}/parts/`), [2], id(7), id(4), text('large.bin'), text('application/octet-stream'), u32(state.planSize), u32(count)); }
      if (symbol === 'mesh_messenger_attachment_fetch_chunk') {
        const f = fields(args), index = new DataView(f[2].buffer).getUint32(0);
        if (f.length !== 3 || f[1].length !== 1 || f[1][0] !== 2 || index >= count) throw Error('invalid native download input');
        state.fetched.push(index); return new Uint8Array(Math.min(65536, size - index * 65536));
      }
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return id(1);
      if (symbol === 'mesh_messenger_directory_resolve') return [1];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1,16), []);
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
      if (symbol === 'mesh_messenger_group_list') return list(list([1],id(80),u64(1),u32(2)));
      if (symbol === 'mesh_messenger_group_inspect') return list([1],id(80),u64(1),u32(0),id(4),id(5),list());
      if (symbol === 'mesh_messenger_group_history') return list(list([1],[1],u64(1),id(1),id(1,16),u64(Date.now()),text('Download proof'),summary()));
      if (symbol === 'mesh_messenger_presentation_load') return vectors(text('Test files'), []);
      if (['mesh_messenger_list_conversations','mesh_messenger_group_invitations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (['mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound','mesh_messenger_transparency_fork','mesh_messenger_mailbox_stream_poll','mesh_messenger_mailbox_stream_close'].includes(symbol)) return [];
      throw Error(`Offline paid download fixture: ${symbol ?? command}`);
    } };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('tab', { name: /^Groups/ }).click();
  await page.getByRole('button', { name: /^Test files/ }).click();
  const download = page.getByRole('button', { name: /^large.bin/ }).first();
  for (const version of [2, 4]) {
    await page.evaluate(version => { window.paidDownloadTest.version = version; }, version);
    await download.click();
    await page.waitForFunction(version => window.paidDownloadTest.saves.includes(version), version).catch(async error => {
      console.error('Download did not complete', { version, state: await page.evaluate(() => {
        const { plans, begins, saves, aborts } = window.paidDownloadTest;
        return { plans, begins, saves, aborts };
      }) });
      throw error;
    });
    assert.deepEqual(await page.evaluate(() => window.paidDownloadTest.fetched), Array.from({ length: 257 }, (_, i) => i));
    assert.deepEqual(await page.evaluate(() => window.paidDownloadTest.writes.at(-1)), { offset: 16_777_216, length: 1 });
  }
  assert.deepEqual(await page.evaluate(() => window.paidDownloadTest.begins), [16_777_217, 16_777_217]);
  for (const invalid of [{ version: 4, planSize: 16_777_218 }, { version: 3, planSize: 16_777_217 }]) {
    const before = await page.evaluate(() => window.paidDownloadTest.plans);
    await page.evaluate(value => Object.assign(window.paidDownloadTest, value), invalid);
    await download.click();
    await page.waitForFunction(before => window.paidDownloadTest.plans > before, before);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.deepEqual(await page.evaluate(() => window.paidDownloadTest.begins), [16_777_217, 16_777_217], 'Invalid version or same-bucket size mismatch must not open a destination');
  }
  assert.equal(await page.evaluate(() => window.paidDownloadTest.aborts), 0);
  assert.deepEqual(errors, []);
  console.log('Paid downloads: real React accepts legacy2 and padded4, saves exact original ranges, and rejects unknown versions and same-bucket size mismatches before opening a destination.');
} finally { await browser?.close(); server.close(); }
