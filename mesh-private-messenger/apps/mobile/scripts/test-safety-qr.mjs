// The real React app and QR codec; native authority is separately exercised by
// mobile-core/tests/safety_qr.test.mpl. This fixture replaces platform I/O only.
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
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const text = value => [...new TextEncoder().encode(value)];
    const decode = value => new TextDecoder().decode(new Uint8Array(value));
    const id = (n, size = 32) => Array(size).fill(n);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const fields = bytes => { const out = []; let at = 0; while (at < bytes.length) { const size = new DataView(new Uint8Array(bytes.slice(at, at + 4)).buffer).getUint32(0); at += 4; out.push(bytes.slice(at, at + size)); at += size; } return out; };
    const state = window.safetyTest = { safety: '0123456789abcdef'.repeat(4), verified: false, requests: [], hold: false, release: null };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/safety.db';
      if (command === 'appearance') return 'dark';
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return id(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
      if (symbol === 'mesh_messenger_directory_resolve') return [1];
      if (symbol === 'mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
      if (symbol === 'mesh_messenger_transparency_fork') return [];
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(2, 16), text('alex'), id(2), id(2, 16), text(state.safety), [1], [0], [state.verified ? 1 : 0], [0], u32(0)));
      if (['mesh_messenger_group_invitations','mesh_messenger_outbox_list','mesh_messenger_outbox_page','mesh_messenger_group_list','mesh_messenger_load_history'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_presentation_load') return [];
      if (symbol === 'mesh_messenger_update_conversation') {
        const parts = fields(Array.from(args));
        const expected = decode(parts[4] ?? []);
        state.requests.push({ action: parts[2]?.[0], expected });
        if (parts.length !== 5 || parts[2][0] !== 6) throw Error('Unsafe verification frame');
        if (state.hold) await new Promise(resolve => { state.release = resolve; });
        if (expected !== state.safety) throw Error('safety_number_mismatch');
        state.verified = true;
        return text('ok');
      }
      if (['mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound'].includes(symbol)) {
        const parts = fields(Array.from(args)); const label = `sealed/${decode(parts[2])}`;
        if (symbol.includes('_load')) return text(localStorage.getItem(label) ?? '');
        if (parts[3].length === 1 && parts[3][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, decode(parts[3]));
        return [];
      }
      throw Error(`Offline safety fixture boundary: ${symbol ?? command}`);
    } };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('button', { name: /^Conversation with @?alex/ }).locator('..').click();
  await page.getByRole('button', { name: 'Conversation details', exact: true }).click();
  await page.getByText('Compare in person or through a channel you already trust. This code contains only your shared safety number.', { exact: true }).waitFor();
  const scan = async value => {
    await page.getByRole('textbox', { name: 'Safety code', exact: true }).fill(value);
    await page.getByRole('button', { name: 'Read code', exact: true }).click();
  };
  await page.getByRole('button', { name: 'Scan safety code', exact: true }).click();
  await scan('mesh://contact/v1/other');
  await page.getByText('This is not a safety number code. Open Conversation details on the other device.', { exact: true }).waitFor();
  assert.equal(await page.evaluate(() => window.safetyTest.requests.length), 0, 'Wrong QR kind never reaches native verification');
  await scan(`mesh://safety/v1/${'0'.repeat(64)}`);
  await page.getByText('These safety numbers do not match. Check that this is the right conversation and compare again.', { exact: true }).waitFor().catch(async error => { console.error(await page.locator('body').innerText()); console.error(await page.evaluate(() => ({requests:window.safetyTest.requests,verified:window.safetyTest.verified}))); throw error; });
  assert.equal(await page.evaluate(() => window.safetyTest.verified), false);
  const code = await page.evaluate(() => `mesh://safety/v1/${window.safetyTest.safety}`);
  await scan(code);
  await page.getByRole('button', { name: 'Scan safety code', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => window.safetyTest.verified), true);
  assert.deepEqual(await page.evaluate(() => window.safetyTest.requests.map(value => value.action)), [6, 6]);
  // Change native identity after the scan request is sent. A delayed response
  // cannot turn the stale displayed code into verification of the new key.
  await page.evaluate(() => { window.safetyTest.verified = false; window.safetyTest.hold = true; });
  await page.getByRole('button', { name: 'Scan safety code', exact: true }).click();
  await scan(code);
  await page.waitForFunction(() => window.safetyTest.release);
  await page.evaluate(() => { window.safetyTest.safety = 'f'.repeat(64); window.safetyTest.hold = false; window.safetyTest.release(); });
  await page.getByText('These safety numbers do not match. Check that this is the right conversation and compare again.', { exact: true }).waitFor().catch(async error => { console.error(await page.locator('body').innerText()); console.error(await page.evaluate(() => ({requests:window.safetyTest.requests,verified:window.safetyTest.verified}))); throw error; });
  assert.equal(await page.evaluate(() => window.safetyTest.verified), false);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('button', { name: 'Mark as verified', exact: true }).click();
  await page.waitForFunction(() => window.safetyTest.verified);
  assert.deepEqual(await page.evaluate(() => window.safetyTest.requests.at(-1)), { action: 6, expected: 'f'.repeat(64) }, 'Manual verification binds the exact displayed number too');
  // Canceling a pending scan keeps navigation closed after its result arrives.
  await page.evaluate(() => { window.safetyTest.hold = true; window.safetyTest.release = null; });
  await page.getByRole('button', { name: 'Scan safety code', exact: true }).click();
  await scan(`mesh://safety/v1/${'f'.repeat(64)}`);
  await page.waitForFunction(() => window.safetyTest.release);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.evaluate(() => { window.safetyTest.hold = false; window.safetyTest.release(); });
  await page.getByRole('textbox', { name: 'Safety code', exact: true }).waitFor({ state: 'detached' });
  await page.getByRole('button', { name: 'Scan safety code', exact: true }).waitFor();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.getByRole('textbox', { name: 'Safety code', exact: true }).count(), 0);
  assert.deepEqual(errors, []);
  console.log('Safety QR: real React display, strict QR kind, native mismatch, matched scan, delayed key change and manual exact-number request passed');
} finally { await browser?.close(); server.close(); }
