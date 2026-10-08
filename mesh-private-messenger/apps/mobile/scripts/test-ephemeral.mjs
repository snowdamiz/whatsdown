// Disappearing and view-once messages and safety codes, on the desktop web export.
// Run after npm run web --prefix ../desktop (or point MORSE_WEB_DIST at another web
// export). Only native IPC/network I/O is replaced; MORSE_EPHEMERAL_SHOTS=<dir>
// saves screenshots.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const dist = process.env.MORSE_WEB_DIST
  ? pathToFileURL(`${process.env.MORSE_WEB_DIST}/`)
  : new URL('../../desktop/dist/', import.meta.url);
const shots = process.env.MORSE_EPHEMERAL_SHOTS;
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(10_000);
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const decode = (b) => new TextDecoder().decode(new Uint8Array(b));
    const id = (n, length = 32) => Array(length).fill(n);
    const hex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    const vectors = (...values) => values.flatMap((v) => [...u32(v.length), ...v]);
    const list = (...values) => vectors(u32(values.length), ...values);
    const fields = (bytes) => {
      const out = []; let i = 0;
      while (i < bytes.length) {
        const n = new DataView(new Uint8Array(bytes.slice(i, i + 4)).buffer).getUint32(0);
        i += 4; out.push(bytes.slice(i, i + n)); i += n;
      }
      return out;
    };
    const now = Date.now();
    // Direct summaries end with the kind: 0 a message, 1 view-once unopened, 2 view-once gone.
    const direct = (body, serial, direction, kind, seconds = 0) =>
      vectors([direction], id(serial, 16), u64(now - 60_000 + serial), text(body), u32(seconds), [], [0], [kind]);
    // Group summaries end with the expiry and the kind (3: a timer notice).
    const group = (body, serial, sender, kind, expires = 0) => list([1], [sender === 1 ? 1 : 2], u64(1), id(sender), id(sender, 16),
      u64(now - 60_000 + serial), text(body), [], id(serial), [0], u64(expires), [kind]);
    const safety = '1234'.repeat(16);
    const state = window.ephemeralTest = {
      verified: false, calls: [], viewOnce: { direct: 'unopened', group: 'unopened' }, timer: 3600,
    };
    const directHistory = () => [
      direct('Hello Alice', 1, 2, 0),
      direct('', 2, 2, state.viewOnce.direct === 'unopened' ? 1 : 2),
      direct('', 3, 1, 2),
      ...state.calls.filter((call) => call.symbol === 'mesh_messenger_send_view_once').map((_, index) => direct('', 20 + index, 1, 2)),
    ];
    const groupHistory = () => [
      group('3600', 4, 2, 3),
      group('Short-lived hello', 5, 2, 0, now + 3_600_000),
      group('', 6, 2, state.viewOnce.group === 'unopened' ? 1 : 2),
    ];
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/ephemeral.db';
      if (command === 'appearance') return 'light';
      if (command === 'binary_request') return new Uint8Array([0, 200, ...args]).buffer;
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      const request = args instanceof Uint8Array ? [...args] : [];
      const parts = fields(request);
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(20, 16), text('bob'), id(2), id(2, 16), text(safety), [1], [0], [state.verified ? 1 : 0], [0], u32(0), u64(0)));
      if (symbol === 'mesh_messenger_load_history') return list(...directHistory());
      if (symbol === 'mesh_messenger_group_history') return list(...groupHistory());
      if (symbol === 'mesh_messenger_group_list') return list(list([1], id(80), u64(1), u32(2)));
      if (symbol === 'mesh_messenger_group_inspect') return list([1], id(80), u64(1), u32(0), id(4), id(5), list(...[1, 2].map((n) => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n, 16), u64(1), [2]))));
      if (symbol === 'mesh_messenger_presentation_load') {
        const key = decode(parts[1]);
        if (key.startsWith('group/')) return vectors(text('Weekend walks'), []);
        if (key === `user/${hex(id(2))}`) return vectors(text('Bob'), []);
        return [];
      }
      if (['mesh_messenger_group_invitations', 'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_expiry_purge') return list(u64(0));
      if (symbol === 'mesh_messenger_group_timer_state') return u32(state.timer);
      if (symbol === 'mesh_messenger_open_view_once') {
        if (state.viewOnce.direct !== 'unopened') throw Error('view_once_unavailable');
        state.viewOnce.direct = 'gone';
        return vectors([2], id(2, 16), u64(now), text('Secret words'), u32(0), [], [0], [1]);
      }
      if (symbol === 'mesh_messenger_group_open_view_once') {
        state.viewOnce.group = 'gone';
        return list([1], [2], u64(1), id(2), id(2, 16), u64(now), text('Group secret'), [], id(6), [0], u64(0), [1]);
      }
      if (symbol === 'mesh_messenger_safety_code') return text(`morse-verify:1:${hex(id(1))}:${hex(id(2))}:${safety}`);
      if (symbol === 'mesh_messenger_safety_code_check') {
        const code = decode(parts[2]);
        const outcome = code === `morse-verify:1:${hex(id(2))}:${hex(id(1))}:${safety}` ? 'verified'
          : code.startsWith('morse-verify:1:') ? 'mismatch' : 'invalid';
        state.verified = outcome === 'verified';
        return text(outcome);
      }
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request') return parts[1];
      if (symbol === 'mesh_messenger_verify_transparency') return parts[1];
      if (symbol === 'mesh_messenger_inspect_device_set') {
        const peer = decode(parts[1]) === 'bob';
        return vectors(text(peer ? 'bob' : 'alice'), id(peer ? 2 : 1), u64(1), [0], [1], list());
      }
      if (symbol === 'mesh_messenger_prepare_fanout_prekeys') return [];
      // Bob's devices ask no postage for a message request.
      if (symbol === 'mesh_messenger_credits_postage_quote') return [0];
      if (['mesh_messenger_send_view_once', 'mesh_messenger_group_timer', 'mesh_messenger_group_send', 'mesh_messenger_send_fanout'].includes(symbol)) {
        state.calls.push({ symbol, parts: parts.map(decode) });
        if (symbol === 'mesh_messenger_group_timer') state.timer = new DataView(new Uint8Array(parts[2]).buffer).getUint32(0);
        return list();
      }
      // The app lock's owner check (src-tauri/src/owner.rs); a reload keeps its answer.
      if (command === 'lock_available') return true;
      if (command === 'lock_authenticate') {
        state.asked = (state.asked ?? 0) + 1;
        return localStorage.getItem('ephemeral-unlock') === 'yes';
      }
      if (symbol === 'mesh_messenger_journal_load') {
        return decode(parts[1]) === 'settings/app-lock' ? text(localStorage.getItem('ephemeral-lock') ?? '') : [];
      }
      if (symbol === 'mesh_messenger_journal_save') return [];
      throw Error('Offline test boundary');
    } };
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('button', { name: /^Conversation with / }).first().press('Enter');
  await page.getByText('Hello Alice', { exact: true }).last().waitFor();
  // A view-once message shows what a tap does, never what it says.
  const unopened = page.getByRole('button', { name: 'View once · Tap to open', exact: true });
  await unopened.waitFor();
  assert.equal(await page.getByText('Secret words').count(), 0, 'An unopened view-once message showed its content');
  await page.getByText('View once message', { exact: true }).first().waitFor();
  if (shots) await page.screenshot({ path: `${shots}/chat.png` });
  await unopened.click();
  const viewer = page.getByRole('dialog', { name: 'View once message', exact: true });
  await viewer.getByText('Secret words', { exact: true }).waitFor();
  await viewer.getByText(/can’t stop a screenshot/).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/view-once-open.png` });
  await viewer.getByRole('button', { name: 'Done', exact: true }).click();
  await viewer.waitFor({ state: 'hidden' });
  await page.getByText('Opened', { exact: true }).waitFor();
  assert.equal(await page.getByText('Secret words').count(), 0, 'The opened content stayed on screen');
  // The composer sends the next message view-once, then turns itself off.
  await page.getByRole('button', { name: 'View once: off', exact: true }).click();
  await page.getByRole('button', { name: 'View once: on', exact: true }).waitFor();
  await page.getByPlaceholder('Message', { exact: true }).fill('Just once');
  await page.keyboard.press('Enter');
  await page.getByRole('button', { name: 'View once: off', exact: true }).waitFor();
  const sent = await page.evaluate(() => window.ephemeralTest.calls);
  assert.equal(sent.at(-1).symbol, 'mesh_messenger_send_view_once');
  assert.equal(sent.at(-1).parts[3], 'Just once');
  // Verify with a code: this device's QR, and a pasted code checked by the core.
  await page.getByRole('button', { name: 'Conversation details', exact: true }).first().click();
  await page.getByRole('button', { name: /^Verify with a code/ }).click();
  const verify = page.getByRole('dialog', { name: 'Verify with a code', exact: true });
  await verify.getByText('Your code for this chat', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/safety-code.png` });
  await verify.getByRole('button', { name: 'Paste their code', exact: true }).click();
  await verify.getByLabel('Their code').fill(`morse-verify:1:${'02'.repeat(32)}:${'01'.repeat(32)}:${'4321'.repeat(16)}`);
  await verify.getByRole('button', { name: 'Check code', exact: true }).click();
  await verify.getByText(/The codes don’t match/).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/safety-mismatch.png` });
  await verify.getByRole('button', { name: 'Paste their code', exact: true }).click();
  await verify.getByLabel('Their code').fill(`morse-verify:1:${'02'.repeat(32)}:${'01'.repeat(32)}:${'1234'.repeat(16)}`);
  await verify.getByRole('button', { name: 'Check code', exact: true }).click();
  await verify.getByText(/The codes match/).waitFor();
  await verify.getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByText('Safety number verified').first().waitFor();
  // A group: the timer notice, its setting in details, and a view-once message.
  await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
  await page.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
  await page.getByText('Bob set disappearing messages to 1 hour.', { exact: true }).waitFor();
  const groupUnopened = page.getByRole('button', { name: 'View once · Tap to open', exact: true });
  await groupUnopened.click();
  await viewer.getByText('Group secret', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/group-view-once-open.png` });
  await viewer.getByRole('button', { name: 'Done', exact: true }).click();
  await viewer.waitFor({ state: 'hidden' });
  await page.getByText('Opened', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/group.png` });
  await page.getByRole('button', { name: 'Group details', exact: true }).first().click();
  const day = page.getByRole('radio', { name: 'Disappear: 1 day', exact: true });
  await page.getByRole('radio', { name: 'Disappear: 1 hour', exact: true }).waitFor();
  assert.equal(await page.getByRole('radio', { name: 'Disappear: 1 hour', exact: true }).getAttribute('aria-checked'), 'true');
  if (shots) await page.screenshot({ path: `${shots}/group-details.png` });
  await day.click();
  await page.waitForFunction(() => window.ephemeralTest.calls.some((call) => call.symbol === 'mesh_messenger_group_timer'));
  await page.waitForFunction(() => document.querySelector('[aria-label="Disappear: 1 day"]')?.getAttribute('aria-checked') === 'true');
  // App lock: with the lock on, nothing of the app shows until the owner check passes.
  await page.evaluate(() => { localStorage.setItem('ephemeral-lock', '{"minutes":0}'); localStorage.setItem('ephemeral-unlock', 'no'); });
  await page.reload();
  const lockTitle = page.getByRole('heading', { name: 'Morse is locked', exact: true });
  await lockTitle.waitFor();
  await page.waitForFunction(() => (window.ephemeralTest.asked ?? 0) >= 1);
  assert.equal(await page.getByText('Weekend walks').count(), 0, 'The locked app showed a chat list');
  if (shots) await page.screenshot({ path: `${shots}/locked.png` });
  await page.evaluate(() => localStorage.setItem('ephemeral-unlock', 'yes'));
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await lockTitle.waitFor({ state: 'detached' });
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('button', { name: /^Conversation with / }).first().waitFor();
  await page.evaluate(() => { localStorage.removeItem('ephemeral-lock'); localStorage.removeItem('ephemeral-unlock'); });
  await page.setViewportSize({ width: 720, height: 800 });
  await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  assert.deepEqual(errors, []);
  console.log('Ephemeral: view-once bubbles hide content, open once and read as opened; the composer sends view-once; safety codes show a QR and report mismatches and matches; group timer notices and the group timer setting; the app lock holds the app back until the owner check passes; layout passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
