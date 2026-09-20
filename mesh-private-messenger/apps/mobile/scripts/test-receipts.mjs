// Run after npm run web --prefix ../desktop. Only native IPC/network I/O is replaced.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const dist = new URL(process.env.MORSE_TEST_DIST ?? '../../desktop/dist/', import.meta.url);
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
  page.setDefaultTimeout(20_000);
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const decode = (b) => new TextDecoder().decode(new Uint8Array(b));
    const id = (n, length = 32) => Array(length).fill(n);
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
    const receipt = (state, through) => `MORSE-RECEIPT/1\n${JSON.stringify([state, through])}`;
    // An envelope expires 30 days after the message it carries was stamped.
    const envelope = (queuedAt) => [1, ...text('MSG'), ...id(0, 16), ...id(0), 0, 1, ...u64(queuedAt + 2_592_000_000), ...u32(512), ...u32(0)];
    // Message IDs stay unique across a restart, as real ones do; the edge is only down at first.
    const restarted = sessionStorage.getItem('receipt-serial') !== null;
    const state = window.receiptTest = { now, focused: true, channel: null, stuck: !restarted, calls: [],
      serial: Number(sessionStorage.getItem('receipt-serial') ?? 20),
      outbox: [envelope(now - 20_000)],
      direct: [
        { id: 1, direction: 1, body: 'Read one', time: now - 50_000 },
        { id: 2, direction: 1, body: 'Delivered one', time: now - 40_000 },
        { id: 3, direction: 2, body: receipt(2, now - 50_000), time: now - 39_000 },
        { id: 4, direction: 2, body: receipt(1, now - 40_000), time: now - 38_000 },
        { id: 5, direction: 1, body: 'Sent one', time: now - 30_000 },
        { id: 6, direction: 1, body: 'Queued one', time: now - 20_000 },
        { id: 7, direction: 2, body: 'Hello from bob', time: now - 10_000 },
      ] };
    // Simulate OS focus independently of headless Chromium's window manager.
    document.hasFocus = () => state.focused;
    state.focus = (focused) => { state.focused = focused; window.dispatchEvent(new Event(focused ? 'focus' : 'blur')); };
    state.arrive = (body) => {
      const time = Date.now();
      state.direct.push({ id: ++state.serial, direction: 2, body, time });
      sessionStorage.setItem('receipt-serial', String(state.serial));
      state.channel.onmessage('encrypted-wakeup');
      return time;
    };
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: 'main' } },
      transformCallback: () => 1,
      unregisterCallback: () => {},
      invoke: async (command, args, options) => {
        if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
        if (command === 'database_path') return '/test/receipts.db';
        if (command === 'appearance') return 'dark';
        if (command === 'mailbox_connect') { state.channel = args.events; args.events.onmessage('ready'); return; }
        if (command === 'mailbox_disconnect') return;
        if (command === 'binary_request') return [0, 200, 0, 0, 0, 0, 0];
        const symbol = options?.headers?.['X-Mesh-Symbol'];
        const request = args instanceof Uint8Array ? [...args] : [];
        if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
        if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(20, 16), text('bob'), id(2), id(2, 16), text('1234'.repeat(16)), [1], [0], [0], [0], u32(0)));
        if (symbol === 'mesh_messenger_load_history') return list(...state.direct.map((m) => vectors([m.direction], id(m.id, 16), u64(m.time), text(m.body), u32(0), [],
          // A message is waiting while the envelope queued with it has not left.
          [m.direction === 1 && state.outbox.length > 0 && m.time >= now - 20_000 ? 1 : 0])));
        if (symbol === 'mesh_messenger_outbox_list' || symbol === 'mesh_messenger_outbox_page') return list(...state.outbox.slice(request.at(-1)));
        if (symbol === 'mesh_messenger_privacy_submission') { if (state.stuck) throw Error('Could not connect'); return [1]; }
        if (symbol === 'mesh_messenger_outbox_ack') { state.outbox.shift(); return []; }
        if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
        if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request' || symbol === 'mesh_messenger_verify_transparency') return fields(request)[1];
        if (symbol === 'mesh_messenger_inspect_device_set') {
          const peer = decode(fields(request)[1]) === 'bob';
          return vectors(text(peer ? 'bob' : 'alice'), id(peer ? 2 : 1), u64(1), [0], [1], list());
        }
        if (symbol === 'mesh_messenger_send_fanout') {
          const body = decode(fields(request)[3]);
          state.calls.push({ body, fields: fields(request).length });
          state.direct.push({ id: ++state.serial, direction: 1, body, time: Date.now() });
          sessionStorage.setItem('receipt-serial', String(state.serial));
          return list();
        }
        if (['mesh_messenger_group_list', 'mesh_messenger_group_invitations'].includes(symbol)) return list();
        if (['mesh_messenger_presentation_load', 'mesh_messenger_directory_entry', 'mesh_messenger_register_request', 'mesh_messenger_replenish_prekeys',
          'mesh_messenger_mailbox_fetch', 'mesh_messenger_process_delivery_batch', 'mesh_messenger_prepare_fanout_prekeys'].includes(symbol)) return [];
        // The sealed journals, kept where a reload leaves them alone, as the database would.
        if (symbol === 'mesh_messenger_journal_load' || symbol === 'mesh_messenger_journal_save') {
          const bytes = Array.from(args), parts = [];
          for (let at = 0; at < bytes.length;) {
            const size = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
            parts.push(new Uint8Array(bytes.slice(at + 4, at + 4 + size)));
            at += 4 + size;
          }
          const label = `sealed-journal/${new TextDecoder().decode(parts[1])}`;
          if (symbol.endsWith('_load')) return [...new TextEncoder().encode(localStorage.getItem(label) ?? '')];
          if (parts[2].length === 1 && parts[2][0] === 0) localStorage.removeItem(label);
          else localStorage.setItem(label, new TextDecoder().decode(parts[2]));
          return [];
        }
        throw Error(`Unexpected IPC: ${symbol || command}`);
      },
    };
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const receipts = () => page.evaluate(() => window.receiptTest.calls.filter((call) => call.body.startsWith('MORSE-RECEIPT/1\n'))
    .map((call) => JSON.parse(call.body.slice(16))));
  const sentReceipt = (state, through) => page.waitForFunction(([state, through]) => window.receiptTest.calls
    .some((call) => call.body === `MORSE-RECEIPT/1\n${JSON.stringify([state, through])}`), [state, through]);
  const status = (body, label) => page.getByLabel(`Sent message: ${body}`, { exact: true }).getByRole('img', { name: label, exact: true });
  const anyStatus = /^(Sending|Sent|Delivered|Read)$/;
  const openChat = async () => {
    await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
    await page.getByRole('button', { name: /^Conversation with @bob(?:,|$)/ }).press('Enter');
    await page.getByText('Hello from bob', { exact: true }).last().waitFor();
  };

  await page.goto(url);
  const now = await page.evaluate(() => window.receiptTest.now);
  await page.getByRole('button', { name: 'Conversation with @bob, 1 unread message', exact: true }).waitFor();
  assert.deepEqual(await receipts(), [], 'An unopened chat is not read, and old history is not acknowledged');
  await openChat();

  // Every state a sent bubble can take, and none on a received one.
  for (const [body, label] of [['Read one', 'Read'], ['Delivered one', 'Delivered'], ['Sent one', 'Sent'], ['Queued one', 'Sending']]) {
    await status(body, label).waitFor();
    assert.equal(await page.getByLabel(`Sent message: ${body}`, { exact: true }).getByRole('img', { name: anyStatus }).count(), 1, `${body} shows one state`);
  }
  assert.equal(await page.getByLabel('Received message: Hello from bob', { exact: true }).getByRole('img', { name: anyStatus }).count(), 0);
  assert.equal(await page.getByText(/MORSE-RECEIPT/).count(), 0, 'Receipts never become bubbles or previews');
  if (process.env.MORSE_RECEIPT_SCREENSHOT) await page.screenshot({ path: process.env.MORSE_RECEIPT_SCREENSHOT });

  // Reading the chat tells the other side once, for everything on screen.
  await sentReceipt(2, now - 10_000);
  assert.deepEqual(await receipts(), [[2, now - 10_000]]);

  // The queue drains in order, so the waiting message is sent once the head leaves.
  await page.evaluate(() => { window.receiptTest.stuck = false; });
  await status('Queued one', 'Sent').waitFor();

  // An open chat answers with "read" alone; it also says delivered.
  const open = await page.evaluate(() => window.receiptTest.arrive('While you watch'));
  await sentReceipt(2, open);
  assert.ok(!(await receipts()).some(([state, through]) => state === 1 && through === open), 'No separate delivery receipt for an open chat');

  // Behind an unfocused window the message is delivered, and read only once seen.
  await page.evaluate(() => window.receiptTest.focus(false));
  const away = await page.evaluate(() => window.receiptTest.arrive('While you are away'));
  await sentReceipt(1, away);
  assert.ok(!(await receipts()).some(([state, through]) => state === 2 && through === away), 'An unseen message is not read');
  await page.evaluate(() => window.receiptTest.focus(true));
  await sentReceipt(2, away);
  for (const call of await page.evaluate(() => window.receiptTest.calls)) {
    assert.equal(call.fields, 4, 'Receipts must not send composer attachments');
  }

  // Turning read receipts off stops them, hides the other side's, and survives a restart.
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  const toggle = page.getByRole('switch', { name: 'Read receipts', exact: true });
  assert.equal(await toggle.getAttribute('aria-checked'), 'true');
  await toggle.click();
  await page.reload();
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  assert.equal(await toggle.getAttribute('aria-checked'), 'false');
  if (process.env.MORSE_RECEIPT_SCREENSHOT) await page.screenshot({ path: process.env.MORSE_RECEIPT_SCREENSHOT.replace(/\.png$/, '-settings.png') });
  await openChat();
  await status('Read one', 'Delivered').waitFor();
  const quiet = await page.evaluate(() => window.receiptTest.arrive('Are you there?'));
  await sentReceipt(1, quiet);
  await page.getByText('Are you there?', { exact: true }).last().waitFor();
  assert.ok((await receipts()).every(([state]) => state === 1), 'No read receipt leaves while they are off');

  assert.deepEqual(errors, []);
  console.log('Receipts: sending/sent/delivered/read ticks, hidden control records, queue draining, one read receipt per view, delivery behind an unfocused window, and the read-receipt opt-out passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
