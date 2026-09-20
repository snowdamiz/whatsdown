// Run after npm run web --prefix ../desktop (or point MORSE_WEB_DIST at another web export).
// Only native IPC/network I/O is replaced.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const dist = process.env.MORSE_WEB_DIST
  ? pathToFileURL(`${process.env.MORSE_WEB_DIST}/`)
  : new URL('../../desktop/dist/', import.meta.url);
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
    const direct = (body, serial, direction = 1) => vectors([direction], id(serial, 16), u64(Date.now()), text(body), u32(0), []);
    const group = (body, serial, sender = 1) => list([1], [sender === 1 ? 1 : 2], u64(1), id(sender), id(sender, 16), u64(Date.now()), text(body), [], id(serial));
    const saved = JSON.parse(sessionStorage.getItem('reactions-test') || 'null');
    const policy = new URLSearchParams(location.search);
    const state = window.reactionTest = { failed: false, blocked: policy.has('blocked'), pending: policy.has('pending'), calls: [],
      direct: saved?.direct ?? [direct('Hello chat', 10, 2)],
      group: saved?.group ?? [group('Hello group', 11, 2), group('MORSE-REACTION/1\n' + JSON.stringify(['0b'.repeat(32), '👍', 1]), 12, 2)],
    };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/reactions.db';
      if (command === 'appearance') return 'dark';
      if (command === 'binary_request') return new Uint8Array([0, 200, ...args]).buffer;
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      const request = args instanceof Uint8Array ? [...args] : [];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(20, 16), text('bob'), id(2), id(2, 16), text('1234'.repeat(16)), [state.pending ? 0 : 1], [state.blocked ? 1 : 0], [0], [0], u32(0)));
      if (symbol === 'mesh_messenger_load_history') return list(...state.direct);
      if (symbol === 'mesh_messenger_group_history') return list(...state.group);
      if (symbol === 'mesh_messenger_group_list') return list(list([1], id(80), u64(1), u32(2)));
      if (symbol === 'mesh_messenger_group_inspect') return list([1], id(80), u64(1), u32(0), id(4), id(5), list(...[1, 2].map((n) => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n, 16), u64(1), [2]))));
      if (symbol === 'mesh_messenger_presentation_load') {
        const key = decode(fields(request)[1]);
        return key.startsWith('group/') ? vectors(text('Reaction group'), []) : [];
      }
      if (['mesh_messenger_group_invitations', 'mesh_messenger_outbox_list'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_transparency_lookup') return fields(request)[1];
      if (symbol === 'mesh_messenger_verify_transparency') return fields(request)[1];
      if (symbol === 'mesh_messenger_inspect_device_set') {
        const peer = decode(fields(request)[1]) === 'bob';
        return vectors(text(peer ? 'bob' : 'alice'), id(peer ? 2 : 1), u64(1), [0], [1], list());
      }
      if (symbol === 'mesh_messenger_prepare_fanout_prekeys') return [];
      if (['mesh_messenger_send_fanout', 'mesh_messenger_group_send'].includes(symbol)) {
        const isGroup = symbol === 'mesh_messenger_group_send';
        const body = decode(fields(request)[isGroup ? 2 : 3]);
        if (!body) return list(); // group presentation announcement
        if (state.failed) throw Error('Reaction send failed');
        state.calls.push({ isGroup, body, fields: fields(request).length });
        const messages = isGroup ? state.group : state.direct;
        messages.push(isGroup ? group(body, messages.length + 30) : direct(body, messages.length + 30));
        sessionStorage.setItem('reactions-test', JSON.stringify({ direct: state.direct, group: state.group }));
        return list();
      }
      throw Error('Offline test boundary');
    } };
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  await page.goto(url);
  const openChat = async () => {
    await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
    await page.getByRole('button', { name: /^Conversation with @bob(?:,|$)/ }).press('Enter');
    await page.getByText('Hello chat', { exact: true }).last().waitFor();
  };
  const menu = page.getByRole('dialog', { name: 'Message actions', exact: true });
  const composer = (group = false) => page.getByPlaceholder(group ? 'Message · @mention someone' : 'Message', { exact: true });
  // The desktop controls appear beside a bubble while the pointer rests on it.
  const hoverControl = async (text, name) => {
    await page.getByText(text, { exact: true }).last().hover();
    return page.getByLabel(new RegExp(`message: ${text}$`)).getByRole('button', { name, exact: true });
  };
  const choose = async (text, label) => {
    await (await hoverControl(text, 'React')).click();
    await menu.getByRole('button', { name: label, exact: true }).click();
    await menu.waitFor({ state: 'hidden' });
  };
  const pill = (description) => page.getByRole('button', { name: description, exact: true });
  await openChat();
  await composer().fill('Keep this draft');
  await choose('Hello chat', 'Heart');
  await pill('1 reaction: Heart').waitFor();
  assert.equal(await composer().inputValue(), 'Keep this draft');
  await choose('Hello chat', 'Laugh');
  await pill('1 reaction: Laugh').waitFor();
  assert.equal(await pill('1 reaction: Heart').count(), 0);
  await page.reload();
  await openChat();
  await pill('1 reaction: Laugh').waitFor();
  // A right click opens the same menu; your own emoji is marked, and choosing it again removes it.
  await page.getByText('Hello chat', { exact: true }).last().click({ button: 'right' });
  assert.equal(await menu.getByRole('button', { name: 'Laugh', exact: true }).getAttribute('aria-pressed'), 'true');
  await menu.getByRole('button', { name: 'Laugh', exact: true }).click();
  await pill('1 reaction: Laugh').waitFor({ state: 'hidden' });
  await page.evaluate(() => { window.reactionTest.failed = true; });
  await choose('Hello chat', 'Heart');
  await page.getByText('Reaction send failed', { exact: true }).waitFor();
  assert.equal(await pill('1 reaction: Heart').count(), 0);
  await page.evaluate(() => { window.reactionTest.failed = false; });
  // Escape closes the menu without choosing.
  await (await hoverControl('Hello chat', 'React')).click();
  await menu.getByRole('button', { name: 'Thumbs up', exact: true }).focus();
  await page.keyboard.press('Escape');
  await menu.waitFor({ state: 'hidden' });
  // A reply quotes the message it answers above the field; Escape there takes the quote back.
  const cancelReply = page.getByRole('button', { name: 'Cancel reply', exact: true });
  await (await hoverControl('Hello chat', 'Reply')).click();
  await cancelReply.waitFor();
  await page.keyboard.press('Escape');
  await cancelReply.waitFor({ state: 'hidden' });
  await page.getByText('Hello chat', { exact: true }).last().click({ button: 'right' });
  await menu.getByRole('button', { name: 'Reply', exact: true }).click();
  await page.getByLabel(/^Replying to .+: Hello chat$/).waitFor();
  await composer().fill('Direct answer');
  await page.keyboard.press('Enter');
  await page.getByRole('button', { name: /^Replying to .+: Hello chat$/ }).waitFor();
  // Sent: the quote lives in the bubble now, and the field is free again.
  assert.equal(await cancelReply.count(), 0);
  await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
  await page.getByRole('button', { name: /^Reaction group(?:,|$)/ }).press('Enter');
  // The pill opens who reacted; the same emojis are offered there.
  await pill('1 reaction: Thumbs up').click();
  await page.getByRole('dialog', { name: 'Reactions', exact: true }).getByRole('button', { name: 'Thumbs up', exact: true }).click();
  await pill('2 reactions: Thumbs up 2').waitFor();
  if (process.env.MORSE_REACTION_SCREENSHOT) await page.screenshot({ path: process.env.MORSE_REACTION_SCREENSHOT });
  await choose('Hello group', 'Celebrate');
  await pill('2 reactions: Thumbs up 1, Celebrate 1').waitFor();
  await (await hoverControl('Hello group', 'Reply')).click();
  await composer(true).fill('Group answer');
  await page.keyboard.press('Enter');
  const quote = page.getByRole('button', { name: /^Replying to .+: Hello group$/ });
  await quote.waitFor();
  await quote.click();
  await page.setViewportSize({ width: 720, height: 800 });
  await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  const calls = await page.evaluate(() => window.reactionTest.calls);
  const reactions = calls.filter((call) => call.body.startsWith('MORSE-REACTION/1\n'));
  assert.ok(reactions.some((call) => call.isGroup) && reactions.some((call) => !call.isGroup));
  for (const call of calls) assert.equal(call.fields, call.isGroup ? 3 : 4, 'Reactions and replies must not send composer attachments');
  // The reply names its target by ID and carries none of the quoted words.
  assert.deepEqual(calls.filter((call) => !call.body.startsWith('MORSE-REACTION/1\n')).map((call) => call.body),
    [`MORSE-REPLY/1\n${'0a'.repeat(16)}\nDirect answer`, `MORSE-REPLY/1\n${'0b'.repeat(32)}\nGroup answer`]);
  await page.goto(`${url}?blocked`);
  await openChat();
  assert.equal(await (await hoverControl('Hello chat', 'React')).isDisabled(), true);
  assert.equal(await page.getByRole('button', { name: 'Reply', exact: true }).count(), 0, 'A blocked thread offers no reply');
  assert.deepEqual(errors, []);
  console.log('Reactions and replies: hover and right-click menus, add, replace, remove, counts, reload, draft preservation, errors, quotes in chats and groups, blocked contacts, keyboard dismissal and layout passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
