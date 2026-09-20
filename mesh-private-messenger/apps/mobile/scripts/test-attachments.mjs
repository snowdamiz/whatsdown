// Run after npm run web --prefix ../desktop. Exercise the real app with native I/O replaced.
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
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(30000);
  const errors = [];
  page.on('pageerror', (error) => { errors.push(error.message); console.error(error.message); });
  await page.addInitScript((png) => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(n)); return [...bytes]; };
    const text = (value) => [...new TextEncoder().encode(value)];
    const id = (value, size = 32) => Array(size).fill(value);
    const vectors = (...fields) => fields.flatMap((field) => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const summary = (index) => list([index + 1], id(index + 1), id(9),
      text(index === 8 ? 'report.pdf' : index === 9 ? 'data.custom' : `photo-${index}.png`),
      text(index === 8 ? 'application/pdf' : index === 9 ? 'application/octet-stream' : 'image/png'),
      u32(png.length), u32(1), u32(65536), u64(Date.now() + 86400000));
    const album = [1, 65, 84, 66, ...u32(10), ...vectors(...Array.from({ length: 10 }, (_, index) => summary(index)))];
    const state = window.attachmentTest = { saves: [], png };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/attachments.db';
      if (command === 'appearance') return 'dark';
      if (command === 'binary_request') return new Uint8Array([0, 200, 1]).buffer;
      if (command === 'save_attachment') { state.saves.push({ bytes: [...args], name: decodeURIComponent(options.headers['X-File-Name']) }); return true; }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (['mesh_messenger_list_conversations', 'mesh_messenger_group_invitations', 'mesh_messenger_outbox_list'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_group_list') return list(list([1], id(80), u64(1), u32(2)));
      if (symbol === 'mesh_messenger_presentation_load') return vectors(text('Test files'), []);
      if (symbol === 'mesh_messenger_group_inspect') return list([1], id(80), u64(1), u32(0), id(4), id(5),
        list(...[1, 2].map((n) => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n, 16), u64(1), [2]))));
      if (symbol === 'mesh_messenger_group_history') return list(list([1], [2], u64(1), id(2), id(2, 16), u64(1800000000000), text('Ten files together'), album));
      if (symbol === 'mesh_messenger_attachment_open_chunk') return png;
      throw Error('Offline test boundary');
    } };
  }, png);
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('tab', { name: /^Groups/ }).click();
  await page.getByRole('button', { name: /^Test files/ }).click();
  const image = page.getByRole('button', { name: 'View photo-0.png', exact: true });
  await image.waitFor();
  await image.click();
  const viewer = page.getByRole('dialog', { name: 'photo-0.png', exact: true });
  await viewer.waitFor();
  await viewer.evaluate((element) => Promise.all(document.getAnimations()
    .filter((animation) => animation.effect?.target?.contains(element))
    .map((animation) => animation.finished)));
  assert.ok((await viewer.boundingBox()).width > (await image.boundingBox()).width * 2);
  assert.equal(await page.evaluate(() => window.attachmentTest.saves.length), 0, 'Viewing must not save a file');
  const download = viewer.getByRole('button', { name: 'Download', exact: true });
  const closeBounds = await viewer.getByRole('button', { name: 'Close', exact: true }).boundingBox();
  const downloadBounds = await download.boundingBox();
  assert.equal(await download.innerText(), '');
  assert.ok(Math.abs(downloadBounds.y - closeBounds.y) < 2 && downloadBounds.x < closeBounds.x);
  await download.click();
  await page.waitForFunction(() => window.attachmentTest.saves.length === 1);
  if (process.env.MORSE_ATTACHMENT_SCREENSHOT) await page.screenshot({ path: process.env.MORSE_ATTACHMENT_SCREENSHOT });
  await page.keyboard.press('Escape');
  await viewer.waitFor({ state: 'hidden' });
  for (const name of ['report.pdf', 'data.custom']) {
    await page.getByRole('button', { name: new RegExp(`^${name.replace('.', '\\.')}`) }).click();
    await page.waitForFunction((name) => window.attachmentTest.saves.some((file) => file.name === name), name);
  }
  assert.deepEqual(await page.evaluate(() => window.attachmentTest.saves),
    ['photo-0.png', 'report.pdf', 'data.custom'].map((name) => ({ name, bytes: png })));

  const files = Array.from({ length: 10 }, (_, index) => ({ name: `${index}.custom`, mimeType: 'application/octet-stream', buffer: Buffer.from([index]) }));
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Attach files (0 of 10)', exact: true }).click();
  assert.equal((await chooser).isMultiple(), true);
  await (await chooser).setFiles(files);
  await page.getByRole('button', { name: 'Attach files (10 of 10)', exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: /^Remove \d+\.custom$/ }).count(), 10);
  assert.equal(await page.getByRole('button', { name: 'Attach files (10 of 10)', exact: true }).getAttribute('aria-disabled'), 'true');
  await page.getByRole('button', { name: 'Remove 0.custom', exact: true }).click();
  await page.getByRole('button', { name: 'Attach files (9 of 10)', exact: true }).waitFor();
  await page.evaluate(() => {
    const data = new DataTransfer();
    data.items.add(new File(['one'], 'extra.one'));
    data.items.add(new File(['two'], 'extra.two'));
    window.dispatchEvent(new DragEvent('drop', { dataTransfer: data, cancelable: true }));
  });
  await page.getByText('You can attach up to 10 files per message.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: /^Remove \d+\.custom$/ }).count(), 9);
  for (const width of [1160, 720]) {
    await page.setViewportSize({ width, height: 800 });
    await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  }
  assert.deepEqual(errors, []);
  console.log('Attachments: 10 arbitrary files, per-file removal, overflow rejection, image viewer, and exact-byte downloads passed');
} finally { await browser?.close(); server.close(); }
