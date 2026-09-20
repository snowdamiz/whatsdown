// Run after npm run web --prefix ../desktop. Only native IPC is replaced.
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const dist = new URL(process.env.MORSE_PROFILE_DIST || '../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}`;
const screenshots = process.env.MORSE_PROFILE_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });

async function open({ scheme = 'dark', account = true, creator = true, width = 1160, contact = false } = {}) {
  const page = await browser.newPage({ viewport: { width, height: 800 }, colorScheme: scheme, reducedMotion: 'reduce' });
  page.on('pageerror', (error) => { throw error; });
  await page.addInitScript(({ scheme, account, creator, contact }) => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const decode = (b) => new TextDecoder().decode(new Uint8Array(b));
    const id = (n, length = 32) => Array(length).fill(n);
    const hex = (b) => b.map((v) => v.toString(16).padStart(2, '0')).join('');
    const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const fields = (bytes) => { const out = []; let i = 0; while (i < bytes.length) { const n = new DataView(new Uint8Array(bytes.slice(i, i + 4)).buffer).getUint32(0); i += 4; out.push(bytes.slice(i, i + n)); i += n; } return out; };
    const self = creator ? 1 : 3;
    const profile = vectors(text(creator ? 'alice' : 'maya'), id(self), id(self, 16), []);
    const state = window.profileTest = { account, creates: 0, saved: {}, calls: [], groups: [{ id: id(80), count: 3 }] };
    state.saved[`group/${hex(id(80))}`] = vectors(text('Weekend walks'), []);
    for (const [n, name] of [[1, 'alice'], [2, 'alex'], [3, 'maya']]) state.saved[`user/${hex(id(n))}`] = vectors(text(name), []);
    state.saved[`user/${hex(id(2))}`] = vectors(text('Alex Chen'), []);
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return scheme;
      if (command === 'binary_request' && options?.headers?.['X-Service-Url']?.endsWith('/v1/devices/resolve')) return [0, 200, 1];
      const symbol = options?.headers?.['X-Mesh-Symbol'] || args?.symbol;
      const request = args instanceof Uint8Array ? Array.from(args) : args?.request;
      state.calls.push(symbol || command);
      if (symbol === 'mesh_messenger_load_profile') { if (!state.account) throw Error('profile_not_found'); return profile; }
      if (symbol === 'mesh_messenger_create_account') { state.account = true; return profile; }
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request' || symbol === 'mesh_messenger_verify_transparency') return [1];
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text(creator ? 'alice' : 'maya'), id(self), u64(1), [0], [1], list(vectors(id(self, 16), [1], [1])));
      if (symbol === 'mesh_messenger_list_conversations') return contact ? list(vectors(id(20, 16), text('alex_1987'), id(2), id(2, 16), text('1234'.repeat(16)), [1], [0], [0], [0], u32(0))) : list();
      if (symbol === 'mesh_messenger_load_history' || symbol === 'mesh_messenger_group_invitations' || symbol === 'mesh_messenger_outbox_list' || symbol === 'mesh_messenger_outbox_page') return list();
      if (symbol === 'mesh_messenger_group_list') return list(...state.groups.map((g) => list([1], g.id, u64(1), u32(g.count))));
      if (symbol === 'mesh_messenger_group_create') { state.creates++; const g = { id: id(80 + state.creates), count: 1 }; state.groups.push(g); return g.id; }
      if (symbol === 'mesh_messenger_presentation_load') return state.saved[decode(fields(request)[1])] || [];
      if (symbol === 'mesh_messenger_presentation_save') { const [, key, data] = fields(request); state.saved[decode(key)] = data.length === 1 && data[0] === 0 ? [] : data; return state.saved[decode(key)]; }
      if (symbol === 'mesh_messenger_group_send') return list();
      if (symbol === 'mesh_messenger_group_inspect') {
        const group = state.groups.find((g) => hex(g.id) === hex(fields(request)[1]));
        return list([1], group.id, u64(1), u32(creator ? 0 : 2), id(4), id(5), list(...Array.from({ length: group.count }, (_, leaf) => list([1], u32(leaf), [leaf + 1 === self ? 1 : 0], id(leaf + 1), id(leaf + 1, 16), u64(1), [2], text(['alice', contact ? 'alex_1987' : 'alex', 'maya'][leaf] || 'member')))));
      }
      if (symbol === 'mesh_messenger_group_history') return list(...[
        [2, 'Sunday works for me.'], [3, 'I’ll bring coffee.'], [1, 'See you both there!'],
      ].map(([sender, body], i) => list([1], [2], u64(1), id(sender), id(sender, 16), u64(Date.now() - (3 - i) * 60_000), text(body), [])));
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
      throw Error('Offline test boundary');
    } };
  }, { scheme, account, creator, contact });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}


try {
  for (const scheme of ['dark', 'light']) {
    const page = await open({ scheme, width: 720 });
    const handle = page.getByRole('separator', { name: 'Resize sidebar', exact: true });
    await handle.waitFor({ state: 'visible', timeout: 10_000 });
    const sidebarStyle = () => page.getByRole('button', { name: 'Settings', exact: true }).evaluate((button) => {
      let panel = button.parentElement;
      while (!panel.querySelector('[role="tab"]')) panel = panel.parentElement;
      const material = Array.from(panel.children).find((child) => {
        const css = getComputedStyle(child);
        return css.position === 'absolute' && child.getBoundingClientRect().height === panel.getBoundingClientRect().height;
      });
      const rect = panel.getBoundingClientRect();
      const css = material && getComputedStyle(material);
      return { left: rect.x, top: rect.y, bottom: innerHeight - rect.bottom,
        backdrop: css?.backdropFilter, background: css?.backgroundColor, radius: css?.borderRadius,
        width: document.documentElement.scrollWidth };
    });
    const glass = await sidebarStyle();
    assert.match(glass.backdrop || '', /blur/);
    assert.match(glass.background || '', /^rgba/);
    assert.equal(glass.radius, '16px');
    assert.deepEqual([glass.left, glass.top, glass.bottom], [12, 12, 12]);
    assert.ok(glass.width <= 720);
    if (screenshots) await page.screenshot({ path: screenshots + '/glass-' + scheme + '.png' });
    await page.getByRole('tab', { name: /^Groups\b/ }).click();
    await page.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
    await page.getByText('Alex Chen', { exact: true }).waitFor();
    await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
    if (screenshots) await page.screenshot({ path: screenshots + '/group-glass-' + scheme + '.png' });
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-transparency', value: 'reduce' }] });
    await page.waitForFunction(() => matchMedia('(prefers-reduced-transparency: reduce)').matches);
    await page.waitForFunction(() => {
      let panel = document.querySelector('[aria-label="Settings"]').parentElement;
      while (!panel.querySelector('[role="tab"]')) panel = panel.parentElement;
      return Array.from(panel.children).some((child) => getComputedStyle(child).position === 'absolute' && child.getBoundingClientRect().height === panel.getBoundingClientRect().height && getComputedStyle(child).backdropFilter === 'none');
    }, null, { timeout: 10000 });
    const solid = await sidebarStyle();
    assert.equal(solid.backdrop, 'none');
    assert.equal(solid.background, scheme === 'dark' ? 'rgb(21, 21, 26)' : 'rgb(245, 245, 247)');
    assert.deepEqual([solid.left, solid.top, solid.bottom], [12, 12, 12]);
    if (screenshots) await page.screenshot({ path: screenshots + '/reduced-transparency-' + scheme + '.png' });

    await page.setViewportSize({ width: 1160, height: 800 });
    const expectWidth = async (width) => {
      await page.waitForFunction((width) => {
        const handle = document.querySelector('[role="separator"][aria-label="Resize sidebar"]');
        return document.getElementById(handle.getAttribute('aria-controls')).getBoundingClientRect().width === width;
      }, width);
      assert.equal(Number(await handle.getAttribute('aria-valuenow')), width);
    };
    const dragTo = async (width) => {
      const box = await handle.boundingBox();
      const currentWidth = Number(await handle.getAttribute('aria-valuenow'));
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width / 2 + width - currentWidth, box.y + box.height / 2, { steps: 8 });
      await page.mouse.up();
    };
    await expectWidth(325);
    const paint = () => handle.evaluate((element) => {
      const css = getComputedStyle(element);
      return [css.backgroundColor, css.borderWidth, css.boxShadow];
    });
    const beforeHover = await paint();
    await handle.hover();
    assert.deepEqual(await paint(), beforeHover, 'Hover changes no paint');
    assert.deepEqual(beforeHover, ['rgba(0, 0, 0, 0)', '0px', 'none']);
    assert.equal(await handle.evaluate((element) => getComputedStyle(element).cursor), 'col-resize');
    await dragTo(420);
    await expectWidth(420);
    await dragTo(900);
    await expectWidth(480);
    await dragTo(100);
    await expectWidth(280);
    await page.mouse.move(600, 400);
    await expectWidth(280); // Releasing the pointer ends resizing.
    await handle.focus();
    await page.keyboard.press('ArrowRight');
    await expectWidth(290);
    await page.keyboard.press('ArrowLeft');
    await expectWidth(280);
    await page.keyboard.press('End');
    await expectWidth(480);
    await page.getByRole('tab', { name: /^Chats\b/ }).click();
    await expectWidth(480);
    if (screenshots) await page.screenshot({ path: screenshots + '/resized-' + scheme + '.png' });
    await page.setViewportSize({ width: 720, height: 800 });
    await expectWidth(296);
    assert.equal(Number(await handle.getAttribute('aria-valuemax')), 296);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.setViewportSize({ width: 1160, height: 800 });
    await expectWidth(480);
    await handle.press('Home');
    await expectWidth(280);
    await page.setViewportSize({ width: 390, height: 800 });
    await handle.waitFor({ state: 'detached' });
    console.log('Sidebar verified: ' + scheme + ', translucent glass, 12px inset, usable groups, opaque accessibility fallback');
    console.log('Sidebar resize verified: drag, min/max, keyboard, navigation, viewport clamping and cursor-only hover');
    await page.close();
  }
} finally { await browser.close(); server.close(); }
