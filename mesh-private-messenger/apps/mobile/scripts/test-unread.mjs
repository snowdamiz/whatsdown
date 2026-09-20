// Run after npm run web --prefix ../desktop. Only the native IPC boundary is replaced.
// --windows checks the Windows default; --release checks a release export supplied by MORSE_TEST_DIST.
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
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
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
const screenshots = process.env.MORSE_UNREAD_SCREENSHOTS;
const windowsHost = process.argv.includes('--windows');
if (screenshots) await mkdir(screenshots, { recursive: true });

async function tabResizeFrames(tab, label, change) {
  const recording = tab.evaluate((tab, label) => new Promise((resolve, reject) => {
    const frames = [];
    const deadline = performance.now() + 5000;
    const sample = () => {
      const thumb = tab.parentElement.querySelector('[data-testid="segment-thumb"]');
      frames.push({ width: tab.getBoundingClientRect().width, thumb: thumb.getBoundingClientRect().width });
      if (tab.getAttribute('aria-label') === label && tab.getAnimations().length === 0) return resolve(frames);
      if (performance.now() > deadline) return reject(Error('Tab resize did not settle'));
      requestAnimationFrame(sample);
    };
    sample();
  }), label);
  await change();
  return recording;
}

try {
  for (const scheme of ['dark', 'light']) {
    const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, colorScheme: scheme, reducedMotion: 'reduce',
      userAgent: `Mozilla/5.0 (${windowsHost ? 'Windows NT 10.0; Win64; x64' : 'Macintosh; Intel Mac OS X 10_15_7'}) AppleWebKit/537.36` });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.addInitScript(({ scheme, windowsHost }) => {
      const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
      const u64 = (n) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(n)); return [...bytes]; };
      const text = (s) => [...new TextEncoder().encode(s)];
      const decode = (b) => new TextDecoder().decode(new Uint8Array(b));
      const id = (n, length = 32) => Array(length).fill(n);
      const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
      const list = (...fields) => vectors(u32(fields.length), ...fields);
      const fields = (bytes) => { const out = []; let i = 0; while (i < bytes.length) { const n = new DataView(new Uint8Array(bytes.slice(i, i + 4)).buffer).getUint32(0); i += 4; out.push(bytes.slice(i, i + n)); i += n; } return out; };
      const now = Date.now();
      const state = window.unreadTest = {
        focused: true, reloads: 0, channel: null,
        notifications: [],
        windowCalls: [], decorations: !windowsHost, maximized: false,
        messages: [{ id: 1, direction: 2, body: 'Coffee this weekend?', time: now - 120000 },
          { id: 2, direction: 2, body: 'There’s a new place by the park.', time: now - 60000 }],
        groups: [{ sender: 2, body: 'Sunday works for me.', time: now - 60000 },
          { sender: 1, body: 'Sent from my other device.', time: now }],
      };
      // Simulate OS focus independently of headless Chromium's window manager.
      document.hasFocus = () => state.focused;
      state.focus = (focused) => { state.focused = focused; window.dispatchEvent(new Event(focused ? 'focus' : 'blur')); };
      state.wake = () => state.channel.onmessage('encrypted-wakeup');
      const profile = vectors(text('alice'), id(1), id(1, 16), []);
      window.isTauri = true;
      Object.defineProperty(window.Notification, 'permission', { get: () => 'granted' });
      localStorage.setItem('/test/unread.db/notifications-enabled', 'true');
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } },
        transformCallback: () => 1,
        unregisterCallback: () => {},
        invoke: async (command, args, options) => {
          if (command === 'plugin:notification|is_permission_granted') return true;
          if (command === 'plugin:notification|notify') { state.notifications.push(args.options); return; }
          if (command.startsWith('plugin:window|')) {
            state.windowCalls.push(command);
            if (command === 'plugin:window|set_decorations') state.decorations = args.value;
            if (command === 'plugin:window|is_maximized') return state.maximized;
            if (command === 'plugin:window|toggle_maximize') {
              state.maximized = !state.maximized;
              window.dispatchEvent(new Event('resize'));
            }
            return;
          }
          if (command === 'database_path') return '/test/unread.db';
          if (command === 'appearance') return scheme;
          if (command === 'mailbox_connect') { state.channel = args.events; args.events.onmessage('ready'); return; }
          if (command === 'mailbox_disconnect') return;
          if (command === 'binary_request') return [0, 200, 0, 0, 0, 0, 0];
          const symbol = options?.headers?.['X-Mesh-Symbol'];
          if (symbol === 'mesh_messenger_load_profile') return profile;
          if (symbol === 'mesh_messenger_list_conversations') {
            state.reloads++;
            return list(...[[2, 'alex'], [3, 'maya'], [4, 'jordan']].map(([n, name]) =>
              vectors(id(n, 16), text(name), id(n), id(n, 16), text('1234567890'.repeat(6)), [1], [0], [0], [0], u32(0))));
          }
          if (symbol === 'mesh_messenger_load_history') {
            const peer = fields(Array.from(args))[1][0];
            const messages = peer === 2 ? state.messages : [{ id: peer, direction: 1, body: peer === 3 ? 'See you tomorrow.' : 'Thanks for the heads up!', time: now - peer * 60000 }];
            return list(...messages.map((m) => vectors([m.direction], id(m.id, 16), u64(m.time), text(m.body), u32(0), [])));
          }
          if (symbol === 'mesh_messenger_group_list') return list(list([1], id(80), u64(1), u32(2)));
          if (symbol === 'mesh_messenger_group_history') return list(...state.groups.map((m, index) =>
            list([1], [2], u64(1), id(m.sender), id(m.sender, 16), u64(m.time), text(m.body), [], id(index + 100))));
          if (symbol === 'mesh_messenger_group_inspect') return list([1], id(80), u64(1), u32(0), id(9), id(10),
            list(...[1, 2].map((n) => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n, 16), u64(1), [2], text(n === 1 ? 'alice' : 'alex')))));
          if (symbol === 'mesh_messenger_presentation_load') {
            const key = decode(fields(Array.from(args))[1]);
            return key.startsWith('group/') ? vectors(text('Weekend walks'), []) : [];
          }
          if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
          if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text('alice'), id(1), u64(1), [0], [1], vectors(u32(0)));
          if (['mesh_messenger_group_invitations', 'mesh_messenger_outbox_list', 'mesh_messenger_group_send'].includes(symbol)) return list();
          if (['mesh_messenger_directory_entry', 'mesh_messenger_replenish_prekeys', 'mesh_messenger_mailbox_fetch',
            'mesh_messenger_process_delivery_batch', 'mesh_messenger_transparency_lookup', 'mesh_messenger_verify_transparency'].includes(symbol)) return [];
          throw Error(`Unexpected IPC: ${symbol || command}`);
        },
      };
    }, { scheme, windowsHost });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    const chat = (unread) => page.getByRole('button', { name: new RegExp(`^Conversation with @?alex${unread ? `, ${unread} unread ${unread === 1 ? 'message' : 'messages'}` : ''}$`) });
    await chat(2).waitFor();
    await page.getByRole('button', { name: /^Conversation with @?maya$/ }).waitFor();
    await page.getByRole('tab', { name: 'Chats, 2 needing attention', exact: true }).waitFor();
    if (screenshots) await page.screenshot({ path: `${screenshots}/unread-${scheme}.png` });
    for (const title of ['Chats', 'Groups']) {
      const tab = page.getByRole('tab', { name: new RegExp(`^${title},`) });
      assert.equal(await tab.innerText(), '', `${title} shows no numeric counter`);
      const dot = await tab.getByTestId('segment-dot').boundingBox();
      const icon = await tab.locator('svg').boundingBox();
      assert.ok(dot.width > 0 && dot.width <= 10, `${title} has a small notification dot`);
      assert.ok(dot.x + dot.width < icon.x, `${title} dot sits left of the icon`);
      assert.equal(dot.y + dot.height / 2, icon.y + icon.height / 2, `${title} dot is vertically centered`);
    }
    const toolbar = await page.getByRole('tablist').locator('..').locator('..').boundingBox();
    const toolbarBottom = toolbar.y + toolbar.height;
    const firstChat = await chat(2).locator('..').boundingBox();
    assert.ok(firstChat.y >= toolbarBottom && firstChat.y <= toolbarBottom + 8, 'Chats start just below the toolbar');
    // ConversationRow's accessible overlay delegates pointer input to its row.
    const unreadTabWidth = (await page.getByTestId('segment-chats').boundingBox()).width;
    await chat(2).locator('..').click();
    await chat(0).waitFor();
    await page.getByRole('tab', { name: 'Chats', exact: true }).waitFor();
    const readTabWidth = (await page.getByTestId('segment-chats').boundingBox()).width;
    assert.ok(readTabWidth < unreadTabWidth, 'The tab contracts after its notifications are read');
    assert.equal(await page.getByTestId('segment-chats').getByTestId('segment-dot').evaluate((dot) => getComputedStyle(dot).opacity), '0');
    await page.reload();
    await chat(0).waitFor();
    await page.waitForFunction(() => window.unreadTest.channel !== null);
    await page.waitForFunction(() => localStorage.getItem(`/test/unread.db/notification-state/v1/${'01'.repeat(32)}`) !== null);
    assert.deepEqual(await page.evaluate(() => window.unreadTest.notifications), [], 'Restart must not replay old messages');
    // A late message with an older sender timestamp must still become unread.
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const expanding = await tabResizeFrames(page.getByTestId('segment-chats'), 'Chats, 1 needing attention', () =>
      page.evaluate(() => { window.unreadTest.messages.push({ id: 9, direction: 2, body: 'One more thing…', time: 1 }); window.unreadTest.wake(); }));
    await chat(1).waitFor();
    await page.waitForFunction(() => window.unreadTest.notifications.some((item) => item.body === 'One more thing…'));
    assert.equal((await page.getByTestId('segment-chats').boundingBox()).width, unreadTabWidth, 'New notifications expand the tab again');
    const contracting = await tabResizeFrames(page.getByTestId('segment-chats'), 'Chats', () => chat(1).locator('..').click());
    for (const frames of [expanding, contracting]) {
      assert.ok(frames.some(({ width }) => width > readTabWidth && width < unreadTabWidth), 'Tab width animates through intermediate sizes');
      assert.ok(frames.every(({ width, thumb }) => Math.abs(width - thumb) < 1), 'Selection highlight resizes with the tab');
    }
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await chat(0).waitFor();
    // Selected history may refresh in the background, but cannot be marked read.
    await page.evaluate(() => { window.unreadTest.focus(false); window.unreadTest.messages.push({ id: 10, direction: 2, body: 'While you were away.', time: Date.now() }); window.unreadTest.wake(); });
    await chat(1).waitFor();
    await page.evaluate(() => window.unreadTest.focus(true));
    await chat(0).waitFor();
    await page.getByRole('button', { name: 'Conversation details', exact: true }).click();
    await page.evaluate(() => { window.unreadTest.messages.push({ id: 11, direction: 2, body: 'In the details screen.', time: Date.now() }); window.unreadTest.wake(); });
    await chat(1).waitFor();
    await page.getByRole('tab', { name: /^Groups/ }).click();
    const firstGroup = await page.getByRole('button', { name: 'Weekend walks, 1 unread message', exact: true }).boundingBox();
    assert.ok(firstGroup.y >= toolbarBottom && firstGroup.y <= toolbarBottom + 8, 'Groups start just below the toolbar');
    await page.getByRole('button', { name: 'Weekend walks, 1 unread message', exact: true }).click();
    await page.getByRole('button', { name: 'Weekend walks', exact: true }).waitFor();
    await page.getByRole('tab', { name: 'Groups', exact: true }).waitFor();
    const groupComposer = page.getByRole('textbox', { name: 'Group message', exact: true });
    await groupComposer.fill('Hello @al');
    await page.getByRole('button', { name: /@alex/ }).waitFor();
    await groupComposer.press('ArrowDown');
    await groupComposer.press('Enter');
    assert.equal(await groupComposer.inputValue(), 'Hello @alex ');
    await groupComposer.fill('');
    const beforeVisible = await page.evaluate(() => window.unreadTest.notifications.length);
    await page.evaluate(() => { window.unreadTest.groups.push({ sender: 2, body: 'Hello @alice!', time: Date.now() }); window.unreadTest.wake(); });
    await page.getByText('Hello @alice!', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.unreadTest.notifications.length), beforeVisible, 'Open chat suppresses system alerts');
    assert.match(await page.getByText('@alice!', { exact: false }).last().innerHTML(), /text-decoration-line: underline/);
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.evaluate(() => { window.unreadTest.groups.push({ sender: 2, body: '@alice a new trail to try.', time: Date.now() + 1 }); window.unreadTest.wake(); });
    await page.getByRole('button', { name: 'Weekend walks, 1 unread message', exact: true }).waitFor();
    await page.waitForFunction(() => window.unreadTest.notifications.some((item) => item.body === '@alex mentioned you: @alice a new trail to try.'));
    const notifications = await page.evaluate(() => window.unreadTest.notifications);
    assert.equal(notifications.filter((item) => item.body.includes('mentioned you')).length, 1);
    const beforeRepeat = await page.evaluate(() => window.unreadTest.reloads);
    await page.evaluate(() => window.unreadTest.wake());
    await page.waitForFunction((before) => window.unreadTest.reloads > before, beforeRepeat);
    assert.deepEqual(await page.evaluate(() => window.unreadTest.notifications), notifications, 'Repeated wakeups must not repeat alerts');
    if (screenshots) await page.screenshot({ path: `${screenshots}/groups-unread-${scheme}.png` });
    const saved = await page.evaluate(() => localStorage.getItem(`/test/unread.db/read-state/v1/${'01'.repeat(32)}`));
    assert.ok(saved);
    assert.equal(saved.includes('Coffee'), false, 'Read metadata must never persist message text');
    if (process.argv.includes('--notifications')) {
      await page.getByRole('button', { name: 'Notifications', exact: true }).click();
      await page.getByRole('button', { name: 'Turn off notifications', exact: true }).click();
      await page.getByRole('button', { name: 'Enable notifications', exact: true }).waitFor();
      const beforeDisabled = await page.evaluate(() => window.unreadTest.reloads);
      await page.evaluate(() => { window.unreadTest.groups.push({ sender: 2, body: '@alice notifications are off', time: Date.now() }); window.unreadTest.wake(); });
      await page.waitForFunction((before) => window.unreadTest.reloads > before, beforeDisabled);
      assert.deepEqual(await page.evaluate(() => window.unreadTest.notifications), notifications, 'Disabled notifications stay silent');
      assert.deepEqual(errors, []);
      console.log(`Notifications: ${scheme} ordinary/mention alerts, autocomplete, highlighting, active chat suppression, duplicate/restart suppression and opt-out passed`);
      await page.close();
      continue;
    }
    // Exercise the actual injectable sample content and keep real read state untouched.
    const sample = page.getByRole('switch', { name: 'Sample content', exact: true });
    const windowsUI = page.getByRole('switch', { name: 'Windows UI', exact: true });
    assert.equal(await page.getByRole('button', { name: 'Close window', exact: true }).count(), Number(windowsHost),
      'Only Windows uses custom controls by default');
    if (process.argv.includes('--release')) {
      assert.equal(await sample.count(), 0, 'Sample content must be absent in releases');
      assert.equal(await windowsUI.count(), 0, 'Windows UI preview must be absent in releases');
      await page.close();
      console.log(`Release: ${scheme} development toggles are hidden`);
      continue;
    }
    const tabs = page.getByRole('tab', { name: /^Chats/ });
    const hostTabs = await tabs.boundingBox();
    assert.equal(await windowsUI.count(), 1, 'Desktop development settings offer Windows UI');
    assert.equal(await windowsUI.isChecked(), false);
    await windowsUI.click();
    assert.equal(await windowsUI.isChecked(), true);
    const windowsTabs = await tabs.boundingBox();
    if (windowsHost) assert.deepEqual(windowsTabs, hostTabs, 'Windows preview matches the native Windows layout');
    else {
      assert.ok(windowsTabs.x < hostTabs.x, 'Windows layout removes the Mac window-button inset');
      assert.equal(windowsTabs.y, hostTabs.y, 'Windows controls share the existing toolbar without adding a title strip');
    }
    const caption = await page.getByRole('group', { name: 'Window controls', exact: true }).boundingBox();
    assert.equal(caption.y + caption.height / 2, windowsTabs.y + windowsTabs.height / 2, 'Compact controls are centered in the existing toolbar');
    assert.equal(caption.x + caption.width, 1144, 'Windows controls share the toolbar’s right inset');
    assert.equal(await page.evaluate(() => window.unreadTest.decorations), false, 'The preview hides native traffic lights');
    await page.getByRole('button', { name: 'Minimize window', exact: true }).click();
    await page.getByRole('button', { name: 'Maximize window', exact: true }).click();
    await page.getByRole('button', { name: 'Restore window', exact: true }).click();
    // Resizing through the OS also updates the maximize/restore button.
    await page.evaluate(() => { window.unreadTest.maximized = true; window.dispatchEvent(new Event('resize')); });
    await page.getByRole('button', { name: 'Restore window', exact: true }).press('Space');
    await page.getByRole('button', { name: 'Maximize window', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Close window', exact: true }).click();
    assert.ok(await page.evaluate(() => ['minimize', 'toggle_maximize', 'close'].every((action) =>
      window.unreadTest.windowCalls.includes(`plugin:window|${action}`))), 'Custom controls invoke native window actions');
    assert.equal(await sample.isChecked(), false, 'Windows preview is independent of sample content');
    if (screenshots) await page.screenshot({ path: `${screenshots}/windows-settings-${scheme}.png` });
    const sampleChat = (unread) => page.getByRole('button', { name: `Conversation with Alex Walker${unread ? `, ${unread} unread messages` : ''}`, exact: true });
    await sample.click();
    await page.getByRole('tab', { name: /^Chats/ }).click();
    await sampleChat(2).waitFor();
    await page.getByRole('button', { name: 'Conversation with Maya Chen', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Conversation with Jordan, 1 unread message', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Conversation with Riley, 12 unread messages', exact: true }).waitFor();
    if (screenshots) await page.screenshot({ path: `${screenshots}/sample-chats-${scheme}.png` });
    await sampleChat(2).locator('..').click();
    await sampleChat(0).waitFor();
    await page.setViewportSize({ width: 720, height: 560 });
    await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
    const details = await page.getByRole('button', { name: 'Conversation details', exact: true }).boundingBox();
    const narrowControls = await page.getByRole('group', { name: 'Window controls', exact: true }).boundingBox();
    assert.equal(details.y + details.height / 2, narrowControls.y + narrowControls.height / 2,
      'Window controls and conversation actions share the same vertical center');
    assert.ok(details.x + details.width <= narrowControls.x, 'Conversation actions stay clear of caption buttons at minimum width');
    if (screenshots) await page.screenshot({ path: `${screenshots}/windows-chat-narrow-${scheme}.png` });
    await page.setViewportSize({ width: 1160, height: 800 });
    await page.getByRole('tab', { name: /^Groups/ }).click();
    const sampleGroup = page.getByRole('button', { name: 'Weekend walks, 3 unread messages', exact: true });
    await sampleGroup.waitFor();
    await page.getByRole('button', { name: 'The dinner club', exact: true }).waitFor();
    if (screenshots) await page.screenshot({ path: `${screenshots}/sample-groups-${scheme}.png` });
    await sampleGroup.click();
    await page.getByRole('button', { name: 'Weekend walks', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    assert.equal(await windowsUI.isChecked(), true, 'Windows preview survives navigation and sample changes');
    await windowsUI.click();
    assert.deepEqual(await tabs.boundingBox(), hostTabs, 'Turning off Windows UI restores the host layout');
    assert.equal(await page.evaluate(() => window.unreadTest.decorations), !windowsHost);
    if (!windowsHost) assert.ok(await page.evaluate(() => window.unreadTest.windowCalls.includes('plugin:window|set_title_bar_style')),
      'Restoring Mac decorations also restores the overlay titlebar');
    assert.equal(await page.getByRole('button', { name: 'Close window', exact: true }).count(), Number(windowsHost));
    assert.equal(await sample.isChecked(), true);
    await sample.click();
    assert.equal(await page.evaluate(() => localStorage.getItem(`/test/unread.db/read-state/v1/${'01'.repeat(32)}`)), saved);
    await sample.click();
    await page.getByRole('tab', { name: /^Chats/ }).click();
    await sampleChat(2).waitFor();
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await windowsUI.click();
    await page.reload();
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    assert.equal(await windowsUI.isChecked(), false, 'Windows preview resets on reload');
    const resetTabs = await tabs.boundingBox();
    assert.equal(resetTabs.x, hostTabs.x, 'Reload restores the host toolbar position');
    assert.equal(resetTabs.y, hostTabs.y);
    assert.deepEqual(errors, []);
    console.log(`Unread: ${scheme} counts, opening, restart, background arrivals, sample content, isolation, Windows UI and preview reset passed`);
    await page.close();
  }
} finally { await browser.close(); server.close(); }
