// Run against the exported app. Native IPC is the fixture boundary; React,
// navigation, Settings and the persistent banner use the real bundle.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const forkFixture = JSON.parse(await readFile(new URL('../../../tests/fixtures/fork-v1/vectors.json', import.meta.url), 'utf8')).cases.find(value => value.name === 'same-size-service-only').wire_hex;
const forkBytes = [...Buffer.from(forkFixture, 'hex')];
const dist = new URL('../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const screenshots = process.env.MORSE_ANCHOR_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const cases = [1160, 390].flatMap(width => ['fork', 'observed', 'consistent', 'proof_unavailable', 'stale', 'mismatch', 'service_slashed']
    .map(status => ({ status, width, blockTime: '1792670360' })));
  cases.push(...['0', '1792670401'].map(blockTime => ({ status: 'observed', width: 390, blockTime })));
  for (const { status, width, blockTime } of cases) {
    const page = await browser.newPage({ viewport: { width, height: 800 }, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(({ status, forkBytes, blockTime }) => {
      window.anchorClockMs = 1792670400000;
      Date.now = () => window.anchorClockMs;
      let checked = false;
      const text = value => [...new TextEncoder().encode(value)];
      const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
      const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
      const list = (...fields) => vectors(u32(fields.length), ...fields);
      let release;
      const anchorReady = status === 'observed' ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
      window.anchorUITest = { release: () => release?.() };
      window.isTauri = true;
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback: () => {},
        invoke: async (command, args, options) => {
          if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
          if (command === 'database_path') return '/test/anchor.db';
          if (command === 'appearance') return 'dark';
          if (command === 'mailbox_connect') return;
          if (command === 'mailbox_disconnect') return;
          if (command === 'binary_request') throw Error('Offline fixture');
          const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
          if (symbol === 'mesh_messenger_directory_resolve') return [1];
          if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
          if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
          if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), Array(32).fill(1), Array(16).fill(1), []);
          if (symbol === 'mesh_messenger_signup_draft_state') return [0];
          if (symbol === 'mesh_messenger_anchor_check') { await anchorReady; checked = true; return list(...[status === 'fork' ? 'mismatch' : status, '9000000', '501', '500', blockTime].map(text)); }
          if (symbol === 'mesh_messenger_transparency_fork') return checked && status === 'fork' ? forkBytes : [];
          if (symbol === 'mesh_messenger_fork_filing') return list(...['disabled', '', '', '', '0', '', '0', '0', '0', '0', '0', '0'].map(text));
          if (['mesh_messenger_list_conversations', 'mesh_messenger_group_list', 'mesh_messenger_group_invitations',
            'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
          if (symbol === 'mesh_messenger_resolve_plan') return list(list(text('/v2/devices/resolve'), []));
          if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
          if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
          if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
          if (['mesh_messenger_presentation_load', 'mesh_messenger_journal_load', 'mesh_messenger_journal_save', 'mesh_messenger_journal_load_bound', 'mesh_messenger_journal_save_bound',
            'mesh_messenger_register_request', 'mesh_messenger_mailbox_fetch', 'mesh_messenger_directory_entry'].includes(symbol)) return [];
          throw Error(`Unexpected IPC: ${symbol || command}`);
        },
      };
    }, { status, forkBytes, blockTime });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    // RPC availability must not delay opening the app or navigating local data.
    try {
      const settings = width < 600 ? page.getByRole('tab', { name: 'You', exact: true }) : page.getByRole('button', { name: 'Settings', exact: true });
      await settings.click({ timeout: 5000 });
    } catch (cause) {
      throw new Error(`Anchor UI startup failed (${status}): ${JSON.stringify({ errors, body: await page.locator('body').innerText() })}`, { cause });
    }
    await page.evaluate(() => window.anchorUITest.release());
    if (status === 'fork') {
      await page.getByText('Your device found conflicting signed key logs. New chats and key changes are paused. Existing chats can continue.', { exact: true }).waitFor({ timeout: 1500 });
      await page.getByRole('button', { name: 'Details', exact: true }).click();
      const evidence = page.getByRole('dialog', { name: 'Key log evidence', exact: true });
      await evidence.getByRole('button', { name: 'Copy evidence', exact: true }).waitFor();
      await evidence.getByText(forkFixture, { exact: true }).waitFor();
      await page.waitForTimeout(500);
      if (screenshots) await page.screenshot({ path: `${screenshots}/fork-${width}.png`, fullPage: true });
      assert.deepEqual(errors, []);
      console.log(`Anchor UI: immediate fork evidence (${width}px)`);
      await page.close();
      continue;
    }
    const title = { observed: 'Public checkpoint observed', consistent: 'Public checkpoint verified', proof_unavailable: 'Checkpoint proof unavailable', stale: 'Public checkpoint is overdue', mismatch: 'Public checkpoint could not be verified', service_slashed: 'Morse’s key log was caught signing two versions' }[status];
    await page.getByText(title, { exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Public checkpoint', exact: true });
    await dialog.waitFor();
    if (blockTime !== '1792670360') {
      await dialog.getByText('Public checkpoint time is unavailable.', { exact: true }).waitFor();
      assert.equal(await dialog.getByText(/^Last public checkpoint:/).count(), 0);
      assert.deepEqual(errors, []);
      console.log(`Anchor UI: unavailable age (${blockTime}, ${width}px)`);
      await page.close();
      continue;
    }
    await dialog.getByText('Last public checkpoint: 40s ago', { exact: true }).waitFor({ timeout: 3000 });
    const ageBounds = await dialog.getByText('Last public checkpoint: 40s ago', { exact: true }).boundingBox();
    assert.ok(ageBounds && ageBounds.x >= 0 && ageBounds.x + ageBounds.width <= width, 'Checkpoint age fits the viewport');
    if (status === 'observed') {
      await page.evaluate(() => { window.anchorClockMs += 60000; });
      await dialog.getByText('Last public checkpoint: 1m 40s ago', { exact: true }).waitFor({ timeout: 3000 });
    }
    if (status === 'observed') await dialog.getByText(/Consistency with your device’s key log has not yet been verified/).waitFor();
    if (status === 'consistent') await dialog.getByText(/belong to the same growing tree/).waitFor();
    if (status === 'proof_unavailable') await dialog.getByText(/could not retrieve the checkpoint proof/).waitFor();
    if (status === 'stale') await dialog.getByText(/over two hours old/).waitFor();
    if (['mismatch', 'service_slashed'].includes(status)) {
      await dialog.getByText(/New chats and key changes are paused/).waitFor();
      // The persistent warning remains on the page when the details close.
      await dialog.getByRole('button', { name: 'Close', exact: true }).click();
      await dialog.waitFor({ state: 'hidden' });
      await page.getByText(`${title}. New chats and key changes are paused. Existing chats can continue.`, { exact: true }).waitFor();
      const height = await page.getByText(`${title}. New chats and key changes are paused. Existing chats can continue.`, { exact: true }).evaluate(element => {
        for (let parent = element.parentElement; parent; parent = parent.parentElement) {
          if ([...parent.querySelectorAll('[role="button"], button')].some(button => button.textContent === 'Details')) {
            return parent.getBoundingClientRect().height;
          }
        }
        throw Error('Missing warning controls');
      });
      assert.ok(height < 240, `The persistent warning must leave the screen usable (${height}px)`);
    }
    // React Native's modal enter/exit animation outlives the accessibility node.
    await page.waitForTimeout(500);
    if (screenshots) await page.screenshot({ path: `${screenshots}/${status}-${width}.png`, fullPage: true });
    assert.deepEqual(errors, []);
    console.log(`Anchor UI: ${status} (${width}px)`);
    await page.close();
  }
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
