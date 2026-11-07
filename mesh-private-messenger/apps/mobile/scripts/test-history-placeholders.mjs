// Run against an Expo web export, as in test-receipts.mjs. Only native I/O is replaced.
// These are literal contract frames, not a Core receive/open integration test.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

const dist = pathToFileURL(resolve(process.env.MORSE_TEST_DIST ?? '../desktop/dist') + '/');
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
const result = { scope: 'Actual App.tsx chat render with literal 02HST frames and synthetic native I/O', cases: [], pageErrors: [] };
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  for (const width of [420, 1160]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 }, reducedMotion: 'reduce' });
    page.setDefaultTimeout(15_000);
    page.on('pageerror', error => result.pageErrors.push(error.message));
    await page.addInitScript(() => {
      const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
      const u64 = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
      const text = s => [...new TextEncoder().encode(s)];
      const id = (n, length = 32) => Array(length).fill(n);
      const vectors = (...values) => values.flatMap(value => [...u32(value.length), ...value]);
      const list = (...values) => vectors(u32(values.length), ...values);
      const owner = '00000000-0000-4000-8000-000000000001';
      const snapshot = { version: 1, owner, revision: '1', state: {
        epoch: owner + '/1', phase: 'activated', policy: 'disabled', capability: 'available', foreground: true,
      } };
      const state = window.historyTest = { calls: [], forbidden: [], historyReads: 0 };
      const history = [2, 72, 83, 84, ...list(...[0, 1, 2, 3, 4, 5].map(status =>
        vectors([2], id(status + 1, 16), u64(Date.now() - (6 - status) * 1000),
          text(status === 0 ? 'ordinary caption' : status === 2 ? 'a visible caption' : ''), u32(0), [], [0], [status])))];
      window.__MORSE_DOCUMENT__ = owner;
      window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback() {},
        invoke: async (command, args, options) => {
          const symbol = options?.headers?.['X-Mesh-Symbol'];
          state.calls.push(symbol || command);
          if (/attachment|view_once|save_file/.test(symbol || command)) {
            state.forbidden.push(symbol || command); throw Error('Placeholder entered an attachment operation');
          }
          if (command === 'app_lock_bind' || command === 'app_lock_state') return snapshot;
          if (command === 'app_lock_check' || command === 'app_lock_release' || command === 'app_lock_file_cleanup') return null;
          if (command === 'plugin:event|listen') return 1;
          if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : null;
          if (command === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
          if (command === 'app_lock_legacy_preference') return null;
          if (command === 'app_lock_notification_binding') return 'disabled';
          if (command === 'app_lock_file') {
            const operation = options.headers['X-Morse-File-Operation'];
            if (operation === 'subscribeIncoming') return { version: 1, handle: owner };
            if (operation === 'pendingChoice') return { version: 1 };
            state.forbidden.push(operation); throw Error('Unexpected file operation');
          }
          if (command === 'database_path') return '/test/history.db';
          if (command === 'appearance') return 'dark';
          if (symbol === 'mesh_messenger_account_capabilities') return [1, 65, 67, 80, 1];
          if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
          if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(20, 16), text('bob'), id(2), id(2, 16), text('1234'.repeat(16)), [1], [0], [0], [0], u32(0)));
          if (symbol === 'mesh_messenger_load_history') { state.historyReads++; return [...history]; }
          if (symbol === 'mesh_messenger_group_list' || symbol === 'mesh_messenger_group_invitations') return list();
          if (symbol === 'mesh_messenger_anchor_check') return list(...['off', '0', '0', '0', '0'].map(text));
          if (symbol === 'mesh_messenger_transparency_fork' || symbol === 'mesh_messenger_presentation_load') return [];
          if (symbol === 'mesh_messenger_signup_draft_state') return [0];
          if (symbol === 'mesh_messenger_journal_load_bound' || symbol === 'mesh_messenger_journal_save_bound') return [];
          throw Error('Offline test boundary');
        },
      };
    });
    try {
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      const chat = page.getByRole('button', { name: /^Conversation with @bob/ });
      await chat.waitFor();
      await chat.getByText('View-once photo · Unavailable', { exact: true }).waitFor();
      await chat.click();
      for (const label of ['Waiting', 'Ready', 'Opened', 'Expired', 'Unavailable']) {
        const body = `View-once photo · ${label}${label === 'Ready' ? '\na visible caption' : ''}`;
        const bubble = page.getByLabel(`Received message: ${body}`, { exact: true });
        await bubble.waitFor();
        assert.equal(await bubble.locator('img').count(), 0);
        assert.equal(await bubble.getByRole('button', { name: /View|Download|Save|Open/ }).count(), 0);
      }
      await page.getByLabel('Received message: ordinary caption', { exact: true }).waitFor();
      assert.equal(await page.getByRole('dialog').count(), 0);
      assert.deepEqual(await page.evaluate(() => window.historyTest.forbidden), []);
      assert.ok(await page.evaluate(() => window.historyTest.historyReads >= 2));
      assert.equal(await page.getByText('Those files could not be read.', { exact: true }).count(), 0);
      result.cases.push({ width, status: 'passed', nativeAttachmentCalls: 0 });
    } catch (error) {
      result.cases.push({ width, status: 'failed', error: error.message,
        body: await page.locator('body').innerText(), calls: await page.evaluate(() => window.historyTest.calls) });
      throw error;
    } finally { await page.close(); }
  }
  assert.deepEqual(result.pageErrors, []);
  result.status = 'passed';
} catch (error) { result.status = 'failed'; result.error = error.message; process.exitCode = 1; }
finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
  if (process.env.MORSE_TEST_RESULT) await writeFile(process.env.MORSE_TEST_RESULT, JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
}
