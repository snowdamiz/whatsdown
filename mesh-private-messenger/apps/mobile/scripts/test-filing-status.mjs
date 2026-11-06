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
const screenshots = process.env.MORSE_FILING_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  for (const status of ['pending', 'accepted', 'rpc_unavailable', 'rpc_disagree', 'settled', 'paid_elsewhere', 'disabled', 'error']) {
    const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(({ status, forkBytes }) => {
      const text = value => [...new TextEncoder().encode(value)];
      const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
      const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
      const list = (...fields) => vectors(u32(fields.length), ...fields);
      let release;
      const ready = status === 'pending' ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
      window.filingUITest = { calls: 0, saves: [], release: () => release?.() };
      window.isTauri = true;
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback: () => {},
        invoke: async (command, args, options) => {
          if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
          if (command === 'database_path') return '/test/filing.db';
          if (command === 'appearance') return 'dark';
          if (command === 'save_attachment') {
            window.filingUITest.saves.push({ bytes: [...args], name: decodeURIComponent(options.headers['X-File-Name']) });
            return true;
          }
          if (command === 'mailbox_connect' || command === 'mailbox_disconnect') return;
          if (command === 'binary_request') throw Error('Offline fixture');
          const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
          if (symbol === 'mesh_messenger_directory_resolve') return [1];
          if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
          if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
          if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), Array(32).fill(1), Array(16).fill(1), []);
          if (symbol === 'mesh_messenger_anchor_check') return list(...['mismatch', '9000000', '501', '500', '8000'].map(text));
          if (symbol === 'mesh_messenger_transparency_fork') return forkBytes;
          if (symbol === 'mesh_messenger_fork_filing') {
            window.filingUITest.calls++;
            await ready;
            if (status === 'error') throw Error('secure_storage_unavailable');
            if (status === 'disabled') return list(...['disabled', '', '', '', '0', '', '0', '0', '0', '0', '0', '0'].map(text));
            const finder = '11111111111111111111111111111112';
            const other = '11111111111111111111111111111113';
            const paid = status === 'settled' || status === 'paid_elsewhere';
            return list(...[status, 'ab'.repeat(32), finder, paid ? (status === 'settled' ? finder : other) : '',
              paid ? '18446744073709551615' : '0', other, status === 'pending' ? '0' : '2', '3', '1000', '61000', '9007199254740993', '0'].map(text));
          }
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
    }, { status, forkBytes });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.waitForFunction(() => window.filingUITest.calls > 0, { timeout: 5000 });
    // Local navigation and the evidence remain usable while the native view is pending.
    await page.getByRole('button', { name: 'Settings', exact: true }).click({ timeout: 1500 });
    await page.getByRole('button', { name: 'Details', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Key log evidence', exact: true });
    await dialog.getByRole('button', { name: 'Copy evidence', exact: true }).waitFor();
    await dialog.getByText(forkFixture, { exact: true }).waitFor();
    await page.evaluate(() => window.filingUITest.release());
    const detail = {
      pending: /Your device is filing the evidence/,
      accepted: /A relay accepted the evidence. Payment has not been confirmed/,
      rpc_unavailable: /The public receipt could not be checked/,
      rpc_disagree: /Public receipt providers disagree/,
      settled: /A public receipt confirms the payout to this proof’s finder address/,
      paid_elsewhere: /Another phone or monitor may have filed the same proof first/,
      disabled: /Automatic filing is not configured in this app release/,
      error: /Filing status could not be loaded/,
    }[status];
    await dialog.getByText(detail).waitFor();
    if (['settled', 'paid_elsewhere'].includes(status)) {
      await dialog.getByText(/18446744073709551615 token base units/).waitFor();
      await dialog.getByText(/Finalized slot: 9007199254740993/).waitFor();
    } else assert.equal(await dialog.getByText(/Paid: /).count(), 0);
    if (status === 'accepted') await dialog.getByText('2 of 3 relays acknowledged the latest completed attempt.', { exact: true }).waitFor();
    await dialog.getByRole('button', { name: 'Save evidence file', exact: true }).click({ timeout: 1500 });
    assert.deepEqual(await page.evaluate(() => window.filingUITest.saves), [{ bytes: forkBytes, name: 'morse-fork.frk' }]);
    if (screenshots) {
      await page.waitForTimeout(500);
      await page.screenshot({ path: `${screenshots}/${status}.png`, fullPage: true });
    }
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await page.getByText('Your device found conflicting signed key logs. New chats and key changes are paused. Existing chats can continue.', { exact: true }).waitFor();
    assert.deepEqual(errors, []);
    console.log(`Filing UI: ${status}`);
    await page.close();
  }
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
