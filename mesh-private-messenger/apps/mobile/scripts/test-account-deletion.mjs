// Run after npm run web --prefix ../desktop (or point MORSE_TEST_DIST at another
// web export). Only native IPC is replaced; the directory answers are scripted.
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
const url = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });

// `creator` is whether this device holds the account key. `answers` maps a
// directory path to the HTTP status it gives, or [status, body]; anything else
// is offline. The account's deletion statement is [1, 65, 68, 76] and its
// revocation of this device [1, 68, 86, 82].
async function open({ account = true, creator = true, answers = {} } = {}) {
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, colorScheme: 'dark', reducedMotion: 'reduce' });
  page.on('pageerror', (error) => { throw error; });
  await page.addInitScript(({ account, creator, answers }) => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const id = (n, length = 32) => Array(length).fill(n);
    const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const state = window.deletionTest = { account, calls: [], answers };
    const profile = () => vectors(text('alice'), id(state.account), id(state.account, 16), []);
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return 'dark';
      if (command === 'binary_request') {
        const path = new URL(options.headers['X-Service-Url']).pathname;
        state.calls.push(path);
        const answer = state.answers[path];
        if (!answer) throw Error('Offline test boundary');
        if (answer === 'pending') return new Promise(() => {});
        const [status, body] = Array.isArray(answer) ? answer : [answer, answer === 200 ? [1] : []];
        // Framed as the desktop host does: status, then any body.
        return [status >> 8, status & 255, ...body];
      }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      state.calls.push(symbol || command);
      if (symbol === 'mesh_messenger_load_profile') { if (!state.account) throw Error('local_state_not_found'); return profile(); }
      if (symbol === 'mesh_messenger_create_account') {
        if (state.account) throw Error('account_already_exists');
        state.account = 7;
        return profile();
      }
      if (['mesh_messenger_register_request', 'mesh_messenger_resolve_request', 'mesh_messenger_verify_transparency',
        'mesh_messenger_replenish_prekeys'].includes(symbol)) return [1];
      if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
      if (symbol === 'mesh_messenger_account_deletion') return creator ? [1, 65, 68, 76] : [];
      if (symbol === 'mesh_messenger_erase_account') { state.account = 0; return []; }
      if (symbol === 'mesh_messenger_device_departure') return [1, 68, 80, 84];
      // The core erases only on a proof it checks, and says which one it was.
      if (symbol === 'mesh_messenger_forget_on_proof') {
        const kind = { '1,65,68,76': 1, '1,68,86,82': 2 }[Array.from(args).slice(-4).join()];
        if (!kind) throw Error('unproven_removal');
        state.account = 0;
        return [kind];
      }
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text('alice'), id(1), u64(1), [0], [creator ? 1 : 0], list(vectors(id(1, 16), [1], [1])));
      if (['mesh_messenger_list_conversations', 'mesh_messenger_group_list', 'mesh_messenger_group_invitations',
        'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_presentation_load' || symbol === 'mesh_messenger_presentation_save') return [];
      if (symbol === 'mesh_messenger_journal_load' || symbol === 'mesh_messenger_journal_save') return [];
      throw Error('Offline test boundary');
    } };
  }, { account: account ? 1 : 0, creator, answers });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}

const calls = (page) => page.evaluate(() => window.deletionTest.calls);
const since = (all, symbol) => all.slice(all.lastIndexOf(symbol));

async function deleteFromSettings(page, row, dialog, action) {
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: new RegExp(`^${row}`) }).click();
  await page.getByText(dialog, { exact: true }).waitFor();
  // The dialog renders after the screen, whose row may carry the same words.
  await page.getByRole('button', { name: action, exact: true }).last().click();
}

async function createAccount(page, username) {
  await page.getByLabel('Choose your username', { exact: true }).fill(username);
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
}

try {
  // The device that created the account deletes it everywhere, then starts over.
  const primary = await open({ answers: { '/v1/accounts/delete': 204, '/v1/devices/register': 201 } });
  await deleteFromSettings(primary, 'Delete account', 'Delete your account?', 'Delete account');
  await primary.getByRole('button', { name: 'Get started', exact: true }).waitFor();
  assert.deepEqual(
    since(await calls(primary), 'mesh_messenger_account_deletion').filter((call) => !call.startsWith('mesh_messenger_journal')),
    ['mesh_messenger_account_deletion', '/v1/accounts/delete', 'mesh_messenger_erase_account', 'mesh_messenger_load_profile'],
    'The account leaves the directory before this device forgets it, and the app starts over',
  );
  await primary.getByRole('button', { name: 'Get started', exact: true }).click();
  await createAccount(primary, 'alice');
  await primary.getByRole('button', { name: 'Settings', exact: true }).waitFor();
  await primary.close();
  console.log('Account deletion: deleted everywhere, back to onboarding, and the same name is free again');

  // Refused, nothing is erased: the account is whole and can try again.
  const offline = await open({ answers: { '/v1/accounts/delete': 500 } });
  await deleteFromSettings(offline, 'Delete account', 'Delete your account?', 'Delete account');
  await offline.getByText('The server hit a problem. Try again in a moment.', { exact: true }).first().waitFor();
  assert.equal((await calls(offline)).includes('mesh_messenger_erase_account'), false);
  assert.equal(await offline.evaluate(() => window.deletionTest.account), 1);
  await offline.getByRole('button', { name: /^Delete account/ }).waitFor();
  await offline.close();
  console.log('Account deletion: a failed request keeps the account and the way to retry');

  // A linked device holds no account key, says so, leaves the account, and
  // erases only itself.
  const linked = await open({ creator: false, answers: { '/v1/devices/resolve': 200, '/v1/devices/leave': 204 } });
  await linked.getByRole('button', { name: 'Settings', exact: true }).click();
  await linked.getByRole('button', { name: /^Linked devices/ }).click();
  await linked.getByRole('button', { name: 'Back', exact: true }).click();
  await deleteFromSettings(linked, 'Erase this device', 'Erase this device?', 'Erase device');
  await linked.getByRole('button', { name: 'Get started', exact: true }).waitFor();
  assert.equal((await calls(linked)).includes('/v1/accounts/delete'), false);
  assert.deepEqual(since(await calls(linked), 'mesh_messenger_device_departure').slice(0, 3),
    ['mesh_messenger_device_departure', '/v1/devices/leave', 'mesh_messenger_erase_account'],
    'A linked device leaves the account before it forgets it, so no one sends to it after');
  await linked.close();
  console.log('Account deletion: a linked device leaves the account and erases only its own copy');

  // The account was deleted on the device that created it. The one left behind
  // hears it the next time it registers, with the owner's statement, and erases
  // itself on that alone.
  const orphan = await open({ creator: false, answers: { '/v1/devices/register': [410, [1, 65, 68, 76]] } });
  await orphan.getByText('Your account was deleted on another device, so its messages and keys were erased from this one too.', { exact: true }).waitFor();
  await orphan.getByRole('button', { name: 'Get started', exact: true }).waitFor();
  assert.equal(await orphan.evaluate(() => window.deletionTest.account), 0);
  await orphan.close();
  // The device that created the account removed this one, and the account's
  // revocation of it does the same.
  const removed = await open({ creator: false, answers: { '/v1/devices/register': [410, [1, 68, 86, 82]] } });
  await removed.getByText('This device was removed from your account on another device, so its messages and keys were erased from it.', { exact: true }).waitFor();
  assert.equal(await removed.evaluate(() => window.deletionTest.account), 0);
  await removed.close();
  const misled = await open({ creator: false, answers: { '/v1/devices/register': [410, [1, 2, 3, 4]] } });
  await misled.getByText('The server says this device is no longer in its account but can’t prove it. Nothing was erased.', { exact: true }).first().waitFor();
  assert.equal(await misled.evaluate(() => window.deletionTest.account), 1);
  await misled.close();
  console.log('Account deletion: a deleted or removed device erases itself on signed proof, and on nothing less');

  // A name the directory refuses is undone at signup instead of stranding the account.
  const taken = await open({ account: false, answers: { '/v1/devices/register': 409 } });
  await taken.getByRole('button', { name: 'Get started', exact: true }).click();
  await createAccount(taken, 'alice');
  await taken.getByText('That username is taken. Try another.', { exact: true }).waitFor();
  assert.equal(await taken.evaluate(() => window.deletionTest.account), 0);
  await taken.evaluate(() => { window.deletionTest.answers['/v1/devices/register'] = 201; });
  await createAccount(taken, 'alice_2');
  await taken.getByRole('button', { name: 'Settings', exact: true }).waitFor();
  await taken.close();
  console.log('Account deletion: a taken username at signup leaves nothing behind');

  // Signup ends at registration. The witnesses countersign the new device set
  // seconds later, and the app checks that in the background, not behind a
  // locked screen.
  const unwitnessed = await open({ account: false, answers: {
    '/v1/devices/register': 201, '/v1/prekeys/one-time/batch': 200, '/v1/devices/resolve': 'pending',
  } });
  await unwitnessed.getByRole('button', { name: 'Get started', exact: true }).click();
  await createAccount(unwitnessed, 'alice');
  await deleteFromSettings(unwitnessed, 'Delete account', 'Delete your account?', 'Cancel');
  await unwitnessed.close();
  console.log('Account creation: usable once registered, before the witnesses countersign');
} finally {
  await browser.close();
  server.close();
}
