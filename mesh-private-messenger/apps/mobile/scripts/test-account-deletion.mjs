// Run after npm run web --prefix ../desktop. Only native IPC is replaced.
// Native domain results are scripted; every JavaScript HTTP escape is refused.
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

// `creator` is whether this device holds the account key. Scripted answers
// belong to the native fixture, never the JS HTTP adapter. Native proof and
// profile races are separately exercised by the owned Mesh service tests.
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
    const state = window.deletionTest = { account, calls: [], answers, unexpected: [] };
    const profile = () => vectors(text(state.account === 2 ? 'bob' : 'alice'), id(state.account), id(state.account, 16), []);
    const fields = input => {
      const bytes = Uint8Array.from(input); const view = new DataView(bytes.buffer); const result = [];
      let offset = 0;
      while (offset < bytes.length) {
        const length = view.getUint32(offset); offset += 4;
        result.push([...bytes.subarray(offset, offset + length)]); offset += length;
      }
      if (offset !== bytes.length) throw Error('invalid fixture input');
      return result;
    };
    const expectedProfile = input => {
      const values = fields(input);
      if (values.length !== 2 || new TextDecoder().decode(Uint8Array.from(values[0])) !== '/test/morse.db' || values[1].join() !== profile().join()) throw Error('account_state_changed');
    };
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return 'dark';
      if (command === 'binary_request') {
        state.unexpected.push('JavaScript HTTP');
        throw Error('JavaScript account/device HTTP is forbidden');
      }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
      state.calls.push(symbol || command);
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
      if (symbol === 'mesh_messenger_transparency_fork') return [];
      if (symbol === 'mesh_messenger_load_profile') { if (!state.account) throw Error('Mesh 9: local_state_not_found'); return profile(); }
      if (symbol === 'mesh_messenger_create_account') {
        if (state.account) throw Error('account_already_exists');
        state.account = 7;
        return profile();
      }
      if (symbol === 'mesh_messenger_directory_resolve') {
        const answer = state.answers['/v1/devices/resolve'] || state.answers['/v2/devices/resolve'];
        if (answer === 'pending') return new Promise(() => {});
        if (answer === 200 || (Array.isArray(answer) && answer[0] === 200)) return [1];
        throw Error('Offline test boundary');
      }
      if (symbol === 'mesh_messenger_directory_register') {
        const answer = state.answers['/v1/devices/register'];
        if (!answer) throw Error('Offline test boundary');
        const [status, body] = Array.isArray(answer) ? answer : [answer, []];
        if (status === 409) throw Error('Mesh 9: registration_refused');
        if (status === 410) {
          const kind = { '1,65,68,76': 1, '1,68,86,82': 2 }[body.join()];
          if (!kind) throw Error('unproven_removal');
          state.account = 0;
          return [1,68,82,71,0,0,kind];
        }
        if (![200,201,204].includes(status)) throw Error('registration_failed');
        return [1,68,82,71,0,64,0];
      }
      if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
      if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
      if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
      if (['mesh_messenger_register_request', 'mesh_messenger_resolve_request', 'mesh_messenger_verify_transparency',
        'mesh_messenger_replenish_prekeys'].includes(symbol)) return [1];
      if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
      if (symbol === 'mesh_messenger_resolve_plan') return list(list(text('/v1/devices/resolve'), [1]));
      if (['account_deletion','device_departure','erase_account','forget_on_proof','renew_devices','create_device_revocation'].some(name => symbol === `mesh_messenger_${name}`)) {
        state.unexpected.push(symbol); throw Error('legacy account authority is private');
      }
      if (symbol === 'mesh_messenger_devices_renew') return [1,68,78,82,0,0,0,0];
      if (symbol === 'mesh_messenger_account_capabilities') { expectedProfile(args); return [1,65,67,80,creator ? 1 : 0]; }
      if (symbol === 'mesh_messenger_account_discard') { expectedProfile(args); state.account = 0; return [1,65,68,83,1]; }
      if (symbol === 'mesh_messenger_account_delete') {
        expectedProfile(args);
        const route = creator ? '/v1/accounts/delete' : '/v1/devices/leave';
        state.calls.push(`native:${route}`);
        if (state.answers[route] === 'late-replacement') return new Promise(resolve => {
          // A completed old erase can be delivered after a new account exists.
          state.finishDelete = () => { state.account = 2; resolve([1,65,68,78,creator ? 1 : 3]); };
        });
        const status = state.answers[route];
        if (status === 404) throw Error('account_deletion_unsupported');
        if (status === 403) throw Error('account_deletion_refused');
        if (status !== 204) throw Error(status ? `account_http_${status}` : 'account_transport_unavailable');
        state.account = 0; return [1,65,68,78,creator ? 1 : 3];
      }
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text('alice'), id(1), u64(1), [0], [creator ? 1 : 0], list(vectors(id(1, 16), [1], [1])));
      if (['mesh_messenger_list_conversations', 'mesh_messenger_group_list', 'mesh_messenger_group_invitations',
        'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_presentation_load' || symbol === 'mesh_messenger_presentation_save') return [];
      if (['mesh_messenger_journal_load', 'mesh_messenger_journal_save', 'mesh_messenger_journal_load_bound', 'mesh_messenger_journal_save_bound'].includes(symbol)) return [];
      throw Error('Offline test boundary');
    } };
  }, { account: account ? 1 : 0, creator, answers });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  const close = page.close.bind(page);
  page.close = async (...args) => { assert.deepEqual(await page.evaluate(() => window.deletionTest.unexpected), []); return close(...args); };
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
  const primaryCalls = await calls(primary);
  assert.equal(primaryCalls.includes('mesh_messenger_account_delete'), true);
  assert.equal(primaryCalls.includes('native:/v1/accounts/delete'), true);
  assert.equal(primaryCalls.includes('mesh_messenger_erase_account'), false);
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
  await linked.getByRole('button', { name: 'Back', exact: true }).click({ timeout: 5000 }).catch(async error => { console.log(await linked.locator('body').innerText(), await calls(linked)); throw error; });
  await deleteFromSettings(linked, 'Erase this device', 'Erase this device?', 'Erase device');
  await linked.getByRole('button', { name: 'Get started', exact: true }).waitFor();
  assert.equal((await calls(linked)).includes('native:/v1/accounts/delete'), false);
  assert.equal((await calls(linked)).includes('native:/v1/devices/leave'), true);
  await linked.close();
  console.log('Account deletion: a linked device leaves the account and erases only its own copy');

  const replacement = await open({ answers: { '/v1/accounts/delete': 'late-replacement', '/v1/devices/register': 201, '/v1/devices/resolve': 200 } });
  await deleteFromSettings(replacement, 'Delete account', 'Delete your account?', 'Delete account');
  await replacement.waitForFunction(() => typeof window.deletionTest.finishDelete === 'function');
  await replacement.evaluate(() => window.deletionTest.finishDelete());
  await replacement.getByText('@bob', { exact: true }).first().waitFor();
  assert.equal(await replacement.evaluate(() => window.deletionTest.account), 2);
  assert.equal(await replacement.getByRole('button', { name: 'Get started', exact: true }).count(), 0);
  await replacement.getByRole('button', { name: 'Cancel', exact: true }).waitFor({ state: 'hidden' });
  await replacement.screenshot({ path: process.env.MORSE_ACCOUNT_SCREENSHOT || '/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/phase6-account-replacement.png' });
  await replacement.close();
  console.log('Account deletion: delayed old completion keeps the replacement account and its view');

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
  await taken.getByText('That username is taken. Try another.', { exact: true }).waitFor({ timeout: 5000 }).catch(async error => { console.log(await taken.locator('body').innerText(), await calls(taken)); throw error; });
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
