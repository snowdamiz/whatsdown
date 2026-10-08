// Settings -> Backups and onboarding's "Restore from a backup", against a web
// export (npm run web --prefix ../desktop, or MORSE_TEST_DIST). Native IPC and
// the object store are scripted; MORSE_SHOTS=<dir> saves screenshots.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const dist = new URL(process.env.MORSE_TEST_DIST ?? '../../desktop/dist/', import.meta.url);
const shots = process.env.MORSE_SHOTS;
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

async function open({ account = true, holdsKey = 1 } = {}) {
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, colorScheme: 'dark', reducedMotion: 'reduce' });
  page.on('pageerror', (error) => { throw error; });
  await page.addInitScript(({ account, holdsKey }) => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const id = (n, length = 32) => Array(length).fill(n);
    const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const code = Array.from({ length: 32 }, (_, index) => index * 7 & 255);
    const state = window.backupTest = { account, on: false, last: 0, calls: [], uploads: [], restored: 0 };
    const profile = () => vectors(text('alice'), id(1), id(1, 16), []);
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return 'dark';
      if (command === 'binary_request') {
        const url = new URL(options.headers['X-Service-Url']);
        state.calls.push(`${options.headers['X-Service-Method']} ${url.pathname}`);
        if (url.pathname === '/v1/devices/resolve') return [0, 200, 1];
        if (url.pathname === '/v1/devices/register') return [0, 201];
        if (url.pathname === '/v1/prekeys/one-time/batch') return [0, 200, 1];
        if (url.pathname.startsWith('/v1/attachments/') || url.pathname.startsWith('/v1/objects/')) {
          if (url.pathname.includes('/parts/')) state.uploads.push(url.pathname);
          if (url.pathname === '/v1/attachments/delete') return [0, 204];
          // Restoring: part 0 of the second slot answers, the rest never existed.
          if (url.pathname.includes(`${'11'.repeat(32)}/parts/`)) return [0, 200, 1, 65, 67, 72];
          if (url.pathname.includes(`${'22'.repeat(32)}/parts/`)) return [1, 148];
          return [0, 201, 1, 79, 71, 83];
        }
        throw Error('Offline test boundary');
      }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol && !symbol.startsWith('mesh_messenger_journal')) state.calls.push(symbol);
      const tail = Array.from(args).slice(-32);
      switch (symbol) {
        case 'mesh_messenger_load_profile': if (!state.account) throw Error('local_state_not_found'); return profile();
        case 'mesh_messenger_backup_status': return vectors([state.on ? 2 : 0], u64(state.last));
        case 'mesh_messenger_backup_begin': return code;
        case 'mesh_messenger_backup_confirm':
          if (tail.join() !== code.join()) throw Error('Mesh 1: backup_code_mismatch');
          state.on = true;
          return [];
        case 'mesh_messenger_backup_prepare':
          return list(id(9), id(8), [1, 79, 71, 82], [1, 79, 67, 80], [1, 79, 68, 76], u32(3));
        case 'mesh_messenger_backup_part': return [1, 69, 65, 77];
        case 'mesh_messenger_backup_finish': if (Array.from(args).at(-1) === 1) state.last = Date.now(); return [];
        case 'mesh_messenger_backup_disable': state.on = false; return list([1, 79, 68, 76], [1, 79, 68, 76]);
        case 'mesh_messenger_backup_restore_slots': return list([...id(34), ...id(3)], [...id(17), ...id(3)]);
        case 'mesh_messenger_backup_restore_begin': return u32(1);
        case 'mesh_messenger_backup_restore_chunk': return [];
        case 'mesh_messenger_backup_restore_finish':
          state.restored += 1;
          return vectors(u32(2), u32(1), u64(Date.now()), text('{"v":1,"appearance":"dark"}'), u32(9));
        case 'mesh_messenger_backup_restore_identity': return vectors(text('alice'), id(1), [holdsKey]);
        case 'mesh_messenger_backup_restore_account':
          state.account = 1;
          state.recovered = true;
          return vectors(u32(4), u32(0), u64(Date.now()), text('{"v":1}'), u32(9));
        case 'mesh_messenger_account_deletion': return holdsKey ? [1, 65, 68, 76] : [];
        case 'mesh_messenger_oblivious_encapsulate': return [];
        case 'mesh_messenger_resolve_request': case 'mesh_messenger_verify_transparency': case 'mesh_messenger_register_request':
        case 'mesh_messenger_replenish_prekeys': return [1];
        case 'mesh_messenger_reconcile_prekeys': return u32(64);
        case 'mesh_messenger_renew_devices': return list();
        case 'mesh_messenger_inspect_device_set':
          return vectors(text('alice'), id(1), u64(2), [0], [1], list(vectors(id(1, 16), [1], [0]), vectors(id(2, 16), [1], [1])));
        case 'mesh_messenger_create_link_request': return [1, 76, 78, 75];
        case 'mesh_messenger_device_link_sas': return text('a1b2c3d4e5f6');
        case 'mesh_messenger_journal_load': case 'mesh_messenger_journal_save':
        case 'mesh_messenger_presentation_load': case 'mesh_messenger_presentation_save': return [];
        case 'mesh_messenger_list_conversations': case 'mesh_messenger_group_list': case 'mesh_messenger_group_invitations':
        case 'mesh_messenger_outbox_list': case 'mesh_messenger_outbox_page': return list();
        default: throw Error('Offline test boundary');
      }
    } };
  }, { account: account ? 1 : 0, holdsKey });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}

const shoot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
const state = (page) => page.evaluate(() => window.backupTest);

try {
  const page = await open();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Backups', exact: true }).click();
  await page.getByText('Back up your chats, the history of your groups and your settings', { exact: false }).waitFor();
  await shoot(page, 'backups-off');
  await page.getByRole('button', { name: 'Turn on backups', exact: true }).click();
  // The code is shown once, in thirteen groups of four.
  const shown = page.getByText(/^([0-9A-HJKMNP-TV-Z]{4} ){12}[0-9A-HJKMNP-TV-Z]{4}$/);
  await shown.waitFor();
  const code = await shown.innerText();
  await page.getByText('Keep it like a password', { exact: false }).waitFor();
  await shoot(page, 'backups-code');
  await page.getByRole('button', { name: 'I’ve written it down', exact: true }).click();
  const field = page.getByLabel('Recovery code', { exact: true });
  const wrong = `${code.slice(0, -1)}${code.at(-1) === '0' ? '2' : '0'}`;
  await field.fill(wrong.toLowerCase());
  await page.getByRole('button', { name: 'Turn on backups', exact: true }).click();
  await page.getByText('That isn’t the recovery code. Check it and try again.', { exact: true }).waitFor();
  assert.equal((await state(page)).on, false, 'A wrong code turns nothing on');
  await field.fill(code.replaceAll(' ', '-').toLowerCase());
  await page.getByRole('button', { name: 'Turn on backups', exact: true }).click();
  await page.getByText('Backups are on. The first backup is stored.', { exact: true }).waitFor();
  const first = await state(page);
  assert.equal(first.on, true);
  assert.deepEqual(first.uploads.map((path) => path.slice(-7)), ['parts/0', 'parts/1', 'parts/2'],
    'The first backup uploads every part the core prepared');
  assert.ok(first.calls.indexOf('POST /v1/attachments/complete') > first.calls.lastIndexOf(`PUT /v1/objects/${'09'.repeat(32)}/parts/2`),
    'The object is completed only after its last part');
  await page.getByText(/^On · Last backup today at/).waitFor();
  await shoot(page, 'backups-on');
  console.log('Backups: the code is shown once, a wrong code is refused, and the first backup uploads every part');

  await page.getByRole('button', { name: 'Turn off backups', exact: true }).click();
  await page.getByText('Turn off backups?', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Turn off', exact: true }).click();
  await page.getByText('Backups are off and deleted.', { exact: true }).waitFor();
  assert.equal((await state(page)).calls.filter((call) => call === 'POST /v1/attachments/delete').length, 2);
  console.log('Backups: turning them off deletes every stored backup');

  await page.getByRole('button', { name: 'Restore from a backup', exact: true }).click();
  await page.getByLabel('Recovery code', { exact: true }).fill(code);
  await page.getByRole('button', { name: 'Restore', exact: true }).click();
  await page.getByText('Restored 2 chats and the history of 1 group.', { exact: true }).waitFor();
  const restored = await state(page);
  assert.equal(restored.restored, 1);
  assert.ok(restored.calls.includes(`GET /v1/objects/${'22'.repeat(32)}/parts/0`) || restored.uploads.some((path) => path.includes('22'.repeat(32))),
    'The slot that never existed is asked and skipped');
  await shoot(page, 'backups-restored');
  await page.close();
  console.log('Backups: a restore skips empty slots and reports what came back');

  // Every device is gone: a new install gets the account back from the code
  // alone, then offers to remove the devices that are gone.
  const fresh = await open({ account: false });
  await fresh.getByRole('button', { name: 'Restore from a backup', exact: true }).click();
  await fresh.getByLabel('Recovery code', { exact: true }).fill(code);
  await shoot(fresh, 'backups-recover');
  await fresh.getByRole('button', { name: 'Restore my account', exact: true }).click();
  await fresh.getByText('@alice is back on this device.', { exact: true }).waitFor();
  await shoot(fresh, 'backups-recovered');
  const recovered = await state(fresh);
  assert.equal(recovered.recovered, true);
  const sequence = recovered.calls.filter((call) => ['mesh_messenger_backup_restore_identity', 'POST /v1/devices/resolve',
    'mesh_messenger_backup_restore_account', 'PUT /v1/devices/register'].includes(call));
  // The app then registers again at startup, as it does for any account.
  assert.deepEqual(sequence.slice(0, 4), ['mesh_messenger_backup_restore_identity', 'POST /v1/devices/resolve',
    'mesh_messenger_backup_restore_account', 'PUT /v1/devices/register'],
    'The account is restored onto the set the key log shows, then the new device registers');
  await fresh.getByRole('button', { name: 'Remove devices you no longer have', exact: true }).click();
  await fresh.getByText('Linked devices', { exact: true }).first().waitFor();
  await shoot(fresh, 'backups-recovered-devices');
  await fresh.close();
  console.log('Backups: with every device lost, the code brings the account back and offers to remove the old devices');

  // A backup from a linked device holds no account key: link this device first.
  const linkedBackup = await open({ account: false, holdsKey: 0 });
  await linkedBackup.getByRole('button', { name: 'Restore from a backup', exact: true }).click();
  await linkedBackup.getByLabel('Recovery code', { exact: true }).fill(code);
  await linkedBackup.getByRole('button', { name: 'Restore my account', exact: true }).click();
  await linkedBackup.getByText('That backup was made on a linked device', { exact: false }).waitFor();
  await linkedBackup.getByRole('button', { name: 'Link this device', exact: true }).click();
  await linkedBackup.getByText('A backup comes back onto a device of its account.', { exact: false }).waitFor();
  assert.equal((await state(linkedBackup)).calls.includes('mesh_messenger_backup_restore_account'), false);
  await linkedBackup.close();
  console.log('Backups: a linked device’s backup restores through linking this device first');

} finally {
  await browser.close();
  server.close();
}
