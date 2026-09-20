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
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_verify_transparency') return [1];
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text(creator ? 'alice' : 'maya'), id(self), u64(1), [0], [1], list(vectors(id(self, 16), [1], [1])));
      if (symbol === 'mesh_messenger_list_conversations') return contact ? list(vectors(id(20, 16), text('alex_1987'), id(2), id(2, 16), text('1234'.repeat(16)), [1], [0], [0], [0], u32(0))) : list();
      if (symbol === 'mesh_messenger_load_history' || symbol === 'mesh_messenger_group_invitations' || symbol === 'mesh_messenger_outbox_list') return list();
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
      throw Error('Offline test boundary');
    } };
  }, { scheme, account, creator, contact });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}

async function choosePhoto(page) {
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: /^(Add|Change) photo$/ }).click();
  await (await chooser).setFiles(fileURLToPath(new URL('../assets/icon.png', import.meta.url)));
  await page.getByRole('button', { name: 'Remove photo', exact: true }).waitFor();
}

try {
  const named = await open({ account: false });
  await named.getByLabel('Choose your username', { exact: true }).fill('alice');
  await named.getByLabel('Display name (optional)', { exact: true }).fill('Alice Chen');
  await named.getByRole('button', { name: 'Create account', exact: true }).click();
  await named.getByRole('button', { name: 'Settings', exact: true }).click();
  await named.getByText('Alice Chen', { exact: true }).first().waitFor();
  const light = named.getByRole('radio', { name: 'Theme: Light', exact: true });
  await light.click();
  await named.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  assert.equal(await light.getAttribute('aria-checked'), 'true', 'The theme switch marks and applies the choice');
  await choosePhoto(named);
  const savedName = () => named.evaluate(() => {
    const bytes = new Uint8Array(window.profileTest.saved[`user/${'01'.repeat(32)}`]);
    return new TextDecoder().decode(bytes.slice(4, 4 + new DataView(bytes.buffer).getUint32(0)));
  });
  assert.equal(await savedName(), 'Alice Chen', 'Changing the photo preserves the display name');
  await named.getByRole('button', { name: /Display name/ }).click();
  const editName = named.getByRole('dialog', { name: 'Display name', exact: true });
  await editName.getByLabel('Display name', { exact: true }).fill('Alice C.');
  await editName.getByRole('button', { name: 'Save', exact: true }).click();
  await editName.waitFor({ state: 'detached' });
  assert.equal(await savedName(), 'Alice C.');
  await named.getByRole('button', { name: /Display name/ }).click();
  await editName.getByLabel('Display name', { exact: true }).fill('');
  await editName.getByRole('button', { name: 'Save', exact: true }).click();
  await editName.waitFor({ state: 'detached' });
  assert.equal(await savedName(), 'alice', 'Clearing the optional name restores the username');
  await named.close();
  console.log('Profiles: optional signup name can be edited and survives photo changes');
  const nicknamed = await open({ contact: true });
  await nicknamed.getByText('Alex Chen', { exact: true }).click();
  await nicknamed.getByRole('button', { name: 'Conversation details', exact: true }).click();
  assert.equal(await nicknamed.getByRole('radio', { name: 'Disappear: Off', exact: true }).getAttribute('aria-checked'), 'true', 'The timer shows the saved choice');
  await nicknamed.getByRole('button', { name: /Private nickname/ }).click();
  const nicknameEditor = nicknamed.getByRole('dialog', { name: 'Private nickname', exact: true });
  await nicknameEditor.getByLabel('Private nickname', { exact: true }).fill('Dad');
  if (screenshots) await nicknamed.screenshot({ path: `${screenshots}/nickname-editor.png`, animations: 'disabled' });
  await nicknameEditor.getByRole('button', { name: 'Save', exact: true }).click();
  await nicknameEditor.waitFor({ state: 'detached' });
  await nicknamed.getByRole('button', { name: 'Conversation with Dad', exact: true }).waitFor();
  await nicknamed.getByText('@alex_1987', { exact: true }).waitFor();
  if (screenshots) await nicknamed.screenshot({ path: `${screenshots}/nickname-saved.png`, animations: 'disabled' });
  await nicknamed.getByRole('tab', { name: /^Groups\b/ }).click();
  await nicknamed.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
  await nicknamed.getByText('Dad', { exact: true }).waitFor();
  await nicknamed.getByRole('button', { name: 'Group members', exact: true }).click();
  await nicknamed.getByRole('button', { name: 'Message Dad', exact: true }).click();
  await nicknamed.getByRole('button', { name: 'Conversation details', exact: true }).click();
  await nicknamed.getByRole('button', { name: /Private nickname/ }).click();
  await nicknameEditor.getByLabel('Private nickname', { exact: true }).fill('');
  await nicknameEditor.getByRole('button', { name: 'Save', exact: true }).click();
  await nicknameEditor.waitFor({ state: 'detached' });
  await nicknamed.getByRole('button', { name: 'Conversation with Alex Chen', exact: true }).waitFor();
  await nicknamed.close();
  console.log('Profiles: private nicknames override names in chats and groups and can be removed');
  for (const scheme of ['dark', 'light']) {
    const page = await open({ scheme });
    await page.getByRole('tab', { name: /^Groups\b/ }).click();
    await page.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
    await page.getByText('Alex Chen', { exact: true }).waitFor();
    await page.getByText('@maya', { exact: true }).waitFor();
    // Own messages carry no name; the thread names only the others.
    const own = page.getByLabel('@alice message: See you both there!', { exact: true });
    await own.waitFor();
    assert.equal(await own.getByText('@alice', { exact: true }).count(), 0);
    const colors = await Promise.all(['Alex Chen', '@maya'].map((name) => page.getByText(name, { exact: true }).evaluate((el) => getComputedStyle(el).color)));
    assert.notEqual(colors[0], colors[1], 'Different accounts need different message colors in this fixture');
    if (await page.getByRole('button', { name: 'Dismiss', exact: true }).count()) await page.getByRole('button', { name: 'Dismiss', exact: true }).first().click();
    if (screenshots) await page.screenshot({ path: `${screenshots}/group-${scheme}.png` });
    const openMembers = () => page.getByRole('button', { name: 'Group members', exact: true }).click();
    await openMembers();
    const members = page.getByRole('dialog', { name: 'Group members', exact: true });
    await members.getByText('3 members', { exact: true }).waitFor();
    await members.getByText('@alice', { exact: true }).waitFor();
    await members.getByText('You', { exact: true }).waitFor();
    await members.getByText('Alex Chen', { exact: true }).waitFor();
    await members.getByText('@maya', { exact: true }).waitFor();
    assert.equal(await members.getByText('Created the group', { exact: true }).count(), 1);
    // Nobody here is in the chat list, so each of the others can be written to afresh; you cannot.
    assert.equal(await members.getByText('Not in your chats yet', { exact: true }).count(), 2);
    assert.equal(await members.getByRole('button', { name: /^Message / }).count(), 2);
    if (screenshots) await page.screenshot({ path: `${screenshots}/members-${scheme}.png` });
    await members.getByRole('button', { name: 'Close', exact: true }).click();
    await members.waitFor({ state: 'detached' });
    await openMembers();
    await members.getByRole('button', { name: 'Message Alex Chen', exact: true }).click();
    await members.waitFor({ state: 'detached' });
    assert.equal(await page.getByLabel('Username', { exact: true }).inputValue(), 'alex', 'The private message shortcut addresses the new message');
    assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), 'First message', 'With the recipient named, the message is what is left to write');
    await page.getByRole('tab', { name: /^Groups\b/ }).click();
    await page.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
    await openMembers();
    await members.getByRole('button', { name: 'Invite someone', exact: true }).click();
    await members.waitFor({ state: 'detached' });
    await page.getByLabel('Exact username', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), 'Exact username', 'Inviting from the dialog lands ready to type');
    await choosePhoto(page);
    await page.getByRole('button', { name: 'Remove photo', exact: true }).click();
    await page.getByRole('button', { name: 'Add photo', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Create group', exact: true }).click();
    assert.equal(await page.evaluate(() => window.profileTest.creates), 0, 'Opening the creation flow must not create a group');
    await page.getByLabel('Group name', { exact: true }).fill('Dinner club');
    await choosePhoto(page);
    if (screenshots) await page.screenshot({ path: `${screenshots}/create-${scheme}.png` });
    await page.getByRole('button', { name: 'Create group', exact: true }).last().click();
    await page.getByText('Invite someone', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.profileTest.creates), 1);
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await choosePhoto(page);
    await page.reload();
    // The IPC fixture resets on reload; persistent bytes are asserted at the native layer.
    await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
    console.log(`Profiles: ${scheme} group senders, members dialog, group creation, group photo changes and settings picker`);
    await page.close();
  }
  const member = await open({ creator: false, width: 720 });
  await member.getByRole('tab', { name: /^Groups\b/ }).click();
  await member.getByRole('button', { name: /^Weekend walks(?:,|$)/ }).click();
  await member.getByRole('button', { name: 'Group details', exact: true }).click();
  await member.getByText('Invite someone', { exact: true }).waitFor();
  assert.equal(await member.getByRole('button', { name: 'Add photo', exact: true }).count(), 0);
  await member.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  if (screenshots) await member.screenshot({ path: `${screenshots}/group-details-narrow.png` });
  assert.ok(await member.getByLabel('Exact username', { exact: true }).evaluate((el) => el.parentElement.getBoundingClientRect().width) >= 160, 'The invite field must remain usable in a narrow pane');
  if (screenshots) await member.screenshot({ path: `${screenshots}/group-details-narrow.png` });
  assert.ok(await member.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'The minimum desktop width must not overflow');
  await member.close();
  const onboarding = await open({ account: false });
  await choosePhoto(onboarding);
  await onboarding.getByLabel('Choose your username', { exact: true }).fill('alice');
  await onboarding.getByRole('button', { name: 'Create account', exact: true }).click();
  await onboarding.getByRole('button', { name: 'Settings', exact: true }).waitFor();
  const saved = await onboarding.evaluate(() => window.profileTest.saved[`user/${'01'.repeat(32)}`]);
  assert.ok(saved.length > 100, 'The chosen photo must be saved with the new account');
  await onboarding.close();
  console.log('Profiles: non-creators cannot edit group photos; onboarding saves the selected photo');
} finally { await browser.close(); server.close(); }
