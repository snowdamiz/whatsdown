// Run after npm run web --prefix ../desktop (or point MORSE_WEB_DIST at another web export).
// Only native IPC/network I/O is replaced. Alice (1) is this account. By default she is a
// member of the community's second part; `?owner` makes her its owner in two of its three
// parts, and `?full` also fills those parts so an invitation grows a new one. `?departed`
// has another of her devices leave first. `?outsider` is in no community yet, and
// `?approved` has already been let in by Bob, whose invitation waits.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const dist = process.env.MORSE_WEB_DIST
  ? pathToFileURL(`${process.env.MORSE_WEB_DIST}/`)
  : new URL('../../desktop/dist/', import.meta.url);
const shots = process.env.MORSE_COMMUNITY_SCREENSHOTS;
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const hex = (n) => n.toString(16).padStart(2, '0').repeat(32);
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(10_000);
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const decode = (b) => new TextDecoder().decode(new Uint8Array(b));
    const id = (n, length = 32) => Array(length).fill(n);
    const hex = (n) => n.toString(16).padStart(2, '0').repeat(32);
    const vectors = (...values) => values.flatMap((v) => [...u32(v.length), ...v]);
    const list = (...values) => vectors(u32(values.length), ...values);
    const fields = (bytes) => {
      const out = []; let i = 0;
      while (i < bytes.length) {
        const n = new DataView(new Uint8Array(bytes.slice(i, i + 4)).buffer).getUint32(0);
        i += 4; out.push(bytes.slice(i, i + n)); i += n;
      }
      return out;
    };
    const query = new URLSearchParams(location.search);
    const owner = query.has('owner');
    const full = query.has('full');
    const departed = query.has('departed');
    const outsider = query.has('outsider') || query.has('approved');
    const approved = query.has('approved');
    // Parts 80, 83 and 84; linked groups Trading (81) and Dev (82).
    const [first, second, third, trading, dev, grown] = [80, 83, 84, 81, 82, 90];
    const names = { 1: 'alice', 2: 'bob', 3: 'carol', 5: 'dave', 6: 'erin' };
    const creator = owner ? 1 : 2;
    const record = (parts, admins = [5]) => vectors(text('Solana builders'), [], u64(5),
      text(JSON.stringify(['Builders shipping on Solana.', [[hex(trading), 'Trading'], [hex(dev), 'Dev']], parts.map(hex)])),
      [creator, ...admins].flatMap((n) => id(n)));
    const post = (body, serial, sender) => list([1], [sender === 1 ? 1 : 2], u64(1), id(sender), id(sender, 16), u64(Date.now()), text(body), [], id(serial));
    const reaction = (target, sender, serial) => post(`MORSE-REACTION/1\n${JSON.stringify([hex(target), '👍', 1])}`, serial, sender);
    const member = (n, leaf) => list([1], u32(leaf), [n === 1 ? 1 : 0], id(n), id(n, 16), u64(1), [2], text(names[n]));
    const devicePackage = Array(369).fill(7);
    const saved = JSON.parse(sessionStorage.getItem('community-test') || 'null');
    const state = window.communityTest = saved ?? {
      sends: [], invites: [], adds: [], saves: [], removes: [], forgotten: [], created: 0, direct: {}, pending: [], policies: [],
      fanouts: [], accepted: [],
      histories: owner ? {
        [first]: [post('Mainnet upgrade on Friday', 11, 1), reaction(11, 2, 12), post('gm, buy my token', 13, 2),
          post(`MORSE-DEVICE/1\n${hex(second)}\n${'0a'.repeat(369)}`, 14, 5), post('MORSE-LEAVE/1', 15, 2)],
        [second]: [post('Mainnet upgrade on Friday', 21, 1), reaction(21, 3, 22), post(`MORSE-JOIN/1\n${hex(trading)}`, 23, 3)],
      } : {
        [second]: [post('Mainnet upgrade on Friday', 21, 2), post('gm, buy my token', 22, 3), post('AMA at 5pm', 23, 5),
          post(`MORSE-JOIN/1\n${hex(trading)}`, 24, 3), ...(departed ? [post('MORSE-LEAVE/1', 25, 1)] : [])],
      },
      records: owner ? { [first]: record([first, second, third]), [second]: record([first, second, third]) } : { [second]: record([first, second]) },
    };
    const persist = () => sessionStorage.setItem('community-test', JSON.stringify(state));
    // Direct chats about joining: 1 is sent, 2 received.
    const direct = (body, serial, direction) => vectors([direction], id(serial, 16), u64(Date.now()), text(body), u32(0), [], [0]);
    const asked = `MORSE-COMMUNITY-REQUEST/1\n${JSON.stringify([hex(first), 'Solana builders'])}`;
    if (!saved && owner) { state.direct[6] = [direct(asked, 60, 2)]; state.pending = [6]; }
    // Dave shares the community's link in a chat with someone outside it.
    const shared = `mesh://community/${btoa(JSON.stringify([hex(first), 'bob', 'Solana builders'])).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`;
    if (!saved && outsider && !approved) state.direct[5] = [direct(`Come build with us: ${shared}`, 63, 2)];
    if (!saved && approved) {
      state.direct[2] = [direct(asked, 61, 1), direct(`MORSE-COMMUNITY-ANSWER/1\n${JSON.stringify([hex(first), hex(second)])}`, 62, 2)];
    }
    const rosters = owner
      ? { [first]: [1, 5, 2], [second]: [1, 3], [trading]: [1, 2], [dev]: [1], [grown]: [1] }
      : { [second]: [2, 5, 1, 3], [trading]: [1, 2] };
    const leaves = (group) => full && group !== grown ? 60 : rosters[group].length;
    const groups = () => [...(owner ? [first, second, trading, dev] : outsider ? [trading] : [second, trading]), ...(state.created ? [grown] : [])]
      .filter((group) => !state.forgotten.includes(group));
    const other = { [trading]: vectors(text('Trading'), []), [dev]: vectors(text('Dev'), []) };
    const groupOf = (request) => fields(request)[1][0];
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/communities.db';
      if (command === 'appearance') return 'light';
      if (command === 'binary_request') return new Uint8Array([0, 200, ...args]).buffer;
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      const request = args instanceof Uint8Array ? [...args] : [];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') {
        return list(...Object.keys(state.direct).map(Number).map((n) => vectors(id(20 + n, 16), text(names[n]), id(n), id(n, 16),
          text('1234'.repeat(16)), [state.pending.includes(n) ? 0 : 1], [0], [0], [0], u32(0), u64(0))));
      }
      if (symbol === 'mesh_messenger_load_history') return list(...(state.direct[fields(request)[1][0]] ?? []));
      if (symbol === 'mesh_messenger_update_conversation') {
        const n = fields(request)[1][0];
        state.policies.push(n);
        state.pending = state.pending.filter((item) => item !== n);
        persist();
        return [];
      }
      if (symbol === 'mesh_messenger_send_fanout') {
        const parts = fields(request);
        const n = Number(Object.keys(names).find((key) => names[key] === decode(parts[1])));
        const body = decode(parts[3]);
        state.fanouts.push({ peer: names[n], body });
        (state.direct[n] ??= []).push(direct(body, 70 + state.fanouts.length, 1));
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_group_invitation_accept') {
        state.accepted.push(fields(request)[3][0]);
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_group_list') return list(...groups().map((group) => list([1], id(group), u64(1), u32(leaves(group)))));
      if (symbol === 'mesh_messenger_group_history') return list(...(state.histories[groupOf(request)] ?? []));
      if (symbol === 'mesh_messenger_group_inspect') {
        const group = groupOf(request);
        return list([1], id(group), u64(1), u32(0), id(4), id(5), list(...rosters[group].map(member)));
      }
      if (symbol === 'mesh_messenger_presentation_load') {
        const key = decode(fields(request)[1]);
        const group = [first, second, third, trading, dev, grown].find((n) => key === `group/${hex(n)}`);
        return group ? state.records[group] ?? other[group] ?? [] : [];
      }
      if (symbol === 'mesh_messenger_presentation_save') {
        const [, key, value] = fields(request);
        const group = [first, second, third, grown].find((n) => decode(key) === `group/${hex(n)}`);
        state.saves.push({ group, value });
        if (group) state.records[group] = value;
        persist();
        return value;
      }
      if (symbol === 'mesh_messenger_group_create') { state.created += 1; persist(); return id(grown); }
      if (symbol === 'mesh_messenger_group_key_package') return devicePackage;
      if (symbol === 'mesh_messenger_group_invitations') {
        // Bob's invitation to the part he approved, until this device accepts it.
        return approved ? list(list(id(9), id(second), text('bob'), id(2), [state.accepted.length ? 2 : 1])) : list();
      }
      if (['mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request') return fields(request)[1];
      if (symbol === 'mesh_messenger_verify_transparency') return fields(request)[1];
      if (symbol === 'mesh_messenger_inspect_device_set') {
        const username = decode(fields(request)[1]);
        const n = Number(Object.keys(names).find((key) => names[key] === username) ?? 1);
        return vectors(text(names[n]), id(n), u64(1), [0], [1], list());
      }
      if (symbol === 'mesh_messenger_prepare_fanout_prekeys') return [];
      if (symbol === 'mesh_messenger_group_send') {
        const group = groupOf(request);
        const body = decode(fields(request)[2]);
        if (!body) return list(); // group presentation announcement
        state.sends.push({ group, body });
        (state.histories[group] ??= []).push(post(body, 40 + state.sends.length, 1));
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_group_add') {
        const parts = fields(request);
        state.adds.push({ group: parts[1][0], keyPackage: parts[3][0] });
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_group_remove') {
        const parts = fields(request);
        state.removes.push({ group: parts[1][0], account: parts[2][0] });
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_group_forget') {
        state.forgotten.push(groupOf(request));
        persist();
        return [];
      }
      if (symbol === 'mesh_messenger_group_invite') {
        state.invites.push({ group: fields(request)[3][0] });
        persist();
        return list();
      }
      if (symbol === 'mesh_messenger_journal_load' || symbol === 'mesh_messenger_journal_save') {
        const parts = fields(request);
        const label = `sealed-journal/${decode(parts[1])}`;
        if (symbol.endsWith('_load')) return text(localStorage.getItem(label) ?? '');
        if (parts[2].length === 1 && parts[2][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, decode(parts[2]));
        return [];
      }
      throw Error('Offline test boundary');
    } };
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const test = () => page.evaluate(() => window.communityTest);
  const community = page.getByRole('button', { name: /^Solana builders(?:,|$)/ });
  const openCommunity = async (query = '') => {
    await page.evaluate(() => sessionStorage.clear()).catch(() => {});
    await page.goto(`${url}${query}`);
    await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
    await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
    await community.press('Enter');
  };
  const details = () => page.getByRole('button', { name: 'Community details', exact: true }).first().click();

  // A member reads what the owner and admins post, cannot post, and asks to join a linked group.
  await openCommunity();
  await page.getByText('Mainnet upgrade on Friday', { exact: true }).waitFor();
  await page.getByText('AMA at 5pm', { exact: true }).waitFor();
  assert.equal(await page.getByText('gm, buy my token', { exact: true }).count(), 0, 'Only the owner and admins are heard');
  assert.equal(await page.getByText(/MORSE-/).count(), 0, 'Controls never show as posts');
  assert.equal(await page.getByPlaceholder('Only admins post here', { exact: true }).isEditable(), false);
  assert.match(await community.textContent(), /Community(?! ·)/, 'Members are not told how many are in it');
  if (shots) await page.screenshot({ path: `${shots}/member-thread.png` });
  await details();
  await page.getByText('Builders shipping on Solana.', { exact: true }).waitFor();
  await page.getByText('Owner', { exact: true }).waitFor();
  await page.getByText('Admin', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Send invitation', exact: true }).count(), 0, 'Members do not invite');
  assert.equal(await page.getByText('Members', { exact: true }).count(), 0, 'Members do not see each other');
  await page.getByText('Joined', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Ask to join Dev', exact: true }).click();
  await page.getByText('Requested', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/member-details.png` });
  assert.deepEqual((await test()).sends, [{ group: 83, body: `MORSE-JOIN/1\n${hex(82)}` }]);
  // Leaving asks the admins to remove this account, then forgets the community here.
  await page.getByRole('button', { name: 'Leave community', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Leave community', exact: true }).click();
  await community.waitFor({ state: 'detached' });
  assert.deepEqual((await test()).sends.at(-1), { group: 83, body: 'MORSE-LEAVE/1' });
  assert.deepEqual((await test()).forgotten, [83]);
  // Another device of the same account forgets it too once it hears the request.
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(`${url}?departed`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
  await page.waitForFunction(() => window.communityTest.forgotten.includes(83));
  await community.waitFor({ state: 'detached' });

  // Someone outside asks through a link Bob shared, and waits for him.
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(`${url}?outsider`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
  await page.getByRole('button', { name: 'Join a community', exact: true }).first().click();
  const link = `mesh://community/${Buffer.from(JSON.stringify([hex(80), 'bob', 'Solana builders'])).toString('base64url')}`;
  await page.getByLabel('Community link').fill('mesh://community/not-a-link');
  await page.getByRole('button', { name: 'Read link', exact: true }).click();
  await page.getByText('That isn’t a community link. Ask for the link again.', { exact: true }).waitFor();
  await page.getByLabel('Community link').fill(link);
  await page.getByRole('button', { name: 'Read link', exact: true }).click();
  await page.getByText('Community · shared by @bob', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/join-link.png` });
  await page.getByRole('button', { name: 'Ask to join', exact: true }).click();
  await page.getByText('Waiting for @bob to let you in.', { exact: true }).waitFor();
  assert.deepEqual((await test()).fanouts, [{ peer: 'bob', body: `MORSE-COMMUNITY-REQUEST/1\n${JSON.stringify([hex(80), 'Solana builders'])}` }]);
  if (shots) await page.screenshot({ path: `${shots}/join-waiting.png` });
  await page.getByRole('tab', { name: /^Chats(?:,|$)/ }).click();
  await page.getByText(/Asked to join Solana builders$/).first().waitFor();
  // A link someone shares in a chat is answered from its message.
  await page.getByRole('button', { name: /^Conversation with @dave(?:,|$)/ }).press('Enter');
  await page.getByText(/^Come build with us: mesh:\/\/community\//).last().click({ button: 'right' });
  await page.getByRole('dialog', { name: 'Message actions', exact: true }).getByRole('button', { name: 'Ask to join Solana builders', exact: true }).click();
  await page.getByText('Community · shared by @bob', { exact: true }).waitFor();
  // Once Bob lets her in, the invitation he sends is the one she asked for.
  await page.evaluate(() => sessionStorage.clear());
  await page.goto(`${url}?approved`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  await page.waitForFunction(() => window.communityTest.accepted.length === 1);
  assert.equal((await test()).accepted[0], 9, 'Bob’s invitation is accepted for her');
  await page.getByRole('tab', { name: /^Groups(?:,|$)/ }).click();
  await page.getByText('Accepted. Joining when @bob next connects.', { exact: true }).waitFor();
  await page.getByText('Solana builders', { exact: true }).first().waitFor();

  // The owner sees the parts as one community and keeps its admins' devices in every part.
  await openCommunity('?owner');
  assert.equal(await page.getByRole('button', { name: /^Solana builders(?:,|$)/ }).count(), 1, 'Parts are listed once');
  await page.getByRole('button', { name: '2 reactions: Thumbs up 2', exact: true }).waitFor();
  assert.equal(await page.getByText('Mainnet upgrade on Friday', { exact: true }).count(), 1, 'One post per announcement');
  await page.waitForFunction(() => window.communityTest.sends.some((send) => send.body.startsWith('MORSE-DEVICE/1\n')));
  const device = (await test()).sends.find((send) => send.body.startsWith('MORSE-DEVICE/1\n'));
  assert.equal(device.group, 80);
  assert.equal(device.body, `MORSE-DEVICE/1\n${hex(84)}\n${'07'.repeat(369)}`);
  await page.waitForFunction(() => window.communityTest.adds.length === 1);
  assert.deepEqual((await test()).adds, [{ group: 83, keyPackage: 10 }]);
  await page.waitForFunction(() => window.communityTest.sends.some((send) => send.body.startsWith('MORSE-LEFT/1\n')));
  assert.deepEqual((await test()).removes, [{ group: 80, account: 2 }]);
  assert.ok((await test()).sends.some((send) => send.group === 80 && send.body === `MORSE-LEFT/1\n${hex(2)}`));
  await page.getByText('2 people are waiting for you to let them in.', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/owner-thread.png` });
  await page.getByPlaceholder('Announce something', { exact: true }).fill('Hello everyone');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.communityTest.sends.filter((send) => send.body === 'Hello everyone').length === 2);
  assert.deepEqual((await test()).sends.filter((send) => send.body === 'Hello everyone').map((send) => send.group), [80, 83]);
  await page.getByRole('button', { name: 'Review requests', exact: true }).click();
  await page.getByText('Asked to join Trading', { exact: true }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/owner-details.png`, fullPage: true });
  await page.getByRole('button', { name: 'Invite @carol to Trading', exact: true }).click();
  await page.waitForFunction(() => window.communityTest.invites.length === 1);
  assert.equal((await test()).invites[0].group, 81);
  // Erin opened Alice's link: letting her in accepts her request, invites her and tells her where.
  await page.getByText('Asking to join', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Copy link', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Review @erin', exact: true }).click();
  await page.getByRole('dialog', { name: 'Review @erin' }).getByRole('button', { name: 'Let them in', exact: true }).click();
  await page.waitForFunction(() => window.communityTest.fanouts.some((item) => item.body.startsWith('MORSE-COMMUNITY-ANSWER/1\n')));
  const letIn = await test();
  assert.deepEqual(letIn.policies, [6], 'Her message request is accepted first');
  assert.equal(letIn.invites.at(-1).group, 80, 'She is invited to a part with room');
  assert.deepEqual(letIn.fanouts.at(-1), { peer: 'erin', body: `MORSE-COMMUNITY-ANSWER/1\n${JSON.stringify([hex(80), hex(80)])}` });
  await page.getByRole('button', { name: 'Review @erin', exact: true }).waitFor({ state: 'detached' });
  // Promoting someone rewrites every part's record with the new roles.
  const before = (await test()).saves.length;
  await page.getByRole('button', { name: 'Manage @carol', exact: true }).click();
  await page.getByRole('dialog', { name: 'Manage @carol' }).getByRole('button', { name: 'Make admin', exact: true }).click();
  await page.waitForFunction((count) => window.communityTest.saves.length >= count + 2, before);
  const promoted = (await test()).saves.slice(before);
  assert.deepEqual(promoted.map((save) => save.group).sort(), [80, 83]);
  for (const save of promoted) {
    const roles = save.value.slice(-96);
    assert.deepEqual([roles[0], roles[32], roles[64]], [1, 3, 5], 'Owner first, then admins in ascending order');
  }
  await page.getByRole('button', { name: 'Manage @carol', exact: true }).click();
  await page.getByRole('dialog', { name: 'Manage @carol' }).getByRole('button', { name: 'Make owner', exact: true }).waitFor();
  await page.keyboard.press('Escape');

  // A full community grows a part for the next member.
  await openCommunity('?owner&full');
  await details();
  await page.getByLabel('Exact username').fill('erin');
  await page.getByRole('button', { name: 'Send invitation', exact: true }).click();
  await page.waitForFunction(() => window.communityTest.invites.length === 1);
  const grown = await test();
  assert.equal(grown.created, 1);
  assert.equal(grown.invites[0].group, 90);
  const grownRecord = new TextDecoder().decode(new Uint8Array(grown.records[90]));
  assert.ok(grownRecord.includes(hex(90)) && new TextDecoder().decode(new Uint8Array(grown.records[80])).includes(hex(90)),
    'Every part lists the new one');
  await page.setViewportSize({ width: 720, height: 800 });
  await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  assert.deepEqual(errors, []);
  console.log('Communities: admin-only announcements across parts, merged reactions, hidden controls, requests, joining through links, promotion, device joins, leaving, growth and layout passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
