// Run against a fresh desktop web export. Only platform/native I/O is replaced.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
const dist = new URL(process.env.MORSE_ATTACHMENT_DIST || '../../desktop/dist/', import.meta.url);
const png = [...await readFile(new URL('../assets/adaptive-icon.png', import.meta.url))];
const availableScenarios = ['normal', 'group-held', 'group-rejected', 'group-metadata', 'direct-held', 'direct-rejected', 'community-held', 'community-rejected', 'offscreen-group-held', 'offscreen-direct-held', 'selected-preview-group'];
const scenarios = process.env.MORSE_EXPIRY_SCENARIO ? [process.env.MORSE_EXPIRY_SCENARIO] : availableScenarios;
assert.ok(scenarios.every(value => availableScenarios.includes(value)), 'Known expiry fixture scenario required');
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  for (const scenario of scenarios) {
  const community = scenario.startsWith('community-');
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(({ png, scenario }) => {
    const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = n => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(n)); return [...bytes]; };
    const text = value => [...new TextEncoder().encode(value)];
    const decode = value => new TextDecoder().decode(new Uint8Array(value));
    const id = (n, size = 32) => Array(size).fill(n);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const fields = bytes => { const out = []; let at = 0; while (at < bytes.length) { const size = new DataView(new Uint8Array(bytes.slice(at, at + 4)).buffer).getUint32(0); at += 4; out.push(bytes.slice(at, at + size)); at += size; } return out; };
    const album = (...refs) => { const rows = refs.map(ref => list([ref], id(ref === 3 ? 1 : ref), id(9), text(`photo-${ref}.png`), text('image/png'), u32(png.length), u32(1), u32(65536), u64(Date.now() + 86400000))); return rows.length === 1 ? rows[0] : [1, 65, 84, 66, ...u32(rows.length), ...vectors(...rows)]; };
    const state = window.cleanupTest = { groupStamp: Date.now(), directStamp: Date.now(), directActive: scenario === 'offscreen-direct-held', policy: 0, policyWrites: [], created: [], revoked: [], fetches: [], completed: [], pending: {}, saves: 0, phase: 'offscreen', scenario, getterWaiters: [], getterRejected: 0, metadataRejected: 0, getterSettled: 0 };
    const faultedHistory = async (kind, current, stale) => {
      if (state.phase === 'offscreen' && scenario === `offscreen-${kind}-held`) {
        await new Promise(resolve => state.getterWaiters.push(resolve));
        state.getterSettled++; return stale;
      }
      if (state.phase !== (kind === 'community' ? 'group' : kind)) return current;
      if (scenario === `${kind}-rejected`) { state.getterRejected++; throw Error('fixture_local_history_unavailable'); }
      if (scenario === `${kind}-held`) {
        await new Promise(resolve => state.getterWaiters.push(resolve));
        state.getterSettled++;
        return stale;
      }
      return current;
    };
    const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = blob => { const uri = create(blob); state.created.push(uri); return uri; };
    URL.revokeObjectURL = uri => { state.revoked.push(uri); revoke(uri); };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/cleanup.db';
      if (command === 'appearance') return 'dark';
      if (command === 'save_attachment') { state.saves++; return true; }
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return id(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
      if (symbol === 'mesh_messenger_directory_resolve') return [1];
      if (symbol === 'mesh_messenger_transparency_fork') return [];
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_list_conversations') return list(vectors(id(2, 16), text('alex'), id(2), id(2, 16), text('1234567890'.repeat(6)), [1], [0], [0], [0], u32(0)));
      if (['mesh_messenger_group_invitations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_group_list') return list(...[80,81].map(n => list([1], id(n), u64(1), u32(2))));
      if (symbol === 'mesh_messenger_presentation_load') {
        const key = decode(fields(Array.from(args))[1]);
        if (scenario.startsWith('community-') && key === `group/${'50'.repeat(32)}`) {
          return vectors(text('First files'), [], u64(1), text(JSON.stringify(['Expiry fixture', [], ['50'.repeat(32)]])), id(2));
        }
        return key.startsWith('group/') ? vectors(text(key.includes('50'.repeat(32)) ? 'First files' : 'Other files'), []) : [];
      }
      if (symbol === 'mesh_messenger_group_inspect') return list([1], fields(Array.from(args))[1], u64(1), u32(0), id(4), id(5), list(...[1,2].map(n => list([1], u32(n - 1), [n === 1 ? 1 : 0], id(n), id(n,16), u64(1), [2]))));
      if (symbol === 'mesh_messenger_group_policy') {
        const input = fields(Array.from(args));
        if (input.length === 2 && input[1][0] === 80 && scenario === 'group-metadata' && state.phase === 'group' && Date.now() >= state.groupStamp + 60000) {
          state.metadataRejected++; throw Error('fixture_local_policy_unavailable');
        }
        if (input.length === 2 && input[1][0] === 80 && scenario === 'selected-preview-group' && state.policyWrites.length) { state.metadataRejected++; throw Error('fixture_refresh_policy_unavailable'); }
        if (input.length === 3) { state.policy = new DataView(new Uint8Array(input[2]).buffer).getUint32(0); state.policyWrites.push(state.policy); }
        return list([1], input[1], u32(state.policy));
      }
      if (symbol === 'mesh_messenger_group_history') {
        const first = fields(Array.from(args))[1][0] === 80;
        const retained = list([1], [2], u64(1), id(2), id(2,16), u64(state.groupStamp - 1000), text('Group retained control'), [], id(102));
        const timed = list([2], [2], u64(1), id(2), id(2,16), u64(state.groupStamp), text('First group'), album(1,2), id(100), [0], u32(60));
        if (first && Date.now() >= state.groupStamp + 60000) return faultedHistory(scenario.startsWith('community-') ? 'community' : 'group', list(retained), list(retained, timed));
        return first ? list(retained, timed)
          : list(list([1], [2], u64(1), id(2), id(2,16), u64(Date.now()), text('Other group'), album(3), id(101)));
      }
      if (symbol === 'mesh_messenger_load_history') {
        const retained = vectors([2], id(7,16), u64(state.directStamp - 1000), text('Direct retained control'), u32(0), [], [0]);
        const timed = vectors([2], id(6,16), u64(state.directActive ? state.directStamp : Date.now()), text('Direct files'), u32(state.directActive ? 60 : 0), album(4,5), [0]);
        if (state.directActive && Date.now() >= state.directStamp + 60000) return faultedHistory('direct', list(retained), list(retained, timed));
        return list(retained, timed);
      }
      if (symbol === 'mesh_messenger_attachment_fetch_chunk') {
        const ref = fields(Array.from(args).slice(4))[1][0]; // counted request: database, reference, index
        state.fetches.push(ref);
        if ((ref === 2 || ref === 5) && state.fetches.filter(n => n === ref).length === 1) await new Promise(resolve => { state.pending[ref] = resolve; });
        state.completed.push(ref);
        return png;
      }
      if (['mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound'].includes(symbol)) {
        const parts = fields(Array.from(args)); const label = `sealed/${decode(parts[2])}`;
        if (symbol.includes('_load')) return text(localStorage.getItem(label) ?? '');
        if (parts[3].length === 1 && parts[3][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, decode(parts[3]));
        return [];
      }
      throw Error('Offline cleanup fixture boundary');
    } };
  }, { png, scenario });
  await page.clock.install();
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  const active = () => page.evaluate(() => window.cleanupTest.created.filter(uri => !window.cleanupTest.revoked.includes(uri)));
  const openGroup = async name => { await page.getByRole('tab', { name: /^Groups/ }).click(); await page.getByRole('button', { name: new RegExp(`^${name}`) }).click(); };
  const requireFault = async kind => {
    if (kind === 'group' && community) kind = 'community';
    if (scenario === `${kind}-held`) await page.waitForFunction(() => window.cleanupTest.getterWaiters.length > 0);
    if (scenario === `${kind}-rejected`) await page.waitForFunction(() => window.cleanupTest.getterRejected > 0);
    if (kind === 'group' && scenario === 'group-metadata') await page.waitForFunction(() => window.cleanupTest.metadataRejected > 0);
  };
  const releaseStaleGetter = async (kind, expired, retained) => {
    if (kind === 'group' && community) kind = 'community';
    if (scenario !== `${kind}-held`) return;
    await page.evaluate(() => window.cleanupTest.getterWaiters.splice(0).forEach(resolve => resolve()));
    await page.waitForFunction(() => window.cleanupTest.getterSettled > 0);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.getByText(expired, { exact: true }).count(), 0, 'Late stale native history must not repopulate an expired body');
    await page.getByText(retained, { exact: true }).last().waitFor();
    assert.deepEqual(await active(), [], 'Late stale native history must not restore expired previews');
  };

  if (scenario.startsWith('offscreen-')) {
    const group = scenario === 'offscreen-group-held';
    if (group) await page.getByRole('tab', { name: /^Groups/ }).click();
    const row = group ? page.getByRole('button', { name: /^First files/ })
      : page.getByRole('button', { name: /^Conversation with @?alex/ }).locator('..');
    const stale = group ? 'First group' : 'Direct files';
    const retained = group ? 'Group retained control' : 'Direct retained control';
    await row.waitFor(); assert.match(await row.innerText(), new RegExp(stale));
    // Leave browser timers paused after expiry: a zero-delay second cleanup
    // cannot mask stale publication by a held native read.
    await page.clock.pauseAt(await page.evaluate(() => Date.now() + 61000));
    await page.waitForFunction(() => window.cleanupTest.getterWaiters.length > 0, null, { polling: 10 });
    assert.doesNotMatch(await row.innerText(), new RegExp(stale), 'Offscreen cache hides expired text before I/O');
    await page.evaluate(() => window.cleanupTest.getterWaiters.splice(0).forEach(resolve => resolve()));
    await page.waitForFunction(() => window.cleanupTest.getterSettled > 0, null, { polling: 10 });
    // Driver-side wait allows React to commit without advancing browser timers.
    await page.waitForTimeout(100);
    assert.doesNotMatch(await row.innerText(), new RegExp(stale), 'Held offscreen completion must not briefly republish expired text');
    assert.match(await row.innerText(), new RegExp(retained), 'Untimed offscreen control survives late completion');
    if (group) assert.match(await page.getByRole('button', { name: /^Other files/ }).innerText(), /Other group/);
    assert.equal(await page.evaluate(() => window.cleanupTest.saves), 0);
    assert.deepEqual(errors, []);
    console.log(`Group expiry UI (${scenario}): paused-clock held offscreen completion cannot publish expired sidebar content; retained/unrelated controls passed`);
    await page.close(); continue;
  }

  // A never-opened group preview must also age while the list stays visible.
  await page.getByRole('tab', { name: /^Groups/ }).click();
  await page.getByRole('button', { name: /^First files/ }).waitFor();
  if (!community) assert.match(await page.getByRole('button', { name: /^First files/ }).innerText(), /First group/);
  await page.clock.fastForward(61000); await page.clock.resume();
  await page.waitForFunction(() => !Array.from(document.querySelectorAll('[role="button"]')).some(node => node.textContent?.startsWith('First files') && node.textContent?.includes('First group')));
  assert.match(await page.getByRole('button', { name: /^Other files/ }).innerText(), /Other group/);
  await page.evaluate(() => { window.cleanupTest.groupStamp = Date.now(); window.cleanupTest.phase = 'group'; });
  await openGroup('First files');
  await page.getByRole('button', { name: 'View photo-1.png', exact: true }).waitFor();
  await page.waitForFunction(() => window.cleanupTest.pending[2]);
  const first = await active(); assert.equal(first.length, 1);
  if (!community) {
  await page.getByRole('button', { name: 'Group details', exact: true }).click();
  await page.getByText('Applies to messages this device sends to this group. Other members choose their own timers.', { exact: true }).waitFor();
  await page.getByRole('radio', { name: 'Disappear: 1 minute', exact: true }).click();
  await page.waitForFunction(() => window.cleanupTest.policyWrites.includes(60));
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  }
  await page.getByText('First group', { exact: true }).last().waitFor();
  if (scenario === 'selected-preview-group') {
    await page.waitForFunction(() => window.cleanupTest.metadataRejected > 0);
    // Policy's ordinary refresh publishes a different sidebar array while
    // selected metadata fails. Pause at expiry to expose uncoupled cache refs.
    await page.clock.pauseAt(await page.evaluate(() => Date.now() + 61000));
    await page.getByText('First group', { exact: true }).last().waitFor({ state: 'detached', timeout: 2500 });
    await page.getByRole('tab', { name: /^Groups/ }).click();
    const row = page.getByRole('button', { name: /^First files/ });
    assert.doesNotMatch(await row.innerText(), /First group/, 'Selected sidebar refreshed into a distinct array must expire independently');
    assert.match(await row.innerText(), /Group retained control/);
    assert.deepEqual(errors, []);
    console.log(`Group expiry UI (${scenario}): actual policy-refresh sidebar array expires despite selected metadata rejection`);
    await page.close(); continue;
  }
  await page.clock.fastForward(61000); await page.clock.resume();
  await requireFault('group');
  await page.getByText('First group', { exact: true }).last().waitFor({ state: 'detached', timeout: 2500 });
  await page.getByText('Group retained control', { exact: true }).last().waitFor();
  assert.deepEqual(await active(), [], 'Already-visible group expiry must release previews without navigation or sync');
  await page.evaluate(() => window.cleanupTest.pending[2]());
  await page.waitForFunction(() => window.cleanupTest.completed.includes(2));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.deepEqual(await active(), [], 'Late expired group fetch cannot recreate a preview');
  await releaseStaleGetter('group', 'First group', 'Group retained control');
  await openGroup('Other files');
  await page.getByRole('button', { name: 'View photo-3.png', exact: true }).waitFor();
  assert.equal((await active()).length, 1, 'Permanent unrelated group stays visible');
  await page.evaluate(() => { window.cleanupTest.directActive = true; window.cleanupTest.directStamp = Date.now(); window.cleanupTest.phase = 'direct'; });
  await page.getByRole('tab', { name: /^Chats/ }).click();
  await page.getByRole('button', { name: /^Conversation with @?alex/ }).locator('..').click();
  await page.getByRole('button', { name: 'View photo-4.png', exact: true }).waitFor();
  await page.waitForFunction(() => window.cleanupTest.pending[5]);
  assert.equal((await active()).length, 1);
  await page.clock.fastForward(61000); await page.clock.resume();
  await requireFault('direct');
  await page.getByText('Direct files', { exact: true }).last().waitFor({ state: 'detached', timeout: 2500 });
  await page.getByText('Direct retained control', { exact: true }).last().waitFor();
  assert.deepEqual(await active(), [], 'Already-visible direct expiry must release previews without navigation or sync');
  await page.evaluate(() => window.cleanupTest.pending[5]());
  await page.waitForFunction(() => window.cleanupTest.completed.includes(5));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.deepEqual(await active(), [], 'Late expired direct fetch cannot recreate a preview');
  await releaseStaleGetter('direct', 'Direct files', 'Direct retained control');
  assert.equal(await page.evaluate(() => window.cleanupTest.saves), 0);
  assert.deepEqual(errors, []);
  console.log(`Group expiry UI (${scenario}): explicit device-local timer, visible group/direct expiry, retained/untimed controls, pre-I/O preview release, late getter/fetch refusal and unrelated permanent group passed`);
  await page.close();
  }
} finally { await browser?.close(); server.close(); }
