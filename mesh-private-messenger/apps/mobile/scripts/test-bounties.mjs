// Actual Settings/navigation and scoped bounty services. Custody, native approval,
// signatures, packet banking and RPC results are fixtures, not native proof.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const dist = process.env.MORSE_BOUNTY_DIST
  ? pathToFileURL(resolve(process.env.MORSE_BOUNTY_DIST) + '/')
  : new URL('../../desktop/dist/', import.meta.url);
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
  const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(8000);
  const errors = [], prompts = [], externalRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('dialog', async dialog => { prompts.push(dialog.message()); await dialog.accept(); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    externalRequests.push(route.request().url()); return route.abort();
  });
  await page.addInitScript(() => {
    const text = s => [...new TextEncoder().encode(s)], decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    const id = (n, size = 32) => Array(size).fill(n);
    const same = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);
    const u32 = n => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = n => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, BigInt(n)); return [...bytes]; };
    const vectors = (...parts) => parts.flatMap(p => [...u32(p.length), ...p]);
    const list = (...parts) => vectors(u32(parts.length), ...parts);
    const packet = (...parts) => [...u32(parts.length), ...vectors(...parts)];
    const address = bytes => {
      const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      let value = 0n, result = '';
      for (const n of bytes) value = value * 256n + BigInt(n);
      while (value > 0n) { result = alphabet[Number(value % 58n)] + result; value /= 58n; }
      for (const n of bytes) { if (n) break; result = '1' + result; }
      return result;
    };
    const terms = asset => ({ asset, mint: asset === 'legacy' ? 5 : asset === 'usdc' ? 11 : 12,
      units: asset === 'legacy' ? '18446744073709551615' : asset === 'usdc' ? '1234567' : '9876543210',
      decimals: asset === 'morse' ? 9 : 6, availability: 2, attempt: null });
    const attempt = (asset, status, identity = asset === 'legacy' ? 7 : asset === 'usdc' ? 21 : 31) => ({
      identity, status, destination: id(asset === 'morse' ? 8 : 6), signature: id(identity + 40, 64),
    });
    let saved = JSON.parse(localStorage.getItem('bounty-proof-v2') || 'null') ?? {
      enabled: false, selection: 0, created: false, route: 0,
      usdc: terms('usdc'), morse: terms('morse'), legacy: terms('legacy'), events: [],
    };
    const persist = () => localStorage.setItem('bounty-proof-v2', JSON.stringify(saved));
    const state = window.bountyTest = { calls: [], wallet: [], rejected: [], outcome: {},
      destinations: { legacy: address(id(6)), usdc: address(id(6)), morse: address(id(8)) },
      saved: () => structuredClone(saved),
      seed(scenario) {
        const usdc = terms('usdc'), morse = terms('morse'), legacy = terms('legacy');
        let route = 2;
        if (scenario === 'unavailable') route = 0;
        else if (scenario === 'zero') Object.assign(morse, { availability: 1, units: '0' });
        else if (scenario === 'reverse') {
          usdc.attempt = attempt('usdc', 2); morse.attempt = attempt('morse', 4);
        } else if (scenario === 'base-units') Object.assign(morse, { units: '9007199254740993', decimals: 255 });
        else if (scenario === 'legacy') { route = 1; legacy.attempt = attempt('legacy', 1); }
        else if (scenario !== 'ready') throw Error('unknown_fixture_scenario');
        saved = { ...saved, selection: 3, route, usdc, morse, legacy }; state.outcome = {}; persist();
      },
    };
    const replace = (asset, next) => { saved = { ...saved, [asset]: next }; persist(); };
    const event = value => { saved = { ...saved, events: [...saved.events, value] }; persist(); };
    const selection = () => packet(text('\u0001BFP'), [saved.enabled ? 1 : 0], [saved.selection],
      saved.selection === 0 ? [] : id(7), saved.selection < 2 ? [] : saved.selection === 3 ? id(4) : id(0), u64(0));
    const movement = leg => {
      const value = leg.attempt;
      return packet(text('\u0001BMW'), id(value.identity), [value.status], value.status >= 2 ? value.signature : [],
        id(4), value.destination, id(leg.mint), u64(leg.units), [leg.decimals], u64(value.status >= 4 ? 5000 : 0),
        u64(value.status >= 4 ? '9007199254740993' : 0), text(value.status === 5 ? 'InstructionError' : ''));
    };
    const legFrame = leg => packet(text('\u0002BML'), [leg.asset === 'usdc' ? 1 : 2], [leg.attempt ? 3 : leg.availability],
      id(leg.mint), u64(leg.units), [leg.decimals], leg.attempt ? movement(leg) : []);
    const aggregate = () => packet(text('\u0002BMW'), [saved.route], text(saved.route === 0 ? 'awaiting_settlement' : ''),
      saved.route === 1 ? movement(saved.legacy) : [], saved.route === 2 ? legFrame(saved.usdc) : [], saved.route === 2 ? legFrame(saved.morse) : []);
    state.frame = asset => asset === 'legacy' ? movement(saved.legacy) : legFrame(saved[asset]);
    // Decode actual count-first IPC bytes, without arbitrary-tag/legacy fallback.
    const request = (input, kind) => {
      try {
        const bytes = new Uint8Array(input), view = new DataView(bytes.buffer);
        const count = kind === 'read' ? 2 : 4;
        if (bytes.length > 5500 || bytes.length < 4 || view.getUint32(0) !== count) throw Error('field_count');
        let at = 4; const fields = [];
        for (let i = 0; i < count; i++) {
          if (at + 4 > bytes.length) throw Error('field_length');
          const length = view.getUint32(at); at += 4;
          if (length > bytes.length - at) throw Error('field_bounds');
          fields.push([...bytes.slice(at, at + length)]); at += length;
        }
        if (at !== bytes.length || !same(fields[0], text('\u0002BMR')) || decode(fields[1]) !== '/test/bounty.db') throw Error('tag_or_database');
        const database = decode(fields[1]);
        if (kind === 'read') { event({ kind, database }); return {}; }
        if (fields[2].length !== 1 || fields[2][0] > 2 || fields[3].length !== 32 || !fields[3].some(Boolean)) throw Error('selector');
        const asset = ['legacy', 'usdc', 'morse'][fields[2][0]];
        if ((asset === 'legacy') !== (saved.route === 1) || saved.route === 0) throw Error('route');
        event({ kind, database, asset, bytes: fields[3] });
        return { asset, bytes: fields[3] };
      } catch (error) {
        state.rejected.push(String(error)); event({ kind: 'rejected', error: String(error) });
        throw Error('invalid_fixture_bounty_request:' + error);
      }
    };
    const tokenAmount = leg => { const value = leg.units.padStart(leg.decimals + 1, '0'); return leg.decimals ? value.slice(0, -leg.decimals) + '.' + value.slice(-leg.decimals) : value; };
    const move = input => {
      const { asset, bytes } = request(input, 'move'), leg = saved[asset];
      if (leg.availability !== 2 || leg.decimals === 255 || [2, 3, 4].includes(leg.attempt?.status)) throw Error('must_recover_exact_saved_packet');
      if (!window.confirm('Move fork bounty: ' + asset.toUpperCase() + '\nThis transfer is public and links the one-time bounty address to the destination and fee-paying wallet.\nNetwork fees and any destination token-account rent are additional.\nAmount: ' + tokenAmount(leg) + ' tokens\nMint: ' + address(id(leg.mint)) + '\nDestination: ' + address(bytes))) throw Error('wallet_native_error_4');
      const next = leg.attempt?.status === 1 ? leg.attempt : attempt(asset, 2, (leg.attempt?.identity ?? (asset === 'legacy' ? 6 : asset === 'usdc' ? 20 : 30)) + 1);
      replace(asset, { ...leg, attempt: { ...next, status: 2, destination: [...bytes] } });
      return aggregate();
    };
    const observe = (input, kind) => {
      const { asset, bytes } = request(input, kind), leg = saved[asset];
      if (!leg.attempt || !same(bytes, id(leg.attempt.identity))) throw Error('wrong_saved_identity');
      if (kind === 'cancel' ? leg.attempt.status !== 1 : ![2, 3].includes(leg.attempt.status)) throw Error('wrong_saved_phase');
      replace(asset, { ...leg, attempt: { ...leg.attempt, status: kind === 'cancel' ? 0 : state.outcome[asset] ?? leg.attempt.status } });
      return aggregate();
    };
    window.isTauri = true;
    // Mocked current startup boundary; this does not qualify desktop owner auth.
    const owner = '00000000-0000-4000-8000-000000000001';
    window.__MORSE_DOCUMENT__ = owner;
    const lockSnapshot = () => ({ version: 1, owner, revision: '1', state: { epoch: owner + '/1', policy: 'disabled', phase: 'activated', capability: 'unavailable', foreground: true } });
    window.__TAURI_INTERNALS__ = { metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback() {},
      invoke: async (command, args, options) => {
        if (command === 'app_lock_bind' || command === 'app_lock_state') return lockSnapshot();
        if (['app_lock_check', 'app_lock_release', 'app_lock_activate', 'app_lock_copy_text', 'app_lock_close_mailbox', 'app_lock_window_action'].includes(command)) return null;
        if (command === 'app_lock_legacy_preference') return null;
        if (command === 'app_lock_notification_binding') return 'disabled';
        if (command === 'app_lock_take_notice_intent') return { version: 1, kind: 'none' };
        if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
        if (command === 'database_path') return '/test/bounty.db';
        if (command === 'appearance') return 'dark';
        if (command === 'mailbox_connect' || command === 'mailbox_disconnect') return;
        if (command === 'binary_request') throw Error('Offline fixture');
        if (command === 'wallet_invoke') {
          const operation = Number(options.headers['X-Wallet-Operation']); state.wallet.push(operation);
          if (operation === 1) {
            if (!window.confirm('Create device-local wallet. There is no seed export or recovery option.')) throw Error('wallet_native_error_4');
            saved = { ...saved, created: true }; persist(); return id(2);
          }
          if (operation === 2) { if (!saved.created) throw Error('wallet_native_error_2'); return id(2); }
          if (operation === 7) {
            if (args[0] === 1 && !saved.created) throw Error('wallet_native_error_2');
            saved = { ...saved, enabled: args[0] === 1 }; persist(); return selection();
          }
          if (operation === 8) return move(args);
          throw Error('private SDK operation exposed');
        }
        const symbol = options?.headers?.['X-Mesh-Symbol']; state.calls.push(symbol);
        if (symbol === 'mesh_messenger_bounty_status') {
          if (decode(args) !== '/test/bounty.db') {
            state.rejected.push('wrong_selection_database:' + decode(args));
            event({ kind: 'rejected', error: 'wrong_selection_database:' + decode(args) });
            throw Error('wrong_selection_database');
          }
          event({ kind: 'selection', database: decode(args) });
          return selection();
        }
        if (symbol === 'mesh_messenger_bounty_transfer_status') { request(args, 'read'); return aggregate(); }
        if (symbol === 'mesh_messenger_bounty_transfer_recover') return observe(args, 'recover');
        if (symbol === 'mesh_messenger_bounty_transfer_cancel') return observe(args, 'cancel');
        if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
        if (symbol === 'mesh_messenger_mailbox_stream_open') return id(1);
        if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
        if (symbol === 'mesh_messenger_directory_resolve') return [1];
        if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
        if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
        if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1,16), []);
        if (symbol === 'mesh_messenger_signup_draft_state') return [0];
        if (symbol === 'mesh_messenger_credit_signup_policy' || symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
        if (symbol === 'mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
        if (['mesh_messenger_group_list','mesh_messenger_group_invitations','mesh_messenger_list_conversations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol)) return list();
        if (symbol === 'mesh_messenger_presentation_load') return vectors(text('Alice'), []);
        if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
        if (['mesh_messenger_journal_load','mesh_messenger_journal_save','mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound','mesh_messenger_transparency_fork','mesh_messenger_register_request','mesh_messenger_mailbox_fetch'].includes(symbol)) return [];
        throw Error('Unexpected IPC ' + symbol);
      },
    };
  });
  const button = name => page.getByRole('button', { name, exact: true });
  const visible = text => page.getByText(text, { exact: true }).first().waitFor();
  const open = async () => {
    await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
    await button('Settings').click(); await page.getByRole('button', { name: /^Fork bounties/ }).click();
  };
  const refresh = async () => {
    await button('Refresh bounty custody').click();
    await page.waitForFunction(() => [...document.querySelectorAll('[role="button"]')].some(n => n.textContent === 'Refresh bounty custody' && n.getAttribute('aria-disabled') !== 'true'));
  };
  const seed = async scenario => { await page.evaluate(s => window.bountyTest.seed(s), scenario); await refresh(); };
  const frame = asset => page.evaluate(asset => window.bountyTest.frame(asset), asset);
  const moves = () => page.evaluate(() => window.bountyTest.saved().events.filter(e => e.kind === 'move').map(e => e.asset));
  const destination = asset => page.evaluate(asset => window.bountyTest.destinations[asset], asset);
  const review = async asset => {
    const label = asset === 'legacy' ? 'Destination Solana address' : asset.toUpperCase() + ' destination Solana address';
    await page.getByLabel(label, { exact: true }).fill(await destination(asset));
    await button(asset === 'legacy' ? 'Review bounty transfer' : `Review ${asset.toUpperCase()} transfer`).click();
  };
  const recover = async (asset, outcome) => {
    await page.evaluate(({ asset, outcome }) => { window.bountyTest.outcome[asset] = outcome; }, { asset, outcome });
    await button(asset === 'legacy' ? 'Recover saved transfer' : `Recover ${asset.toUpperCase()} transfer`).click();
  };
  await page.goto(origin); await open();
  await visible('No retained fork proof on this device.');
  assert.equal(await button('Review bounty transfer').count(), 0);
  await button('Create in-app wallet').click();
  await page.getByRole('switch', { name: 'Collect fork bounties', exact: true }).click();
  assert.equal(await page.evaluate(() => window.bountyTest.saved().enabled), true);
  assert.deepEqual(await moves(), []);

  await seed('unavailable'); await visible('Awaiting settlement');
  assert.equal(await page.getByText('Amount unavailable', { exact: true }).count(), 2);
  assert.equal(await page.getByText('No bounty in this asset', { exact: true }).count(), 0);
  await seed('zero'); await visible('No bounty in this asset'); await visible('1.234567 USDC');
  assert.equal(await button('Review MORSE transfer').count(), 0);
  await seed('ready'); await visible('1.234567 USDC'); await visible('9.876543210 MORSE');
  const initialMorse = await frame('morse'), promptStart = prompts.length;
  await page.getByLabel('USDC destination Solana address', { exact: true }).fill('1'.repeat(32));
  await button('Review USDC transfer').click();
  await visible('Enter a complete, canonical Solana destination address.');
  assert.deepEqual(await moves(), []); assert.equal(prompts.length, promptStart);
  await review('usdc'); await visible('Outcome unknown');
  assert.deepEqual(await moves(), ['usdc']); assert.deepEqual(await frame('morse'), initialMorse);
  const usdcPrompt = prompts.at(-1);
  assert.ok(usdcPrompt.includes('USDC') && usdcPrompt.includes('1.234567') && usdcPrompt.includes('Mint:') && usdcPrompt.includes(await destination('usdc')));
  assert.ok(usdcPrompt.includes('links the one-time bounty address') && usdcPrompt.includes('rent are additional'));
  await recover('usdc', 4); await visible('Transfer finalized');
  assert.equal(await button('Review USDC transfer').count(), 0);
  assert.deepEqual(await frame('morse'), initialMorse);
  const completeUsdc = await frame('usdc');
  await review('morse'); await visible('Outcome unknown');
  assert.deepEqual(await moves(), ['usdc', 'morse']); assert.deepEqual(await frame('usdc'), completeUsdc);
  assert.ok(prompts.at(-1).includes('MORSE') && prompts.at(-1).includes('9.876543210'));
  const unknownMorse = await frame('morse'), beforeRestart = prompts.length;
  await page.reload(); await open(); await visible('Outcome unknown'); await visible('Transfer finalized');
  assert.deepEqual(await frame('usdc'), completeUsdc); assert.deepEqual(await frame('morse'), unknownMorse);
  assert.equal(prompts.length, beforeRestart); assert.deepEqual(await moves(), ['usdc', 'morse']);
  assert.equal(await button('Review MORSE transfer').count(), 0);
  await refresh(); await recover('morse', 2); await visible('Outcome unknown');
  assert.deepEqual(await frame('morse'), unknownMorse); assert.deepEqual(await frame('usdc'), completeUsdc);
  assert.equal(prompts.length, beforeRestart); assert.deepEqual(await moves(), ['usdc', 'morse']);
  await recover('morse', 5); await visible('Transaction finalized with a failure. Fees may still have been charged.');
  await visible('Finalized slot: 9007199254740993 · Fee: 5000 lamports');
  await page.getByLabel('MORSE destination Solana address', { exact: true }).fill(await destination('morse'));
  await button('Explicitly retry failed MORSE transfer').click(); await visible('Outcome unknown');
  assert.equal(prompts.length, beforeRestart + 1); assert.deepEqual(await moves(), ['usdc', 'morse', 'morse']);
  assert.notDeepEqual(await frame('morse'), unknownMorse); assert.deepEqual(await frame('usdc'), completeUsdc);
  await recover('morse', 4);
  await page.waitForFunction(() => [...document.querySelectorAll('*')].filter(n => n.childElementCount === 0 && n.textContent === 'Transfer finalized').length === 2);
  const signatures = await page.evaluate(() => [...document.querySelectorAll('*')].filter(n => n.childElementCount === 0 && n.textContent?.startsWith('Signature: ')).map(n => n.textContent));
  assert.equal(new Set(signatures).size, 2);
  assert.equal(await button('Review MORSE transfer').count(), 0);
  console.log('PASS mixed: unequal units, zero/unavailable, scoped one-leg moves, USDC finalized/MORSE unknown restart, observation without prompts, MORSE failure and explicit new-prompt retry');

  await seed('reverse'); const completeMorse = await frame('morse'), reversePrompts = prompts.length;
  await page.reload(); await open(); await visible('Outcome unknown'); await visible('Transfer finalized');
  await recover('usdc', 5); await visible('Transaction finalized with a failure. Fees may still have been charged.');
  assert.equal(prompts.length, reversePrompts); assert.deepEqual(await frame('morse'), completeMorse);
  await page.getByLabel('USDC destination Solana address', { exact: true }).fill(await destination('usdc'));
  await button('Explicitly retry failed USDC transfer').click(); await visible('Outcome unknown');
  assert.equal(prompts.length, reversePrompts + 1); assert.deepEqual(await moves(), ['usdc', 'morse', 'morse', 'usdc']);
  await recover('usdc', 4); assert.deepEqual(await frame('morse'), completeMorse);
  await seed('base-units'); await visible('9007199254740993 base units');
  console.log('PASS reverse: MORSE finalized survives USDC failure/retry; unknown decimals retain exact base units');

  // Separate legacy 02BMW route retains its original 01BMW token and labels.
  await seed('legacy'); await visible('Unsigned transfer saved');
  await visible('MORSE is not part of this receipt. The saved legacy transfer keeps its original token.');
  assert.equal(await button('Review MORSE transfer').count(), 0);
  await button('Cancel unsigned transfer').click(); await visible('Unsigned transfer cancelled');
  await review('legacy'); await visible('Signed transfer; outcome unknown');
  assert.ok(prompts.at(-1).includes('18446744073709.551615'));
  const legacyPrompts = prompts.length;
  await page.reload(); await open(); await visible('Signed transfer; outcome unknown');
  await recover('legacy', 2); await visible('Signed transfer; outcome unknown');
  assert.equal(prompts.length, legacyPrompts);
  await recover('legacy', 5); await visible('Transaction finalized with a failure. Fees may still have been charged.');
  await page.getByLabel('Destination Solana address', { exact: true }).fill(await destination('legacy'));
  await button('Explicitly retry failed transfer').click(); await visible('Signed transfer; outcome unknown');
  assert.equal(prompts.length, legacyPrompts + 1);
  await recover('legacy', 4); await visible('Bounty transfer finalized');
  assert.equal(await button('Review bounty transfer').count(), 0);
  assert.deepEqual(await moves(), ['usdc', 'morse', 'morse', 'usdc', 'legacy', 'legacy']);
  console.log('PASS legacy: original token/labels, scoped unsigned cancellation, U64 precision, unknown restart, failure/retry and terminal success');
  if (process.env.MORSE_BOUNTY_SCREENSHOTS) {
    await mkdir(process.env.MORSE_BOUNTY_SCREENSHOTS, { recursive: true });
    await page.screenshot({ path: process.env.MORSE_BOUNTY_SCREENSHOTS + '/finalized.png' });
  }
  await page.evaluate(() => {
    const value = JSON.parse(localStorage.getItem('bounty-proof-v2'));
    localStorage.setItem('bounty-proof-v2', JSON.stringify({ ...value, selection: 4, created: false }));
  });
  await page.reload(); await open();
  await visible('Wallet custody was unavailable at detection. The proof can still be filed without a wallet finder.');
  await page.getByRole('switch', { name: 'Collect fork bounties', exact: true }).click();
  assert.equal(await page.evaluate(() => window.bountyTest.saved().enabled), false);
  assert.deepEqual(await page.evaluate(() => window.bountyTest.rejected), []);
  const events = await page.evaluate(() => window.bountyTest.saved().events);
  assert.equal(events.filter(event => event.kind === 'rejected').length, 0);
  assert.ok(events.every(event => event.database === '/test/bounty.db'), 'every bounty IPC carries the scoped database, across reloads');
  assert.equal(await page.evaluate(() => window.bountyTest.calls.filter(x => x?.startsWith('mesh_messenger_credit_') && x !== 'mesh_messenger_credit_signup_policy').length), 0);
  await page.setViewportSize({ width: 720, height: 900 });
  await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
  assert.deepEqual(errors, []); assert.deepEqual(externalRequests, []);
  if (process.env.MORSE_BOUNTY_EVIDENCE) {
    await writeFile(process.env.MORSE_BOUNTY_EVIDENCE, JSON.stringify({ events, prompts, errors, externalRequests }, null, 2) + '\n');
  }
  console.log('PASS browser bounty fixture: actual Settings/navigation + BountyPanel/services; mocked custody/native approval/signatures/RPC, no native owner or release claim');
} catch (error) {
  for (const context of browser?.contexts() ?? []) for (const page of context.pages()) {
    console.error('Bounty browser failure:', await page.evaluate(() => ({
      body: document.body.innerText, saved: window.bountyTest?.saved(), rejected: window.bountyTest?.rejected,
    })).catch(() => 'page unavailable'));
  }
  throw error;
} finally { await browser?.close(); server.close(); }
