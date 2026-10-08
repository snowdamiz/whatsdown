// Run after npm run web --prefix ../desktop (or point MORSE_WALLET_DIST at an export).
// Settings -> Wallet and Network -> Collect fork bounties in the real UI; only native IPC
// (the Mesh core, the wallet host) and the pinned RPC provider are replaced.
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const dist = new URL(process.env.MORSE_WALLET_DIST || '../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}`;
const screenshots = process.env.MORSE_WALLET_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });

const RPC = 'https://rpc.test/solana';
const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

async function open(scheme = 'dark') {
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 }, colorScheme: scheme, reducedMotion: 'reduce' });
  page.on('pageerror', (error) => { throw error; });
  await page.addInitScript(({ scheme, RPC, PHRASE }) => {
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const id = (n, length = 32) => Array(length).fill(n);
    const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const base58 = (bytes) => {
      let value = 0n; for (const byte of bytes) value = value * 256n + BigInt(byte);
      let out = ''; while (value > 0n) { out = alphabet[Number(value % 58n)] + out; value /= 58n; }
      for (const byte of bytes) { if (byte) break; out = `1${out}`; }
      return out;
    };
    // The wallet host: one account key and a bounty key per issued index.
    const keyOf = (kind, index) => id(kind === 1 ? 0xa0 : 0xb0 + index);
    const wallet = window.walletTest = { exists: false, issued: 0, transfers: [], sent: [] };
    const account = base58(keyOf(1, 0));
    // The chain: the account holds a little SOL, bounty 0 got a payout.
    const tokenAccount = base58(id(0xc0));
    const rpc = (method, params) => {
      const bountyZero = base58(keyOf(2, 0));
      if (method === 'getBalance') return { value: params[0] === account ? 2_500_000 : 0 };
      if (method === 'getTokenAccountsByOwner') {
        // Moving the bounty out empties its token account, which stays.
        const held = params[0] === bountyZero ? (wallet.sent.length ? '0' : '1250000000') : params[0] === account ? '0' : null;
        return { value: held === null ? [] : [{ pubkey: tokenAccount, account: { data: { parsed: { info: { tokenAmount: { amount: held } } } } } }] };
      }
      if (method === 'getGenesisHash') return '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
      if (method === 'getLatestBlockhash') return { value: { blockhash: base58(id(3)), lastValidBlockHeight: 99 } };
      if (method === 'sendTransaction') { wallet.sent.push(params[0]); return 'payoutsig'; }
      if (method === 'getSignatureStatuses') return { value: [{ err: null, confirmationStatus: 'finalized' }] };
      if (method === 'getSignaturesForAddress') return [{ signature: 'payoutsig', err: null }];
      if (method === 'getTransaction') return {
        transaction: { message: { accountKeys: [{ pubkey: tokenAccount }] } },
        meta: { preTokenBalances: [], postTokenBalances: [{ accountIndex: 0, uiTokenAmount: { amount: '1250000000' } }] },
      };
      throw Error(`unexpected ${method}`);
    };
    // The trust-alarm details: one filed proof that named bounty 0, landed and paid it.
    const frk = [1, ...text('FRK'), 2, ...keyOf(2, 0), ...id(0, 300)];
    const proof = [...vectors(frk), ...id(9), 1, 1, ...keyOf(2, 0), ...u64(7), 1, ...vectors(text('https://relay-a.test')), 1, ...id(9)];
    const summary = [1, ...u64(3), ...u64(10), ...id(5)];
    const alarm = [1, 1, ...u64(Date.now() - 60_000), ...summary, ...summary, 1, ...vectors(proof)];
    const details = [1, ...text('TAD'), 1, ...vectors(alarm)];
    const status = [1, ...text('NST'), ...vectors(text('bootstrap')), 2, 2, 2, ...id(7),
      ...vectors(text('witness-a')), ...vectors(text('Morse')), 1, ...vectors(text('witness-b')), ...vectors(text('Morse')), 1, 0];
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return scheme;
      if (command === 'wallet_exists') return wallet.exists;
      if (command === 'wallet_create') { wallet.exists = true; return PHRASE; }
      if (command === 'wallet_bounty_index') { wallet.issued = Math.max(wallet.issued, args.atLeast); return wallet.issued; }
      if (command === 'wallet_next_bounty_address') { wallet.issued += 1; return new Uint8Array([...u32(wallet.issued - 1), ...keyOf(2, wallet.issued - 1)]).buffer; }
      if (command === 'wallet_call') {
        const op = Number(options.headers['X-Wallet-Op']);
        const body = Array.from(args);
        if (op === 4) {
          if (body[0] === 2 && body[4] >= wallet.issued) throw Error('bounty_not_issued');
          return new Uint8Array(keyOf(body[0], body[4])).buffer;
        }
        if (op === 5) { wallet.transfers.push(body); return new Uint8Array(vectors(text('payoutsig'), text('dHg='))).buffer; }
        throw Error('bad_op');
      }
      // Two pinned providers, both on mainnet (the wallet's USDC follows the chain).
      if (command === 'binary_request' && options?.headers?.['X-Service-Url']?.startsWith(RPC)) {
        const request = JSON.parse(new TextDecoder().decode(new Uint8Array(args)));
        return [0, 200, ...text(JSON.stringify({ jsonrpc: '2.0', id: 1, result: rpc(request.method, request.params) }))];
      }
      if (command === 'binary_request' && options?.headers?.['X-Service-Url']?.endsWith('/v1/devices/resolve')) return [0, 200, 1];
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_wallet_rpc_urls') return [1, 2, ...vectors(text(RPC)), ...vectors(text(`${RPC}/2`))];
      if (symbol === 'mesh_messenger_trust_alarm_details') return details;
      if (symbol === 'mesh_messenger_network_status') return status;
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text('alice'), id(1), u64(1), [0], [1], list(vectors(id(1, 16), [1], [1])));
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request' || symbol === 'mesh_messenger_verify_transparency') return [1];
      if (['mesh_messenger_list_conversations', 'mesh_messenger_load_history', 'mesh_messenger_group_invitations',
        'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page', 'mesh_messenger_group_list'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_presentation_load') return [];
      // The sealed journals, kept where a reload leaves them alone, as the database would.
      if (symbol === 'mesh_messenger_journal_load' || symbol === 'mesh_messenger_journal_save') {
        const bytes = Array.from(args), parts = [];
        for (let at = 0; at < bytes.length;) {
          const size = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
          parts.push(new Uint8Array(bytes.slice(at + 4, at + 4 + size)));
          at += 4 + size;
        }
        const label = `sealed-journal/${new TextDecoder().decode(parts[1])}`;
        if (symbol.endsWith('_load')) return [...new TextEncoder().encode(localStorage.getItem(label) ?? '')];
        if (parts[2].length === 1 && parts[2][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, new TextDecoder().decode(parts[2]));
        return [];
      }
      throw Error('Offline test boundary');
    } };
  }, { scheme, RPC, PHRASE });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}

const shot = async (page, name) => { if (screenshots) await page.screenshot({ path: `${screenshots}/${name}.png` }); };

try {
  const page = await open();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: /^Wallet/ }).click();
  await page.getByRole('button', { name: 'Create a wallet', exact: true }).click();
  // The phrase is shown once, then two of its words are typed back.
  const words = PHRASE.split(' ');
  await page.getByText(`1. ${words[0]}`, { exact: true }).waitFor();
  await shot(page, 'wallet-phrase');
  await page.getByRole('button', { name: 'I wrote them down', exact: true }).click();
  const confirm = page.getByRole('button', { name: 'Confirm', exact: true });
  const asked = await page.getByText(/^Word \d+$/).allTextContents();
  assert.equal(asked.length, 2);
  assert.equal(await confirm.isEnabled(), false, 'Confirm waits for the words');
  for (const label of asked) await page.getByLabel(label, { exact: true }).fill(words[Number(label.slice(5)) - 1]);
  await confirm.click();
  // D13: offered once, when the wallet is set up.
  await page.getByText('Collect fork bounties?', { exact: true }).waitFor();
  await shot(page, 'wallet-offer');
  await page.getByRole('button', { name: 'Turn on', exact: true }).click();
  await page.getByText('0.0025 SOL · 0 USDC', { exact: true }).waitFor();
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('sealed-journal/wallet/settings')));
  assert.deepEqual([saved.collectBounties, saved.bountiesOffered], [true, true]);

  // The Phase 4 notice: the proof named bounty 0 and the bounty landed there.
  await page.evaluate(() => { window.walletTest.issued = 1; });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('button', { name: /^Wallet/ }).click();
  await page.getByText(/the bounty landed in your wallet: 1,250 USDC\.$/).waitFor();
  await page.getByText('1,250 USDC', { exact: true }).waitFor();
  await shot(page, 'wallet-ready');

  // A move says first that it is public, and signs with the bounty key, account 0 paying.
  await page.getByRole('button', { name: 'Move', exact: true }).click();
  await page.getByText(/A move is as public as any transfer/).waitFor();
  await page.getByRole('button', { name: 'I understand', exact: true }).click();
  await page.getByLabel('Send the bounty to', { exact: true }).fill('HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk');
  await shot(page, 'wallet-move');
  await page.getByRole('button', { name: 'Move the bounty', exact: true }).click();
  await page.getByText(/^Moved\. Transaction payoutsi/).waitFor();
  const transfer = await page.evaluate(() => window.walletTest.transfers[0].slice(0, 10));
  assert.deepEqual(transfer, [2, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
  assert.deepEqual(await page.evaluate(() => window.walletTest.sent), ['dHg=']);

  // Network: the toggle is on, and says what it does.
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('button', { name: /^Witnesses/ }).click();
  const toggle = page.getByRole('switch', { name: 'Collect fork bounties', exact: true });
  await toggle.waitFor();
  assert.equal(await toggle.isChecked(), true);
  await page.getByText(/the bounty landed in your wallet: 1,250 USDC\.$/).waitFor();
  await page.getByText(/never linked to your account\.$/).first().waitFor();
  await shot(page, 'network-bounties');
  await toggle.click();
  await page.waitForFunction(() => JSON.parse(localStorage.getItem('sealed-journal/wallet/settings')).collectBounties === false);
  console.log('wallet: create, confirm, offer, balances, notice, move and the bounty toggle work');
} finally {
  await browser.close();
  server.close();
}
