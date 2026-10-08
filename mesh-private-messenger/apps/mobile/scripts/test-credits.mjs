// Run after npm run web --prefix ../desktop (or point MORSE_CREDITS_DIST at an export
// built with the service URLs). Settings -> Credits and Settings -> Privacy -> Message
// requests from strangers in the real UI; only native IPC (the Mesh core, the wallet
// host) and the services are replaced. The core's credit exports are played by a
// small in-page store that answers in their frames (Mobile.CreditsBuy/Spend).
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const dist = new URL(process.env.MORSE_CREDITS_DIST || '../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}`;
const screenshots = process.env.MORSE_CREDITS_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });

const RPC = 'https://rpc.test/solana';

async function open(scheme = 'dark') {
  const page = await browser.newPage({ viewport: { width: 1160, height: 860 }, colorScheme: scheme, reducedMotion: 'reduce' });
  page.on('pageerror', (error) => { throw error; });
  await page.addInitScript(({ scheme, RPC }) => {
    const u16 = (n) => [n >>> 8 & 255, n & 255];
    const u32 = (n) => [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255];
    const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return [...b]; };
    const text = (s) => [...new TextEncoder().encode(s)];
    const id = (n, length = 32) => Array(length).fill(n);
    const vectors = (...fields) => fields.flatMap((f) => [...u32(f.length), ...f]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const fields = (bytes) => {
      const parts = [];
      for (let at = 0; at < bytes.length;) {
        const size = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
        parts.push(new Uint8Array(bytes.slice(at + 4, at + 4 + size)));
        at += 4 + size;
      }
      return parts;
    };
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const unbase58 = (value) => {
      let n = 0n; for (const c of value) n = n * 58n + BigInt(alphabet.indexOf(c));
      const out = []; while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
      while (out.length < 32) out.unshift(0);
      return out;
    };
    const USDC = unbase58('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
    const PACK = { 1: 100, 2: 500, 3: 2000 };
    const hour = 3_600_000;
    // The store the core keeps, as far as the screens can see it.
    const store = window.creditsTest = {
      spendable: 100, cooling: 0, coolingUntil: 0, inbox: 0, days: 0, until: 0, next: 1,
      purchases: [{ id: 200, state: 8, pack: 1, asset: 1, amount: 5_000_000, created: Date.now() - 3 * hour, expires: Date.now() - 2 * hour, issued: 0, request: 'solana:old', payment: '' }],
      issues: [], policies: [], puts: [], retention: [], transfers: [],
    };
    const purchaseFrame = (p) => [...id(p.id, 16), p.state, p.pack, p.asset, ...u16(PACK[p.pack]), ...u64(p.amount), ...u64(p.created),
      ...u64(p.created), ...u64(p.expires), ...u32(p.issued), ...id(p.id + 1), ...vectors(text(p.request)), ...vectors(text(p.payment))];
    const status = () => [1, ...text('CST'), 1, 2, ...u32(store.spendable), ...u32(store.cooling), ...u64(store.coolingUntil),
      ...u32(store.spendable + store.cooling), ...u64(Date.now() + 40 * 24 * hour), ...u64(Date.now()), store.inbox, ...u16(store.days),
      ...u64(store.until), store.purchases.length, ...[...store.purchases].reverse().flatMap((p) => vectors(purchaseFrame(p)))];
    const credit = (symbol, parts) => {
      if (symbol === 'status') return status();
      if (symbol === 'refresh_keys') return [1];
      if (symbol === 'quote') {
        const [pack, asset] = [parts[2][0], parts[3][0]];
        const amount = asset === 3 ? 83_340 : asset === 2 ? 166_666_667 * PACK[pack] / 1000 : PACK[pack] * 50_000;
        const request = asset === 3 ? 'lnbcrt83340n1pquotetest'
          : `solana:${'9'.repeat(32)}?amount=${asset === 1 ? amount / 1_000_000 : amount / 1e9}${asset === 1 ? '&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' : ''}&reference=ref&label=Morse`;
        const purchase = { id: store.next++, state: 1, pack, asset, amount, created: Date.now(), expires: Date.now() + 900_000, issued: 0, request, payment: '' };
        store.purchases.push(purchase);
        return purchaseFrame(purchase);
      }
      if (symbol === 'issue') {
        const purchase = store.purchases.find((p) => p.id === parts[2][0]);
        const payment = new TextDecoder().decode(parts[3]);
        store.issues.push({ id: purchase.id, payment });
        // Lightning settles on the issuer's second look; a wallet payment at once.
        const seen = store.issues.filter((call) => call.id === purchase.id).length;
        if (purchase.state === 1 && purchase.asset === 3 && seen < 2) return [2, ...purchaseFrame(purchase)];
        if (purchase.state <= 3) {
          Object.assign(purchase, { state: 4, issued: PACK[purchase.pack], payment });
          store.cooling += PACK[purchase.pack];
          store.coolingUntil = Date.now() + 600_000;
        }
        return [purchase.state === 4 ? 1 : 5, ...purchaseFrame(purchase)];
      }
      if (symbol === 'inbox_policy') { store.policies.push(parts[1][0]); store.inbox = parts[1][0]; return [1, ...text('MBP'), ...id(3), ...u64(Date.now()), parts[1][0], ...id(4, 64)]; }
      if (symbol === 'group_handover') return u32(0);
      if (symbol === 'retention') {
        const periods = parts[1][0];
        store.pending = periods;
        return [...id(7, 16), periods * 10, ...vectors([1, ...text('CRD'), ...text('MRT'), periods])];
      }
      if (symbol === 'settle') {
        const status = (parts[2][0] << 8) | parts[2][1];
        if (status === 201 && store.pending) {
          store.spendable -= store.pending * 10;
          store.days = 30 + store.pending * 30;
          store.until = Date.now() + store.days * 24 * hour;
          store.pending = 0;
        }
        return [1];
      }
      throw Error(`unexpected credits ${symbol}`);
    };
    const rpc = (method) => {
      if (method === 'getGenesisHash') return '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
      if (method === 'getLatestBlockhash') return { value: { blockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi', lastValidBlockHeight: 99 } };
      if (method === 'sendTransaction') return 'creditsig';
      if (method === 'getSignatureStatuses') return { value: [{ err: null, confirmationStatus: 'finalized' }] };
      throw Error(`unexpected ${method}`);
    };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args, options) => {
      if (command === 'database_path') return '/test/morse.db';
      if (command === 'appearance') return scheme;
      if (command === 'wallet_exists') return true;
      if (command === 'wallet_bounty_index') return 0;
      if (command === 'wallet_call') {
        const op = Number(options.headers['X-Wallet-Op']);
        const body = Array.from(args);
        // Op 6 parses the quote's Solana Pay link: 25 USDC to the deposit.
        if (op === 6) {
          const link = new TextDecoder().decode(new Uint8Array(body.slice(4)));
          const amount = Number(new URL(link.replace('solana:', 'https://x/')).searchParams.get('amount'));
          return new Uint8Array([...id(9), 1, ...u64(amount), 0, 1, ...USDC, 0, ...vectors(text('Morse')), ...vectors([]), ...vectors([])]).buffer;
        }
        if (op === 5) { store.transfers.push(body); return new Uint8Array(vectors(text('creditsig'), text('dHg='))).buffer; }
        if (op === 4) return new Uint8Array(id(0xa0)).buffer;
        throw Error('bad_op');
      }
      const service = options?.headers?.['X-Service-Url'];
      if (command === 'binary_request' && service?.startsWith(RPC)) {
        const request = JSON.parse(new TextDecoder().decode(new Uint8Array(args)));
        return [0, 200, ...text(JSON.stringify({ jsonrpc: '2.0', id: 1, result: rpc(request.method) }))];
      }
      if (command === 'binary_request' && service === 'https://messenger.test/v1/mailbox/policy') {
        store.puts.push(options.headers['X-Service-Method']);
        return [0, 201];
      }
      if (command === 'binary_request' && service === 'https://edge.test/v1/mailbox/retention') {
        store.retention.push(Array.from(args));
        return [0, 201, ...u16(90), ...u64(Date.now() + 90 * 24 * hour)];
      }
      if (command === 'binary_request' && service?.endsWith('/v1/devices/resolve')) return [0, 200, 1];
      const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol?.startsWith('mesh_messenger_credits_')) return credit(symbol.slice(23), fields(Array.from(args)));
      if (symbol === 'mesh_messenger_wallet_rpc_urls') return [1, 2, ...vectors(text(RPC)), ...vectors(text(`${RPC}/2`))];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), id(1), id(1, 16), []);
      if (symbol === 'mesh_messenger_inspect_device_set') return vectors(text('alice'), id(1), u64(1), [0], [1], list(vectors(id(1, 16), [1], [1])));
      if (symbol === 'mesh_messenger_transparency_lookup' || symbol === 'mesh_messenger_resolve_request' || symbol === 'mesh_messenger_verify_transparency') return [1];
      if (['mesh_messenger_list_conversations', 'mesh_messenger_load_history', 'mesh_messenger_group_invitations',
        'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page', 'mesh_messenger_group_list'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_presentation_load') return [];
      if (symbol === 'mesh_messenger_journal_load' || symbol === 'mesh_messenger_journal_save') {
        const parts = fields(Array.from(args));
        const label = `sealed-journal/${new TextDecoder().decode(parts[1])}`;
        if (symbol.endsWith('_load')) return [...new TextEncoder().encode(localStorage.getItem(label) ?? '')];
        if (parts[2].length === 1 && parts[2][0] === 0) localStorage.removeItem(label);
        else localStorage.setItem(label, new TextDecoder().decode(parts[2]));
        return [];
      }
      throw Error('Offline test boundary');
    } };
  }, { scheme, RPC });
  await page.goto(url);
  await page.getByRole('progressbar', { name: 'Opening Morse', exact: true }).first().waitFor({ state: 'detached' });
  return page;
}

const shot = async (page, name) => { if (screenshots) await page.screenshot({ path: `${screenshots}/${name}.png`, fullPage: true }); };
const store = (page) => page.evaluate(() => window.creditsTest);

try {
  const page = await open();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: /^Credits/ }).getByText('100 credits', { exact: true }).waitFor();
  await page.getByRole('button', { name: /^Credits/ }).click();
  await page.getByText('100 credits', { exact: true }).first().waitFor();
  // The public-purchase notice sits on the buy screen.
  await page.getByText(/A purchase is as public as any on-chain payment/).waitFor();
  // A purchase only Morse can finish says so, and offers its reference.
  await page.getByText(/Morse can finish this purchase for you/).waitFor();
  await page.getByRole('button', { name: 'Copy reference', exact: true }).waitFor();
  await shot(page, 'credits-buy');

  // 500 credits in USDC from this wallet: the wallet pays the quote's exact amount.
  await page.getByRole('radio', { name: 'Pack: 500 for $25', exact: true }).click();
  await page.getByRole('radio', { name: 'Pay with: USDC', exact: true }).click();
  await page.getByRole('radio', { name: 'From: This wallet', exact: true }).click();
  await page.getByRole('button', { name: 'Buy 500 credits', exact: true }).click();
  await page.getByText('Pay 25 USDC', { exact: true }).waitFor();
  await page.getByText(/Keep Morse open while credits are collected/).waitFor();
  await shot(page, 'credits-pay-wallet');
  await page.getByRole('button', { name: 'Pay from this wallet', exact: true }).click();
  await page.getByText(/^Credits added\./).waitFor();
  await page.getByText(/500 credits ready in 10 min/).waitFor();
  let seen = await store(page);
  assert.equal(seen.transfers.length, 1);
  // The transfer's amount (u64 after the two keys and the USDC asset) is 25 USDC.
  const transfer = new Uint8Array(seen.transfers[0]);
  assert.equal(new DataView(transfer.buffer).getBigUint64(5 + 5 + 34), 25_000_000n);
  assert.deepEqual(seen.issues.at(-1), { id: 1, payment: 'creditsig' });

  // Bitcoin over Lightning: an invoice to scan or copy, collected once it settles.
  await page.getByRole('radio', { name: 'Pay with: Bitcoin', exact: true }).click();
  await page.getByText('Lightning invoice', { exact: true }).waitFor();
  await page.getByRole('radio', { name: 'Pack: 100 for $5', exact: true }).click();
  await page.getByRole('button', { name: 'Buy 100 credits', exact: true }).click();
  await page.getByText('Pay 83,340 sats', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Copy invoice', exact: true }).waitFor();
  await shot(page, 'credits-pay-lightning');
  // The issuer answers 202 until the invoice settles; the screen asks again.
  await page.getByText('Pay 83,340 sats', { exact: true }).waitFor({ state: 'detached', timeout: 20_000 });
  await page.getByText(/^Credits added\./).waitFor();
  seen = await store(page);
  assert.ok(seen.issues.filter((call) => call.id === 2).length >= 2, 'the issuer was asked again after 202');

  // Longer storage: two periods, twenty credits, through the edge.
  await page.getByRole('radio', { name: 'Longer by: 60 days', exact: true }).click();
  await page.getByRole('button', { name: 'Keep 90 days · 20 credits', exact: true }).click();
  await page.getByText('Messages are kept 90 days now.', { exact: true }).waitFor();
  await page.getByText(/^Kept 90 days, until/).waitFor();
  seen = await store(page);
  assert.equal(seen.retention.length, 1);
  await shot(page, 'credits-after');

  // Settings -> Privacy: a price on message requests from strangers.
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('radio', { name: 'Price for message requests: 5 credits', exact: true }).click();
  await page.getByText('5 credits each, paid to the network', { exact: true }).waitFor();
  seen = await store(page);
  assert.deepEqual(seen.policies, [5]);
  assert.deepEqual(seen.puts, ['PUT']);
  await shot(page, 'credits-inbox-price');

  if (screenshots) {
    const light = await open('light');
    await light.getByRole('button', { name: 'Settings', exact: true }).click();
    await light.getByRole('button', { name: /^Credits/ }).click();
    await light.getByText(/A purchase is as public/).waitFor();
    await shot(light, 'credits-light');
  }
  console.log('credits screens: ok');
} catch (error) {
  for (const context of browser.contexts()) {
    for (const page of context.pages()) await shot(page, 'failure');
  }
  throw error;
} finally {
  await browser.close();
  server.close();
}
