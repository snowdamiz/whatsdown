import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

// Chain access for the wallet: only the RPC URLs the core says the build pins, over the
// app's transport (the desktop host allowlists exactly those). The native wallet and
// the core are faked.
type Globals = typeof globalThis & { __walletNative: unknown; __rpcUrls: () => Promise<Uint8Array> };
const globals = globalThis as Globals;
const native: Record<string, (...args: never[]) => unknown> = {};
const nativeCalls: { method: string; args: unknown[] }[] = [];
globals.__walletNative = new Proxy({}, {
  get: (_, method: string) => async (...args: unknown[]) => {
    nativeCalls.push({ method, args });
    return (native[method] as (...values: unknown[]) => unknown)(...args);
  },
});
registerHooks({
  resolve(specifier, context, nextResolve) {
    const parent = context.parentURL ?? '';
    if (specifier === '../modules/mesh-messenger/wallet' && parent.includes('/src/wallet.ts')) {
      return { shortCircuit: true, url: 'data:text/javascript,export const walletNative = globalThis.__walletNative;' };
    }
    if (specifier === '../modules/mesh-messenger' && parent.includes('/src/solana.ts')) {
      return { shortCircuit: true, url: 'data:text/javascript,export const wallet_rpc_urls_export = (r) => globalThis.__rpcUrls(r);' };
    }
    if (specifier === './transport' && parent.includes('/src/solana.ts')) {
      return {
        shortCircuit: true,
        url: 'data:text/javascript,export const fetch = (...args) => globalThis.fetch(...args); export const isDevelopmentBuild = () => false;',
      };
    }
    return nextResolve(specifier, context);
  },
});

const solana = await import('./solana.ts');
const wallet = await import('./wallet.ts');

const u32 = (value: number): number[] => [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
const text = (value: string): number[] => { const bytes = new TextEncoder().encode(value); return [...u32(bytes.length), ...bytes]; };
const key = (fill: number): Uint8Array => new Uint8Array(32).fill(fill);
const OWNER = wallet.base58(key(1));
const SHOP = wallet.base58(key(2));
const BLOCKHASH = wallet.base58(key(3));
const REFERENCE = wallet.base58(key(4));
const TOKEN_ACCOUNT = wallet.base58(key(5));

type Handler = (params: unknown[]) => unknown;
// A fake provider: the methods it answers, and every request it saw.
function provider(handlers: Record<string, Handler>) {
  const seen: { url: string; method: string; params: unknown[]; contentType: string | null }[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(new TextDecoder().decode(new Uint8Array(init!.body as ArrayBuffer))) as { method: string; params: unknown[] };
    seen.push({ url: String(input), method: body.method, params: body.params, contentType: new Headers(init?.headers).get('Content-Type') });
    const handler = handlers[body.method];
    if (!handler) return new Response('{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}');
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: handler(body.params) }));
  };
  return { seen, fetch };
}

const MAINNET = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const DEVNET = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
// One provider on mainnet, as pinnedRpc would hand it over.
const onMainnet = (post: Parameters<typeof solana.rpcOver>[1]) =>
  Object.assign(solana.rpcOver(['https://rpc.test'], post), { usdcMint: wallet.USDC_MINT });

const reset = (): void => { nativeCalls.length = 0; for (const name of Object.keys(native)) delete native[name]; };

test('the wallet reads the chain only through the RPC URLs the build pins', async (t) => {
  globals.__rpcUrls = async () => Uint8Array.of(1, 2, ...text('https://rpc-a.test'), ...text('https://rpc-b.test/key'));
  const chain = provider({
    getBalance: () => ({ value: 7 }),
    getTokenAccountsByOwner: () => ({ value: [] }),
    getGenesisHash: () => MAINNET,
  });
  t.mock.method(globalThis, 'fetch', chain.fetch);
  const rpc = await solana.pinnedRpc();
  assert.ok(rpc);
  assert.equal(rpc.usdcMint, wallet.USDC_MINT);
  assert.deepEqual(await solana.balances(rpc, OWNER), { sol: 7n, usdc: 0n });
  for (const request of chain.seen) {
    assert.ok(['https://rpc-a.test', 'https://rpc-b.test/key'].includes(request.url));
    assert.equal(request.contentType, 'application/json');
  }
  globals.__rpcUrls = async () => Uint8Array.of(1, 0);
  assert.equal(await solana.pinnedRpc(), null);
});

test('a provider that fails is skipped, but a JSON-RPC error is an answer', async () => {
  const tried: string[] = [];
  const rpc = solana.rpcOver(['https://a.test', 'https://b.test', 'https://c.test'], async (url) => {
    tried.push(url);
    if (url === 'https://a.test') throw new Error('offline');
    if (url === 'https://b.test') return { status: 503, body: '' };
    return { status: 200, body: '{"jsonrpc":"2.0","id":1,"result":42}' };
  }, () => 0.999);
  assert.equal(await rpc('getSlot', []), 42);
  assert.deepEqual(tried, ['https://a.test', 'https://b.test', 'https://c.test']);
  const refusing = solana.rpcOver(['https://a.test', 'https://b.test'], async () =>
    ({ status: 200, body: '{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"blockhash not found"}}' }));
  await assert.rejects(refusing('sendTransaction', []), /blockhash not found/);
  await assert.rejects(solana.rpcOver(['https://a.test'], async () => ({ status: 500, body: '' }))('getSlot', []), /rpc_unavailable/);
});

test('balances add up SOL and every USDC account the address owns', async () => {
  const chain = provider({
    getBalance: () => ({ value: 2_500_000 }),
    getTokenAccountsByOwner: (params) => {
      assert.deepEqual(params[1], { mint: wallet.USDC_MINT });
      const amount = (value: string) => ({ account: { data: { parsed: { info: { tokenAmount: { amount: value } } } } } });
      return { value: [amount('1500000'), amount('9007199254740993')] };
    },
  });
  const rpc = onMainnet(solana.poster(chain.fetch));
  assert.deepEqual(await solana.balances(rpc, OWNER), { sol: 2_500_000n, usdc: 9_007_199_256_240_993n });
});

test('a transfer counts only once finalized, and fails when it errs or its blockhash expires', async () => {
  const statuses: unknown[] = [null, { err: null, confirmationStatus: 'confirmed' }, { err: null, confirmationStatus: 'finalized' }];
  const chain = provider({
    sendTransaction: (params) => { assert.deepEqual(params, ['dHg=', { encoding: 'base64', preflightCommitment: 'confirmed' }]); return 'sig1'; },
    getSignatureStatuses: () => ({ value: [statuses.shift()] }),
    getBlockHeight: () => 10,
  });
  const rpc = onMainnet(solana.poster(chain.fetch));
  const waits: number[] = [];
  const wait = async (ms: number) => { waits.push(ms); };
  assert.equal(await solana.sendAndConfirm(rpc, 'dHg=', 20, wait), 'sig1');
  assert.equal(waits.length, 2);
  const failing = provider({ sendTransaction: () => 'sig2', getSignatureStatuses: () => ({ value: [{ err: { InstructionError: [0, 'x'] } }] }) });
  await assert.rejects(solana.sendAndConfirm(onMainnet(solana.poster(failing.fetch)), 'dHg=', 20, wait), /transaction_failed/);
  const lost = provider({ sendTransaction: () => 'sig3', getSignatureStatuses: () => ({ value: [null] }), getBlockHeight: () => 21 });
  await assert.rejects(solana.sendAndConfirm(onMainnet(solana.poster(lost.fetch)), 'dHg=', 20, wait), /transaction_expired/);
});

const signedAnswer = () => Uint8Array.of(...text('sig'), ...text('dHg='));
const confirming = (extra: Record<string, Handler> = {}) => provider({
  getLatestBlockhash: () => ({ value: { blockhash: BLOCKHASH, lastValidBlockHeight: 99 } }),
  sendTransaction: () => 'sig',
  getSignatureStatuses: () => ({ value: [{ err: null, confirmationStatus: 'finalized' }] }),
  ...extra,
});
const transferBody = (): Uint8Array => nativeCalls.find((call) => call.args[0] === 5)!.args[1] as Uint8Array;

test('paying a Solana Pay USDC request signs to its recipient with its references and memo', async () => {
  reset();
  native.walletCall = (op: number) => op === 6
    ? Uint8Array.of(...key(2), 1, 0, 0, 0, 0, 0, 0, 0, 25, 1, 1, ...wallet.fromBase58(wallet.USDC_MINT), 1, ...key(4),
      ...text('Morse'), ...text('3 credits'), ...text('q-7'))
    : signedAnswer();
  const chain = confirming();
  const rpc = onMainnet(solana.poster(chain.fetch));
  const request = await wallet.parsePayUrl(`solana:${SHOP}?amount=2.5&spl-token=${wallet.USDC_MINT}&reference=${REFERENCE}&memo=q-7`);
  assert.equal(await solana.pay(rpc, request), 'sig');
  const expected = wallet.encodeTransfer({
    owner: { kind: 'account', index: 0 }, feePayer: 0, asset: { kind: 'spl', mint: wallet.USDC_MINT, decimals: 6 },
    amount: 2_500_000n, recipient: SHOP, createRecipientAccount: true, references: [REFERENCE], memo: 'q-7',
    computeUnitLimit: 0, computeUnitPrice: 0n, blockhash: BLOCKHASH,
  });
  assert.deepEqual(transferBody(), expected);
  assert.deepEqual(chain.seen.map((request) => request.method), ['getLatestBlockhash', 'sendTransaction', 'getSignatureStatuses']);
  // SOL needs no token account; a token other than USDC, or no amount, is not paid.
  reset();
  native.walletCall = signedAnswer;
  await solana.pay(rpc, { ...request, splToken: null, amount: { mantissa: 1n, scale: 0 } });
  assert.deepEqual(transferBody().subarray(10, 11), Uint8Array.of(1));
  await assert.rejects(solana.pay(rpc, { ...request, splToken: OWNER }), /unsupported_token/);
  await assert.rejects(solana.pay(rpc, { ...request, amount: null }), /amount_required/);
});

test('moving a bounty sends its whole USDC balance, the account paying the fee', async () => {
  reset();
  native.walletBountyIndex = () => 4;
  native.walletCall = (op: number) => (op === 4 ? key(6) : signedAnswer());
  const amount = { account: { data: { parsed: { info: { tokenAmount: { amount: '1250000000' } } } } } };
  const chain = confirming({ getBalance: () => ({ value: 0 }), getTokenAccountsByOwner: () => ({ value: [amount] }) });
  const rpc = onMainnet(solana.poster(chain.fetch));
  assert.equal(await solana.moveBounty(rpc, 2, OWNER), 'sig');
  assert.deepEqual(transferBody().subarray(0, 10), Uint8Array.of(2, 0, 0, 0, 2, 1, 0, 0, 0, 0));
  assert.equal(new DataView(transferBody().buffer, transferBody().byteOffset + 44, 8).getBigUint64(0), 1_250_000_000n);
  const empty = confirming({ getBalance: () => ({ value: 0 }), getTokenAccountsByOwner: () => ({ value: [] }) });
  await assert.rejects(solana.moveBounty(onMainnet(solana.poster(empty.fetch)), 2, OWNER), /nothing_to_move/);
});

test('after a restore, bounty addresses are found on chain and their indexes never handed out again', async () => {
  reset();
  let issued = 0;
  native.walletBountyIndex = (atLeast: number) => { issued = Math.max(issued, atLeast); return issued; };
  native.walletCall = (_op: number, body: Uint8Array) => {
    // Deriving an index the host has not issued is refused, as the hosts do.
    if (body[4]! >= issued) throw new Error('bounty_not_issued');
    return key(10 + body[4]!);
  };
  const used = new Set([wallet.base58(key(10)), wallet.base58(key(12))]);
  const chain = provider({ getSignaturesForAddress: (params) => (used.has(params[0] as string) ? [{ signature: 's' }] : []) });
  const found = await solana.discoverBounties(onMainnet(solana.poster(chain.fetch)), 3);
  assert.equal(found, 6);
  assert.equal(issued, 6);
});

test('the payout of a landed bounty is the first transfer into its token account', async () => {
  const tx = (pre: string, post: string) => ({
    transaction: { message: { accountKeys: [{ pubkey: OWNER }, { pubkey: TOKEN_ACCOUNT }] } },
    meta: {
      preTokenBalances: [{ accountIndex: 1, uiTokenAmount: { amount: pre } }],
      postTokenBalances: [{ accountIndex: 1, uiTokenAmount: { amount: post } }],
    },
  });
  const chain = provider({
    getTokenAccountsByOwner: () => ({ value: [{ pubkey: TOKEN_ACCOUNT, account: { data: { parsed: { info: { tokenAmount: { amount: '0' } } } } } }] }),
    // Newest first: a move out, the payout, the account's creation.
    getSignaturesForAddress: () => [{ signature: 'move', err: null }, { signature: 'payout', err: null }, { signature: 'create', err: null }],
    getTransaction: (params) => ({ create: tx('0', '0'), payout: tx('0', '1250000000'), move: tx('1250000000', '0') }[params[0] as string]),
  });
  const rpc = onMainnet(solana.poster(chain.fetch));
  assert.deepEqual(await solana.bountyPayout(rpc, OWNER), { amount: 1_250_000_000n, signature: 'payout' });
  const none = provider({ getTokenAccountsByOwner: () => ({ value: [] }) });
  assert.equal(await solana.bountyPayout(onMainnet(solana.poster(none.fetch)), OWNER), null);
});

// Every pinned provider answers with its chain's genesis hash.
const genesis = (answers: Record<string, string | null>) => async (url: string) => {
  const answer = answers[url];
  if (answer === undefined) throw new Error('offline');
  return { status: 200, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: answer }) };
};
const URLS = ['https://a.test', 'https://b.test', 'https://c.test'];

test('USDC is the mint of the chain the providers agree they serve', async () => {
  assert.equal((await solana.clusterOf(URLS, genesis({ 'https://a.test': MAINNET, 'https://b.test': MAINNET, 'https://c.test': MAINNET }), false)).usdcMint,
    'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
  // One provider down is fine; two must still agree.
  assert.equal((await solana.clusterOf(URLS, genesis({ 'https://a.test': DEVNET, 'https://b.test': DEVNET }), false)).usdcMint,
    '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU');
  await assert.rejects(solana.clusterOf(URLS, genesis({ 'https://a.test': MAINNET }), false), /rpc_unavailable/);
  await assert.rejects(solana.clusterOf(URLS, genesis({ 'https://a.test': MAINNET, 'https://b.test': DEVNET, 'https://c.test': MAINNET }), false),
    /rpc_disagree/);
});

test('another chain has no USDC, unless a development build names one', async () => {
  const local = wallet.base58(key(9));
  const answers = genesis({ 'https://a.test': local, 'https://b.test': local });
  await assert.rejects(solana.clusterOf(URLS, answers, false), /unsupported_cluster/);
  const mint = wallet.base58(key(8));
  // A release build ignores the development override.
  await assert.rejects(solana.clusterOf(URLS, answers, false, mint), /unsupported_cluster/);
  assert.deepEqual(await solana.clusterOf(URLS, answers, true, mint), { name: 'development', usdcMint: mint });
  await assert.rejects(solana.clusterOf(URLS, answers, true, ''), /unsupported_cluster/);
});

test('without a known chain the wallet neither counts nor pays USDC', async () => {
  const rpc = solana.rpcOver(['https://rpc.test'], async () => ({ status: 200, body: '{"jsonrpc":"2.0","id":1,"result":{"value":1}}' }));
  await assert.rejects(solana.balances(rpc, OWNER), /unsupported_cluster/);
  const request = await (async () => {
    native.walletCall = async () => Uint8Array.of(...key(2), 1, 0, 0, 0, 0, 0, 0, 0, 25, 1, 1, ...wallet.fromBase58(wallet.USDC_MINT), 0,
      ...u32(0), ...u32(0), ...u32(0));
    return wallet.parsePayUrl(`solana:${SHOP}?amount=2.5&spl-token=${wallet.USDC_MINT}`);
  })();
  await assert.rejects(solana.pay(rpc, request), /unsupported_cluster/);
  reset();
});
