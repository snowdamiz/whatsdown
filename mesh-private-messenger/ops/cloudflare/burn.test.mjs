import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AccountRole, appendTransactionMessageInstructions, compileTransaction, createTransactionMessage, getBase64Decoder, getTransactionEncoder,
  pipe, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { burnTick, checkQuote, planChunks } from './burn.mjs';
import { TOKEN, addressFrom, ata, encodeTokenAccount, keypairFromSeed, memoryChain, rewardsAddresses } from './judge.mjs';

const usdc = addressFrom(new Uint8Array(32).fill(9));
const token = addressFrom(new Uint8Array(32).fill(10));
const rewards = addressFrom(new Uint8Array(32).fill(8));
const WEEK = 604_800_000;

// A seeded generator so plans are reproducible in tests.
const seeded = seed => () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);

test('a week\'s burn is split into at least 24 randomized chunks that add up exactly and stay inside the week', () => {
  const start = 2940 * WEEK;
  for (const total of [24n, 1_000_000n, 123_456_789_012n]) {
    const chunks = planChunks(total, { startMs: start, endMs: start + WEEK, random: seeded(7) });
    assert.ok(chunks.length >= 24);
    assert.equal(chunks.reduce((sum, c) => sum + c.amount, 0n), total);
    assert.ok(chunks.every(c => c.amount > 0n && c.dueMs >= start && c.dueMs < start + WEEK));
    assert.ok(chunks.every((c, i) => i === 0 || c.dueMs > chunks[i - 1].dueMs));
  }
  const a = planChunks(1_000_000n, { startMs: start, endMs: start + WEEK, random: seeded(1) });
  const b = planChunks(1_000_000n, { startMs: start, endMs: start + WEEK, random: seeded(2) });
  assert.notDeepEqual(a.map(c => c.amount), b.map(c => c.amount), 'sizes are randomized');
  assert.notDeepEqual(a.map(c => c.dueMs), b.map(c => c.dueMs), 'times are randomized');
  assert.deepEqual(planChunks(10n, { startMs: start, endMs: start + WEEK }), [], 'less than one base unit per chunk waits for more');
});

test('the slippage guard accepts at most 1% and a quote for exactly the planned trade', () => {
  const quote = { inputMint: usdc, outputMint: token, inAmount: '1000', outAmount: '5000', otherAmountThreshold: '4950', slippageBps: 100, priceImpactPct: '0.004' };
  const expect = { usdc, token, amount: 1000n };
  assert.doesNotThrow(() => checkQuote(quote, expect));
  for (const [field, value] of [['slippageBps', 150], ['priceImpactPct', '0.02'], ['otherAmountThreshold', '4900'], ['outputMint', usdc],
    ['inAmount', '1001'], ['outAmount', '0']]) {
    assert.throws(() => checkQuote({ ...quote, [field]: value }, expect), /slippage|quote/, field);
  }
});

async function swapTransaction(feePayer) {
  const message = pipe(createTransactionMessage({ version: 0 }), m => setTransactionMessageFeePayer(feePayer, m),
    m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 9n }, m),
    m => appendTransactionMessageInstructions([{ programAddress: TOKEN, accounts: [{ address: feePayer, role: AccountRole.WRITABLE_SIGNER }], data: new Uint8Array([3]) }], m));
  return getBase64Decoder().decode(getTransactionEncoder().encode(compileTransaction(message)));
}

test('a due chunk swaps through the quote API into the burn account and burns; a bad quote is skipped with a warning', async () => {
  const wallet = await keypairFromSeed(new Uint8Array(32).fill(4));
  const payer = await keypairFromSeed(new Uint8Array(32).fill(5));
  const burnAuthority = await rewardsAddresses(rewards).burn();
  const burnAccount = await ata(burnAuthority, token);
  const chain = memoryChain();
  chain.set(await ata(wallet.address, usdc), encodeTokenAccount({ mint: usdc, owner: wallet.address, amount: 48_000_000n }), TOKEN);
  let impact = '0.001';
  const requests = [];
  const fetcher = async (url, init) => {
    requests.push([String(url), init?.body && JSON.parse(init.body)]);
    const u = new URL(url);
    if (u.pathname.endsWith('/quote')) {
      const amount = u.searchParams.get('amount');
      return Response.json({ inputMint: u.searchParams.get('inputMint'), outputMint: u.searchParams.get('outputMint'), inAmount: amount,
        outAmount: String(BigInt(amount) * 5n), otherAmountThreshold: String(BigInt(amount) * 5n * 99n / 100n), slippageBps: Number(u.searchParams.get('slippageBps')), priceImpactPct: impact });
    }
    return Response.json({ swapTransaction: await swapTransaction(wallet.address) });
  };
  chain.onSend = async (instructions, options, c) => {
    if (options.transaction) {
      const received = BigInt(requests.at(-2)[0].match(/amount=(\d+)/)[1]) * 5n;
      c.set(burnAccount, encodeTokenAccount({ mint: token, owner: burnAuthority, amount: received }), TOKEN);
    }
  };
  const state = new Map();
  const kv = { get: k => state.get(k), set: (k, v) => state.set(k, v) };
  const alerts = [];
  const args = { env: { MORSE_BURN_MODE: 'on' }, chain, rewards, usdc, token, wallet, payer, state: kv, fetcher, api: 'https://quote.test/swap/v1', alert: x => alerts.push(x) };
  const week = 2940;
  await burnTick({ ...args, env: {}, nowMs: week * WEEK });
  assert.equal(requests.length, 0, 'MORSE_BURN_MODE off: nothing happens and the share accumulates');
  await burnTick({ ...args, nowMs: week * WEEK, random: seeded(3) });
  const plan = state.get(`burn:${week}`);
  assert.equal(plan.chunks.reduce((sum, c) => sum + BigInt(c.amount), 0n), 24_000_000n, 'without last week\'s plan, half the balance (backlog over two weeks)');
  const first = plan.chunks[0];
  await burnTick({ ...args, nowMs: first.dueMs });
  assert.equal(requests[0][0], `https://quote.test/swap/v1/quote?inputMint=${usdc}&outputMint=${token}&amount=${first.amount}&slippageBps=100&swapMode=ExactIn`);
  assert.equal(requests[1][1].destinationTokenAccount, burnAccount, 'bought tokens go straight to the burn account');
  assert.equal(requests[1][1].userPublicKey, wallet.address);
  const burn = chain.sent.find(t => t.instructions?.some(ix => ix.programAddress === rewards));
  assert.deepEqual([...burn.instructions.at(-1).data], [5]);
  assert.equal(state.get(`burn:${week}`).chunks[0].status, 'done');
  assert.deepEqual(alerts, []);
  impact = '0.03';
  await burnTick({ ...args, nowMs: plan.chunks[1].dueMs });
  assert.match(alerts[0], /^WARN burn_chunk_failed .*slippage/);
  assert.equal(state.get(`burn:${week}`).chunks[1].status, 'pending');
  assert.equal(state.get(`burn:${week}`).chunks[1].attempts, 1);
});

test('a swap transaction that needs any signer besides the burn wallet is refused', async () => {
  const wallet = await keypairFromSeed(new Uint8Array(32).fill(4));
  const other = await keypairFromSeed(new Uint8Array(32).fill(6));
  const payer = await keypairFromSeed(new Uint8Array(32).fill(5));
  const chain = memoryChain();
  chain.set(await ata(wallet.address, usdc), encodeTokenAccount({ mint: usdc, owner: wallet.address, amount: 48_000_000n }), TOKEN);
  const fetcher = async url => new URL(url).pathname.endsWith('/quote')
    ? Response.json({ inputMint: usdc, outputMint: token, inAmount: new URL(url).searchParams.get('amount'), outAmount: '10', otherAmountThreshold: '10', slippageBps: 100, priceImpactPct: '0' })
    : Response.json({ swapTransaction: await swapTransaction(other.address) });
  const state = new Map([['burn:2941', { chunks: [{ dueMs: 0, amount: '1000000', status: 'pending', attempts: 0 }] }]]);
  const alerts = [];
  await burnTick({ env: { MORSE_BURN_MODE: 'on' }, chain, rewards, usdc, token, wallet, payer, fetcher, api: 'https://quote.test/swap/v1',
    state: { get: k => state.get(k), set: (k, v) => state.set(k, v) }, nowMs: 2941 * WEEK + 1, alert: x => alerts.push(x) });
  assert.match(alerts[0], /signer/);
  assert.equal(chain.sent.filter(t => t.transaction).length, 0);
});
