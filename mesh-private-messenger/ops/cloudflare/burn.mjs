// Burn crank (plan §6.12, Phase 5): each week the burn wallet's USDC (the 30%
// share, moved there by the weekly revenue settlement) buys the token in at
// least 24 randomized chunks with at most 1% slippage, straight into the rewards
// program's burn account, and each chunk is burned. Flag MORSE_BURN_MODE.
import { getBase64Encoder, getTransactionDecoder, partiallySignTransaction } from '@solana/kit';
import { ata, createAtaIdempotent, decodeTokenAccount, rewardsAddresses, rewardsInstructions } from './judge.mjs';

export const WEEK_MS = 604_800_000;
export const MIN_CHUNKS = 24;
export const MAX_SLIPPAGE_BPS = 100;
export const DEFAULT_SWAP_API = 'https://lite-api.jup.ag/swap/v1';

// `total` base units over [startMs, endMs): one chunk per equal slot at a random
// point in its first 90%, sizes random between 0.5 and 1.5 of the mean, every
// chunk at least one unit, adding up exactly.
export function planChunks(total, { startMs, endMs, count = MIN_CHUNKS, random = Math.random }) {
  const n = BigInt(count);
  if (total < n) return [];
  const weights = Array.from({ length: count }, () => BigInt(Math.floor((0.5 + random()) * 1e6)));
  const sum = weights.reduce((a, b) => a + b, 0n);
  const spare = total - n;
  const amounts = weights.map(weight => 1n + spare * weight / sum);
  amounts[count - 1] += total - amounts.reduce((a, b) => a + b, 0n);
  const slot = (endMs - startMs) / count;
  return amounts.map((amount, i) => ({ dueMs: Math.floor(startMs + i * slot + random() * slot * 0.9), amount }));
}

// A quote must be for exactly the planned trade, allow at most 1% slippage and
// move the price by at most 1%.
export function checkQuote(quote, { usdc, token, amount }) {
  if (quote.inputMint !== usdc || quote.outputMint !== token || BigInt(quote.inAmount) !== amount || !(BigInt(quote.outAmount) > 0n)) {
    throw new Error('quote does not match the planned trade');
  }
  const out = BigInt(quote.outAmount);
  if (!(Number(quote.slippageBps) <= MAX_SLIPPAGE_BPS) || !(Number(quote.priceImpactPct) <= MAX_SLIPPAGE_BPS / 10_000)
    || BigInt(quote.otherAmountThreshold) < out * BigInt(10_000 - MAX_SLIPPAGE_BPS) / 10_000n) {
    throw new Error('quote exceeds the 1% slippage limit');
  }
}

const balanceOf = async (chain, account) => {
  const found = await chain.account(account);
  return found ? decodeTokenAccount(found.data).amount : 0n;
};

async function burnChunk({ chain, rewards, usdc, token, wallet, payer, fetcher, api, amount, alert }) {
  const burnAuthority = await rewardsAddresses(rewards).burn();
  const destination = await ata(burnAuthority, token);
  if (!(await chain.account(destination))) await chain.send([await createAtaIdempotent(payer.address, burnAuthority, token)], { payer });
  const signal = AbortSignal.timeout(30_000);
  const quote = await (await fetcher(`${api}/quote?inputMint=${usdc}&outputMint=${token}&amount=${amount}&slippageBps=${MAX_SLIPPAGE_BPS}&swapMode=ExactIn`, { signal })).json();
  checkQuote(quote, { usdc, token, amount });
  const swap = await (await fetcher(`${api}/swap`, { method: 'POST', signal, headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quoteResponse: quote, userPublicKey: wallet.address, destinationTokenAccount: destination,
      wrapAndUnwrapSol: false, dynamicComputeUnitLimit: true }) })).json();
  const transaction = getTransactionDecoder().decode(getBase64Encoder().encode(swap.swapTransaction));
  // The API picks the route; it may not add a signer. The wallet only ever holds
  // this week's burn share, which bounds what a hostile route could take.
  const signers = Object.keys(transaction.signatures);
  if (signers.length !== 1 || signers[0] !== wallet.address) throw new Error('swap transaction needs a signer other than the burn wallet');
  const before = await balanceOf(chain, destination);
  const { signature } = await chain.sendSigned(await partiallySignTransaction([wallet.keyPair], transaction));
  const received = (await balanceOf(chain, destination)) - before;
  if (received * 10_000n < BigInt(quote.outAmount) * BigInt(10_000 - MAX_SLIPPAGE_BPS)) {
    alert(`WARN burn_slippage chunk=${amount} expected=${quote.outAmount} received=${received} tx=${signature}`);
  }
  await chain.send([await rewardsInstructions(rewards).burn({ tokenMint: token })], { payer });
  return { signature, received };
}

// One minute's work: plan the week on its first tick (half the balance when last
// week had no plan, so a backlog spreads over two weeks), then run a due chunk.
// A chunk failing three times stays unspent in the wallet for later weeks.
export async function burnTick({ env, chain, rewards, usdc, token, wallet, payer, state, fetcher = fetch, api = DEFAULT_SWAP_API,
  nowMs = Date.now(), random = Math.random, alert = console.error }) {
  if (env.MORSE_BURN_MODE !== 'on') return null;
  const week = Math.floor(nowMs / WEEK_MS);
  let plan = state.get(`burn:${week}`);
  if (!plan) {
    const balance = await balanceOf(chain, await ata(wallet.address, usdc));
    const budget = state.get(`burn:${week - 1}`) ? balance : balance / 2n;
    plan = { budget: String(budget), chunks: planChunks(budget, { startMs: nowMs, endMs: (week + 1) * WEEK_MS, random })
      .map(c => ({ dueMs: c.dueMs, amount: String(c.amount), status: 'pending', attempts: 0 })) };
    state.set(`burn:${week}`, plan);
  }
  const chunk = plan.chunks.find(c => c.status === 'pending' && c.dueMs <= nowMs);
  if (!chunk) return plan;
  try {
    const { signature, received } = await burnChunk({ chain, rewards, usdc, token, wallet, payer, fetcher, api, amount: BigInt(chunk.amount), alert });
    Object.assign(chunk, { status: 'done', signature, received: String(received), doneMs: nowMs });
    // Every burn stays listed on the public status page.
    state.set('burn:history', [...(state.get('burn:history') ?? []), { week, spent: chunk.amount, burned: String(received), signature, at: new Date(nowMs).toISOString() }]);
  } catch (error) {
    chunk.attempts += 1;
    if (chunk.attempts >= 3) chunk.status = 'failed';
    alert(`WARN burn_chunk_failed amount=${chunk.amount} attempt=${chunk.attempts}: ${String(error.message).slice(0, 200)}`);
  }
  state.set(`burn:${week}`, plan);
  return plan;
}
