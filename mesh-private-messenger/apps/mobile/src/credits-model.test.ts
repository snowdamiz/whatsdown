import assert from 'node:assert/strict';
import test from 'node:test';

import {
  attachmentCreditSource,
  attachmentStatus,
  balanceLine,
  parseCreditsStatus,
  parseIssue,
  parsePostageCheck,
  parsePostageQuote,
  parseSettle,
  parseSignupWork,
  parseSpend,
  payable,
  pollDelay,
  postageQuestion,
  purchaseActions,
  purchaseLine,
  resumable,
  statusBytes,
  type Purchase,
} from './credits-model.ts';

const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const u8 = (value: number) => Uint8Array.of(value);
const u16 = (value: number) => Uint8Array.of(value >> 8, value & 0xff);
const u32 = (value: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, value); return b; };
const u64 = (value: number | bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(value)); return b; };
const text = (value: string) => { const bytes = new TextEncoder().encode(value); return cat(u32(bytes.length), bytes); };

// Mobile.CreditsBuy's purchase frame.
function purchaseFrame(state: number, issued: number): Uint8Array {
  return cat(new Uint8Array(16).fill(1), u8(state), u8(1), u8(1), u16(100), u64(5_000_000), u64(10), u64(20), u64(30),
    u32(issued), new Uint8Array(32).fill(2), text('solana:dep?amount=5'), text('sig'));
}

test('a status names the balance, what is cooling down, the inbox price and each purchase', () => {
  const head = cat(u8(1), new TextEncoder().encode('CST'), u8(1), u8(2), u32(95), u32(100), u64(1_000), u32(195),
    u64(5_000_000_000), u64(7), u8(5), u16(90), u64(9_000));
  const withPurchases = cat(head, u8(2),
    u32(purchaseFrame(4, 100).length), purchaseFrame(4, 100), u32(purchaseFrame(8, 0).length), purchaseFrame(8, 0));
  const status = parseCreditsStatus(withPurchases);
  assert.equal(status.sold, true);
  assert.equal(status.purpose, 'test');
  assert.deepEqual([status.spendable, status.cooling, status.expiring, status.inboxPrice, status.retentionDays],
    [95, 100, 195, 5, 90]);
  assert.deepEqual(status.purchases.map((purchase) => purchase.state), ['issued', 'operator']);
  assert.equal(status.purchases[0]!.amount, 5_000_000n);
  assert.equal(status.purchases[0]!.paymentRequest, 'solana:dep?amount=5');
  assert.throws(() => parseCreditsStatus(cat(withPurchases, u8(0))), /bad_frame/);
});

test('an issue answer names its outcome and the purchase as it stands', () => {
  const answer = parseIssue(cat(u8(5), purchaseFrame(8, 0)));
  assert.equal(answer.outcome, 'operator');
  assert.equal(answer.purchase.state, 'operator');
  assert.equal(parseIssue(cat(u8(9), purchaseFrame(4, 100))).outcome, 'current');
  assert.throws(() => parseIssue(cat(u8(10), purchaseFrame(1, 0))), /bad_frame/);
});

test('spend, settle, postage and sign-up frames decode, and nothing else does', () => {
  const spend = parseSpend(cat(new Uint8Array(16).fill(3), u8(5), u32(3), Uint8Array.of(1, 2, 3)));
  assert.equal(spend.credits, 5);
  assert.deepEqual([...spend.request], [1, 2, 3]);
  assert.equal(parseSettle(u8(4)), 'refresh-keys');
  assert.throws(() => parseSettle(u8(9)), /bad_frame/);
  assert.deepEqual(parsePostageCheck(cat(u8(25), u32(40), text('bob'))), { price: 25, spendable: 40, username: 'bob' });
  assert.deepEqual(parsePostageQuote(cat(u8(1), new Uint8Array(32).fill(0xab), u8(5))),
    [{ mailbox: 'ab'.repeat(32), price: 5 }]);
  assert.deepEqual(parseSignupWork(cat(u8(1), new TextEncoder().encode('WRK'), u8(12), u8(20))), { difficulty: 12, credits: 20 });
  assert.equal(parseSignupWork(new Uint8Array()), null);
  assert.deepEqual([...statusBytes(402)], [1, 146]);
  assert.deepEqual([attachmentStatus(true), attachmentStatus(false), attachmentStatus(undefined)], [201, 400, 0]);
});

const purchase = (changes: Partial<Purchase>): Purchase => ({
  id: new Uint8Array(16), state: 'quoted', pack: 1, asset: 1, batch: 100, amount: 5_000_000n,
  createdAt: 0, updatedAt: 0, expiresAt: 1_000, issued: 0, quoteId: new Uint8Array(32),
  paymentRequest: '', payment: '', ...changes,
});

test('the wallet pays a quote only for its exact amount in its own asset', () => {
  assert.equal(payable(purchase({}), { amount: { mantissa: 5n, scale: 0 }, splToken: USDC }, USDC), true);
  assert.equal(payable(purchase({}), { amount: { mantissa: 6n, scale: 0 }, splToken: USDC }, USDC), false);
  assert.equal(payable(purchase({}), { amount: { mantissa: 5n, scale: 0 }, splToken: null }, USDC), false);
  const sol = purchase({ asset: 2, amount: 33_333_334n });
  assert.equal(payable(sol, { amount: { mantissa: 33_333_334n, scale: 9 }, splToken: null }, USDC), true);
  assert.equal(payable(sol, { amount: { mantissa: 33_333_334n, scale: 9 }, splToken: USDC }, USDC), false);
  assert.equal(payable(purchase({ asset: 3 }), { amount: { mantissa: 1n, scale: 0 }, splToken: null }, USDC), false);
});

test('purchases worth resuming are the paid, interrupted and re-issuable ones', () => {
  assert.deepEqual(['quoted', 'paid', 'issuing', 'issued', 'reissue', 'operator']
    .map((state) => resumable(purchase({ state: state as Purchase['state'] }))),
  [false, true, true, false, true, false]);
  assert.match(purchaseLine(purchase({ state: 'operator' }), 0), /Morse can finish/);
  assert.equal(purchaseLine(purchase({ state: 'quoted' }), 2_000), 'Quote ran out');
  assert.deepEqual([0, 1, 2, 3, 10].map(pollDelay), [5_000, 10_000, 15_000, 20_000, 20_000]);
});

test('the postage question names the recipient, the price and whether it is affordable', () => {
  const single = postageQuestion('bob', 5, 5, 3);
  assert.equal(single.title, '@bob charges 5 credits for message requests');
  assert.equal(single.affordable, false);
  assert.match(postageQuestion('bob', 5, 10, 40).body, /2 of their devices, so it uses 10 credits/);
  assert.match(balanceLine({ ...parseCreditsStatus(cat(u8(1), new TextEncoder().encode('CST'), u8(1), u8(1), u32(0),
    u32(100), u64(120_000), u32(0), u64(0), u64(0), u8(0), u16(0), u64(0), u8(0))) }, 0), /100 credits ready in 2 min/);
});

test('large files take their tokens from the core store and settle through it', async () => {
  const settled: [number, number][] = [];
  const source = attachmentCreditSource(
    async () => 7,
    async (count) => ({ id: Uint8Array.of(count), credits: count, request: new Uint8Array(count * 354).fill(9) }),
    async (id, status) => { settled.push([id[0]!, status]); },
  );
  assert.equal(await source.balance(), 7);
  const taken = await source.take(3);
  assert.equal(taken.tokens.length, 3 * 354);
  await taken.settle(true);
  await (await source.take(1)).settle(false);
  await (await source.take(2)).settle(undefined);
  assert.deepEqual(settled, [[3, 201], [1, 400], [2, 0]]);
  const short = attachmentCreditSource(async () => 0,
    async () => ({ id: new Uint8Array(16), credits: 1, request: new Uint8Array(354) }), async () => {});
  await assert.rejects(short.take(2), /bad_frame/);
});

test('trying a purchase again is offered only when Morse has to finish it', () => {
  const states = ['quoted', 'paid', 'issuing', 'issued', 'expired', 'unpaid', 'reissue', 'operator'] as const;
  const offered = states.filter((state) => purchaseActions(purchase({ state }), 0).includes('retry'));
  assert.deepEqual(offered, ['operator']);
  assert.deepEqual(purchaseActions(purchase({ state: 'operator' }), 0), ['copy-reference', 'retry']);
  assert.deepEqual(purchaseActions(purchase({ state: 'unpaid' }), 0), ['copy-reference']);
  assert.deepEqual(purchaseActions(purchase({ state: 'quoted' }), 2_000), []);
});
