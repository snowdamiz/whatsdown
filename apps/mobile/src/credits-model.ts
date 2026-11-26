import { formatUnits } from './bounty-notice.ts';

// Credits (plan §6.10, §10; protocol/credits-v1.md "Client"): what the core's
// credit exports answer, and what the screens say about it. Pure, so it runs
// under node's test runner; credits.ts carries the calls.

export const PACKS = [
  { pack: 1, credits: 100, usd: 5 },
  { pack: 2, credits: 500, usd: 25 },
  { pack: 3, credits: 2000, usd: 100 },
] as const;
export type Pack = (typeof PACKS)[number]['pack'];

export const ASSETS = [
  { asset: 1, label: 'USDC' },
  { asset: 2, label: 'SOL' },
  { asset: 3, label: 'Bitcoin' },
] as const;
export type Asset = (typeof ASSETS)[number]['asset'];

export const INBOX_PRICES = [0, 1, 5, 25] as const;
export type InboxPrice = (typeof INBOX_PRICES)[number];

export const STORAGE_PERIOD_DAYS = 30;
export const STORAGE_PERIOD_CREDITS = 10;
export const SIGNUP_CREDITS = 20;

export const PURCHASE_STATES = ['quoted', 'paid', 'issuing', 'issued', 'expired', 'unpaid', 'reissue', 'operator'] as const;
export type PurchaseState = (typeof PURCHASE_STATES)[number];

export type Purchase = {
  id: Uint8Array;
  state: PurchaseState;
  pack: number;
  asset: number;
  batch: number;
  // Base units of the asset: USDC micro-units, lamports or satoshis.
  amount: bigint;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  issued: number;
  // The purchase reference: whoever holds it can collect the pack, so it is
  // only shown when Morse needs it (a refund, or a purchase only Morse can finish).
  quoteId: Uint8Array;
  paymentRequest: string;
  payment: string;
};

export type CreditsStatus = {
  // This build sells credits (it pins an issuer).
  sold: boolean;
  purpose: 'live' | 'test' | null;
  spendable: number;
  // Bought in the last ten minutes: spendable once the cool-down ends.
  cooling: number;
  coolingUntil: number;
  // Credits whose key's window ends first, and when.
  expiring: number;
  expiringAt: number;
  keysFetchedAt: number;
  inboxPrice: number;
  retentionDays: number;
  retentionUntil: number;
  purchases: Purchase[];
};

export const ISSUE_OUTCOMES = ['issued', 'pending', 'expired', 'unpaid', 'operator', 'stale-key', 'unavailable', 'interrupted', 'current'] as const;
export type IssueOutcome = (typeof ISSUE_OUTCOMES)[number];

export type Spend = { id: Uint8Array; credits: number; request: Uint8Array };
export type SettleResult = 'spent' | 'returned' | 'kept' | 'refresh-keys';
export type PostageCheck = { price: number; spendable: number; username: string };

class Read {
  private offset = 0;
  private readonly input: Uint8Array;
  constructor(input: Uint8Array) { this.input = input; }
  take(length: number): Uint8Array {
    if (this.offset + length > this.input.length) throw new Error('bad_frame');
    this.offset += length;
    return this.input.subarray(this.offset - length, this.offset);
  }
  byte(): number { return this.take(1)[0]!; }
  u16(): number { const b = this.take(2); return (b[0]! << 8) | b[1]!; }
  u32(): number { const b = this.take(4); return new DataView(b.buffer, b.byteOffset, 4).getUint32(0); }
  u64(): bigint { const b = this.take(8); return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0); }
  vector(): Uint8Array { return this.take(this.u32()); }
  text(): string { return new TextDecoder('utf-8', { fatal: true }).decode(this.vector()); }
  end(): void { if (this.offset !== this.input.length) throw new Error('bad_frame'); }
}

const time = (value: bigint): number => Number(value);

function readPurchase(read: Read): Purchase {
  const id = read.take(16).slice();
  const state = PURCHASE_STATES[read.byte() - 1];
  if (!state) throw new Error('bad_frame');
  return {
    id,
    state,
    pack: read.byte(),
    asset: read.byte(),
    batch: read.u16(),
    amount: read.u64(),
    createdAt: time(read.u64()),
    updatedAt: time(read.u64()),
    expiresAt: time(read.u64()),
    issued: read.u32(),
    quoteId: read.take(32).slice(),
    paymentRequest: read.text(),
    payment: read.text(),
  };
}

export function parsePurchase(input: Uint8Array): Purchase {
  const read = new Read(input);
  const value = readPurchase(read);
  read.end();
  return value;
}

// Mobile.CreditsSpend "CST".
export function parseCreditsStatus(input: Uint8Array): CreditsStatus {
  const read = new Read(input);
  if (read.byte() !== 1 || new TextDecoder().decode(read.take(3)) !== 'CST') throw new Error('bad_frame');
  const sold = read.byte() === 1;
  const purpose = read.byte();
  const status = {
    sold,
    purpose: purpose === 1 ? 'live' as const : purpose === 2 ? 'test' as const : null,
    spendable: read.u32(),
    cooling: read.u32(),
    coolingUntil: time(read.u64()),
    expiring: read.u32(),
    expiringAt: time(read.u64()),
    keysFetchedAt: time(read.u64()),
    inboxPrice: read.byte(),
    retentionDays: read.u16(),
    retentionUntil: time(read.u64()),
    purchases: [] as Purchase[],
  };
  const count = read.byte();
  for (let index = 0; index < count; index += 1) status.purchases.push(parsePurchase(read.vector()));
  read.end();
  return status;
}

export function parseIssue(input: Uint8Array): { outcome: IssueOutcome; purchase: Purchase } {
  const read = new Read(input);
  const outcome = ISSUE_OUTCOMES[read.byte() - 1];
  if (!outcome) throw new Error('bad_frame');
  const purchase = readPurchase(read);
  read.end();
  return { outcome, purchase };
}

export function parseSpend(input: Uint8Array): Spend {
  const read = new Read(input);
  const spend = { id: read.take(16).slice(), credits: read.byte(), request: read.vector().slice() };
  read.end();
  return spend;
}

const SETTLED: Record<number, SettleResult> = { 1: 'spent', 2: 'returned', 3: 'kept', 4: 'refresh-keys' };

export function parseSettle(input: Uint8Array): SettleResult {
  const result = input.length === 1 ? SETTLED[input[0]!] : undefined;
  if (!result) throw new Error('bad_frame');
  return result;
}

export function parsePostageCheck(input: Uint8Array): PostageCheck {
  const read = new Read(input);
  const check = { price: read.byte(), spendable: read.u32(), username: read.text() };
  read.end();
  return check;
}

// Each of a peer's devices that asks a price and has not handed this device a
// contact address: its public mailbox and its price.
export function parsePostageQuote(input: Uint8Array): { mailbox: string; price: number }[] {
  const read = new Read(input);
  const rows = Array.from({ length: read.byte() }, () => ({
    mailbox: Array.from(read.take(32), (byte) => byte.toString(16).padStart(2, '0')).join(''),
    price: read.byte(),
  }));
  read.end();
  return rows;
}

// A 429 from registration carries WRK: the difficulty needed now and the
// sign-up price in credits.
export function parseSignupWork(input: Uint8Array): { difficulty: number; credits: number } | null {
  if (input.length !== 6 || input[0] !== 1 || new TextDecoder().decode(input.subarray(1, 4)) !== 'WRK') return null;
  return { difficulty: input[4]!, credits: input[5]! };
}

// The 16-bit status the core's settle export takes (0: no answer).
export function statusBytes(status: number): Uint8Array {
  if (!Number.isInteger(status) || status < 0 || status > 0xffff) throw new RangeError('bad_status');
  return Uint8Array.of(status >> 8, status & 0xff);
}

// The attachment path settles a take as spent, returned, or unknown.
export const attachmentStatus = (spent: boolean | undefined): number => (spent === true ? 201 : spent === false ? 400 : 0);

// network.ts's CreditSource over the core's token store: a take is one core
// spend (its tokens, for the attachment grant the core frames itself), settled
// through the same path as every other spend.
export function attachmentCreditSource(
  balance: () => Promise<number>,
  spend: (count: number) => Promise<Spend>,
  settle: (id: Uint8Array, status: number) => Promise<unknown>,
): {
  balance: () => Promise<number>;
  take: (count: number) => Promise<{ tokens: Uint8Array; settle: (spent: boolean | undefined) => Promise<void> }>;
} {
  return {
    balance,
    take: async (count) => {
      const taken = await spend(count);
      if (taken.credits !== count || taken.request.length !== count * 354) throw new Error('bad_frame');
      return { tokens: taken.request, settle: async (spent) => { await settle(taken.id, attachmentStatus(spent)); } };
    },
  };
}

const DECIMALS: Record<number, number> = { 1: 6, 2: 9, 3: 0 };

export function formatAmount(asset: number, amount: bigint): string {
  if (asset === 3) return `${formatUnits(amount, 0)} sats`;
  return `${formatUnits(amount, DECIMALS[asset] ?? 0)} ${asset === 1 ? 'USDC' : 'SOL'}`;
}

export const packLabel = (pack: number): string => {
  const found = PACKS.find((item) => item.pack === pack);
  return found ? `${found.credits.toLocaleString('en-US')} credits` : 'Credits';
};

export const credits = (count: number): string => `${count.toLocaleString('en-US')} ${count === 1 ? 'credit' : 'credits'}`;

// A Solana Pay request the in-app wallet may pay for this purchase: to one
// deposit, for exactly the quoted amount, in the quoted asset.
export function payable(purchase: Purchase, request: {
  amount: { mantissa: bigint; scale: number } | null;
  splToken: string | null;
}, usdcMint: string): boolean {
  if (purchase.asset === 3 || !request.amount) return false;
  const decimals = purchase.asset === 1 ? 6 : 9;
  if (request.amount.scale > decimals) return false;
  const units = request.amount.mantissa * 10n ** BigInt(decimals - request.amount.scale);
  const token = purchase.asset === 1 ? usdcMint : null;
  return units === purchase.amount && request.splToken === token;
}

// How long to wait before asking the issuer again about a purchase that is not
// paid or final yet: every batch asked with is half a megabyte for the largest
// pack, so the wait grows to 20 seconds.
export function pollDelay(attempt: number): number {
  return Math.min(5_000 + attempt * 5_000, 20_000);
}

// A purchase worth asking the issuer about again without being told to.
export const resumable = (purchase: Purchase): boolean =>
  purchase.state === 'paid' || purchase.state === 'issuing' || purchase.state === 'reissue';

export const waitingForPayment = (purchase: Purchase, now: number): boolean =>
  purchase.state === 'quoted' && now < purchase.expiresAt + 120_000;

// What each purchase in the list offers: its reference to copy (for a refund
// or for support), paying, collecting, or trying again once Morse re-opened it.
export type PurchaseAction = 'copy-reference' | 'retry' | 'pay' | 'collect';

export function purchaseActions(purchase: Purchase, now: number): PurchaseAction[] {
  if (purchase.state === 'operator') return ['copy-reference', 'retry'];
  if (purchase.state === 'unpaid') return ['copy-reference'];
  if (purchase.state === 'quoted' && now < purchase.expiresAt) return ['pay'];
  if (purchase.state === 'reissue' || purchase.state === 'paid' || purchase.state === 'issuing') return ['collect'];
  return [];
}

export const OPERATOR_RETRY_REFUSED = 'Send the reference to support with your payment proof.';

// What the purchase list says of each purchase.
export function purchaseLine(purchase: Purchase, now: number): string {
  switch (purchase.state) {
    case 'quoted':
      return now < purchase.expiresAt ? 'Waiting for payment' : 'Quote ran out';
    case 'paid':
      return 'Paid. Collecting your credits…';
    case 'issuing':
      return 'Collecting your credits…';
    case 'issued':
      return `${credits(purchase.issued)} added`;
    case 'expired':
      return 'Quote ran out before a payment arrived';
    case 'unpaid':
      return 'The payment was short, late or to another quote. Morse refunds it on request.';
    case 'reissue':
      return 'The key that signed these was replaced. Collect them again.';
    case 'operator':
      return 'The app closed while your credits were being collected. Morse can finish this purchase for you.';
  }
}

// Shown to the person when the core said why a purchase stopped.
export function outcomeMessage(outcome: IssueOutcome): string | null {
  switch (outcome) {
    case 'issued':
      return null;
    case 'pending':
      return 'Waiting for the payment to be final.';
    case 'expired':
      return 'The quote ran out before the payment arrived.';
    case 'unpaid':
      return 'The payment doesn’t match this quote. Morse refunds it on request, with the purchase reference.';
    case 'operator':
      return 'Morse signed your credits, but this device couldn’t store them. Contact Morse with the purchase reference to finish it.';
    case 'stale-key':
      return 'Credit keys changed. Trying again…';
    case 'unavailable':
      return 'Credits can’t be collected right now. Try again later: your payment is safe.';
    case 'interrupted':
      return 'The connection dropped while collecting your credits. Try again: nothing is lost yet.';
    case 'current':
      return 'Nothing to collect again: these credits are still good.';
  }
}

export const PUBLIC_PURCHASE_NOTICE =
  'A purchase is as public as any on-chain payment: anyone can see the paying address send to Morse. Your credits aren’t linked to it or to your account. Buy in batches, from a wallet you don’t mind being seen.';

export const COOLDOWN_NOTICE = 'New credits can be spent 10 minutes after they arrive, so a purchase can’t be timed to what it pays for.';

export const OPERATOR_NOTICE =
  'Keep Morse open while credits are collected. If the app closes at that moment, only Morse can finish the purchase.';

export function balanceLine(status: CreditsStatus, now: number): string {
  const parts: string[] = [];
  if (status.cooling > 0) {
    const minutes = Math.max(1, Math.ceil((status.coolingUntil - now) / 60_000));
    parts.push(`${credits(status.cooling)} ready in ${minutes} min`);
  }
  if (status.expiring > 0 && status.expiringAt > 0) {
    const date = new Date(status.expiringAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    parts.push(`${credits(status.expiring)} expire ${date}`);
  }
  return parts.join(' · ');
}

// Asking a stranger's inbox: shown before a first message (and before a
// queued one waits on it).
export function postageQuestion(username: string, price: number, total: number, spendable: number): {
  title: string;
  body: string;
  affordable: boolean;
} {
  const who = username ? `@${username}` : 'This person';
  const each = total > price ? ` This message goes to ${Math.round(total / price)} of their devices, so it uses ${credits(total)}.` : '';
  return {
    title: `${who} charges ${credits(price)} for message requests`,
    body: `Messages you send before they reply use credits.${each} You have ${credits(spendable)}.`,
    affordable: spendable >= total,
  };
}

export const inboxPriceLabel = (price: number): string => (price === 0 ? 'Free' : credits(price));
