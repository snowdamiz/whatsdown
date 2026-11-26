import {
  credits_group_handover_export,
  credits_inbox_policy_export,
  credits_issue_export,
  credits_postage_export,
  credits_quote_export,
  credits_refresh_keys_export,
  credits_register_at_export,
  credits_retention_export,
  credits_settle_export,
  credits_signup_export,
  credits_spend_export,
  credits_status_export,
} from '../modules/mesh-messenger';
import { utf8, vectors } from './codec';
import {
  SIGNUP_CREDITS,
  attachmentCreditSource,
  parseCreditsStatus,
  parseIssue,
  parsePurchase,
  parsePostageCheck,
  parsePostageQuote,
  parseSettle,
  parseSignupWork,
  parseSpend,
  payable,
  pollDelay,
  postageQuestion,
  resumable,
  statusBytes,
  type CreditsStatus,
  type IssueOutcome,
  type Purchase,
  type SettleResult,
} from './credits-model.ts';
import { drainOutbox, setCreditHooks, setCreditSource } from './network';
import { pay, pinnedRpc } from './solana.ts';
import { fetch } from './transport';
import { parsePayUrl } from './wallet.ts';

// The app's side of credits (plan §6.10, §10). The core does every step that
// touches a token or a blinding state, and the requests that need them go out
// from the core itself (issuer keys, quotes, issuing); what the app sends here
// already carries its tokens inside, and each answer goes back to the core.

const baseUrl = (process.env.EXPO_PUBLIC_MESSENGER_BASE_URL ?? 'http://127.0.0.1:18086').replace(/\/$/, '');

function edgeUrl(): string {
  const value = process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL?.replace(/\/$/, '');
  if (!value) throw new Error('EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL is required');
  return value;
}

type Answer = { status: number; body: Uint8Array };

// No answer at all is status 0: the core treats it as "may have been spent".
async function send(url: string, method: 'POST' | 'PUT', body: Uint8Array): Promise<Answer> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      method,
      redirect: 'error',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
      signal: controller.signal,
    });
    return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
  } catch {
    return { status: 0, body: new Uint8Array() };
  } finally {
    clearTimeout(timeout);
  }
}

const listeners = new Set<() => void>();

// Told whenever the balance or a purchase may have changed.
export function onCreditsChanged(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

function changed(): void {
  for (const listener of listeners) {
    try { listener(); } catch { /* Reporting is best effort. */ }
  }
}

export async function loadCredits(databasePath: string): Promise<CreditsStatus> {
  return parseCreditsStatus(await credits_status_export(vectors(utf8(databasePath))));
}

// Issuer keys from the directory, each checked against the transparency log.
export async function refreshCreditKeys(databasePath: string): Promise<number> {
  const answer = await credits_refresh_keys_export(vectors(utf8(databasePath), utf8(baseUrl)));
  changed();
  return answer[0] ?? 0;
}

const KEYS_FRESH_MS = 6 * 60 * 60 * 1000;

async function freshKeys(databasePath: string): Promise<void> {
  const status = await loadCredits(databasePath);
  if (Date.now() - status.keysFetchedAt > KEYS_FRESH_MS) await refreshCreditKeys(databasePath);
}

// A quote through the privacy edge, kept by the core as a new purchase.
export async function quoteCredits(databasePath: string, pack: number, asset: number): Promise<Purchase> {
  await freshKeys(databasePath);
  const ask = () => credits_quote_export(vectors(utf8(databasePath), utf8(edgeUrl()), Uint8Array.of(pack), Uint8Array.of(asset)));
  let answer: Uint8Array;
  try {
    answer = await ask();
  } catch (error) {
    if (!/credits_key_unknown|credits_keys_needed/.test(String(error))) throw error;
    await refreshCreditKeys(databasePath);
    answer = await ask();
  }
  changed();
  return parsePurchase(answer);
}

// Collects a purchase's tokens, or learns why not yet. A key change on the
// issuer's side (412) is fetched and tried once more.
export async function collectCredits(
  databasePath: string,
  purchase: Purchase,
  payment = '',
): Promise<{ outcome: IssueOutcome; purchase: Purchase }> {
  const once = async () => parseIssue(await credits_issue_export(
    vectors(utf8(databasePath), utf8(edgeUrl()), purchase.id, utf8(payment)),
  ));
  let answer = await once();
  if (answer.outcome === 'stale-key') {
    await refreshCreditKeys(databasePath);
    answer = await once();
  }
  changed();
  return answer;
}

// Pays a USDC or SOL quote from the in-app wallet, waits for it to be final,
// and collects the credits.
export async function payFromWallet(databasePath: string, purchase: Purchase): Promise<{ outcome: IssueOutcome; purchase: Purchase }> {
  const request = await parsePayUrl(purchase.paymentRequest);
  const rpc = await pinnedRpc();
  if (!rpc?.usdcMint) throw new Error('This build has no Solana connection for the wallet.');
  if (!payable(purchase, request, rpc.usdcMint)) throw new Error('This quote asks for a different payment than it names.');
  const signature = await pay(rpc, request);
  return waitForCredits(databasePath, purchase, signature);
}

const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Asks the issuer until the purchase settles one way or the other: a payment
// from another wallet or over Lightning, or one the issuer does not see as
// final yet. Stops when the quote has run out, or when `stopped` says so.
export async function waitForCredits(
  databasePath: string,
  purchase: Purchase,
  payment = '',
  stopped: () => boolean = () => false,
  wait = pause,
): Promise<{ outcome: IssueOutcome; purchase: Purchase }> {
  for (let attempt = 0; ; attempt += 1) {
    const answer = await collectCredits(databasePath, purchase, payment);
    const open = answer.outcome === 'pending' || answer.outcome === 'interrupted' || answer.outcome === 'unavailable';
    if (!open || stopped() || Date.now() > answer.purchase.expiresAt + 120_000) return answer;
    await wait(pollDelay(attempt));
  }
}

// Purchases left paid, mid-exchange or to collect again: asked once each, as
// the app starts and whenever Credits opens.
export async function resumePurchases(databasePath: string): Promise<void> {
  const status = await loadCredits(databasePath);
  for (const purchase of status.purchases.filter(resumable)) {
    try { await collectCredits(databasePath, purchase, purchase.payment); } catch { /* Tried again later. */ }
  }
}

async function settle(databasePath: string, id: Uint8Array, status: number, body: Uint8Array = new Uint8Array()): Promise<SettleResult> {
  const result = parseSettle(await credits_settle_export(vectors(utf8(databasePath), id, statusBytes(status), body)));
  if (result === 'refresh-keys') await refreshCreditKeys(databasePath).catch(() => {});
  changed();
  return result;
}

// Longer storage for this device's mailbox: `periods` x 30 days.
export async function buyStorage(databasePath: string, periods: number): Promise<void> {
  const spend = parseSpend(await credits_retention_export(vectors(utf8(databasePath), Uint8Array.of(periods))));
  const answer = await send(`${edgeUrl()}/v1/mailbox/retention`, 'POST', spend.request);
  await settle(databasePath, spend.id, answer.status, answer.body);
  if (answer.status !== 201) {
    throw new Error(answer.status === 0 ? 'No answer from Morse. Try again: the same credits are used.' : `Storage wasn’t added (${answer.status}).`);
  }
}

// This device's price for message requests from strangers, signed and
// published; a priced inbox then hands its contact address to its groups.
export async function setInboxPrice(databasePath: string, price: number): Promise<void> {
  const policy = await credits_inbox_policy_export(vectors(utf8(databasePath), Uint8Array.of(price)));
  const answer = await send(`${baseUrl}/v1/mailbox/policy`, 'PUT', policy);
  if (answer.status !== 201 && answer.status !== 200) {
    throw new Error(answer.status === 0 ? 'No answer from Morse. Try again.' : `The price wasn’t saved (${answer.status}).`);
  }
  lastHandover = 0;
  await drainOutbox(databasePath).catch(() => {});
  changed();
}

// The prompts credits need (CreditPrompts shows them): a price to pay, or a
// busy sign-up to skip.
export type CreditQuestion =
  | { kind: 'postage'; title: string; body: string; affordable: boolean }
  | { kind: 'signup'; credits: number; spendable: number };
type Asked = { question: CreditQuestion; answer: (yes: boolean) => void };
const asking = new Set<(asked: Asked) => void>();

export function onCreditQuestion(listener: (asked: Asked) => void): () => void {
  asking.add(listener);
  return () => { asking.delete(listener); };
}

// Nobody showing prompts (a background pass) is a no.
function ask(question: CreditQuestion): Promise<boolean> {
  if (asking.size === 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    let settled = false;
    const answer = (yes: boolean) => { if (!settled) { settled = true; resolve(yes); } };
    for (const listener of asking) listener({ question, answer });
  });
}

// Prices the person agreed to, by recipient mailbox, for this run of the app.
const approved = new Map<string, number>();

async function firstContact(databasePath: string, username: string, priced: Uint8Array): Promise<boolean> {
  const rows = parsePostageQuote(priced);
  if (rows.every((row) => (approved.get(row.mailbox) ?? -1) >= row.price)) return true;
  const total = rows.reduce((sum, row) => sum + row.price, 0);
  const { spendable } = await loadCredits(databasePath);
  const question = postageQuestion(username, Math.max(...rows.map((row) => row.price)), total, spendable);
  const yes = await ask({ kind: 'postage', ...question });
  if (yes) for (const row of rows) approved.set(row.mailbox, row.price);
  return yes;
}

const mailboxOf = (envelope: Uint8Array): string =>
  Array.from(envelope.subarray(20, 52), (byte) => byte.toString(16).padStart(2, '0')).join('');

async function postage(databasePath: string, envelope: Uint8Array, policy: Uint8Array): Promise<'paid' | 'declined' | 'waiting'> {
  let check;
  try {
    check = parsePostageCheck(await credits_postage_export(vectors(utf8(databasePath), envelope, policy, Uint8Array.of(0))));
  } catch {
    // A price nobody here can verify is not paid.
    return 'waiting';
  }
  const mailbox = mailboxOf(envelope);
  if ((approved.get(mailbox) ?? -1) < check.price) {
    const yes = await ask({ kind: 'postage', ...postageQuestion(check.username, check.price, check.price, check.spendable) });
    if (!yes) return asking.size === 0 ? 'waiting' : 'declined';
    approved.set(mailbox, check.price);
  }
  // A 409 (a token already spent) is tried once more with fresh tokens.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let spend;
    try {
      spend = parseSpend(await credits_postage_export(vectors(utf8(databasePath), envelope, policy, Uint8Array.of(1))));
    } catch {
      return 'waiting';
    }
    const answer = await send(`${edgeUrl()}/v1/envelopes/batch`, 'POST', spend.request);
    const result = await settle(databasePath, spend.id, answer.status, answer.body);
    if (answer.status >= 200 && answer.status < 300) return 'paid';
    if (answer.status !== 409 || result !== 'spent') return 'waiting';
  }
  return 'waiting';
}

async function busySignup(databasePath: string, work: Uint8Array) {
  const asked = parseSignupWork(work);
  const { spendable } = await loadCredits(databasePath).catch(() => ({ spendable: 0 }));
  if (asked && spendable >= SIGNUP_CREDITS
    && await ask({ kind: 'signup', credits: asked.credits, spendable })) {
    const spend = parseSpend(await credits_signup_export(vectors(utf8(databasePath))));
    return { body: spend.request, settle: async (status: number) => { await settle(databasePath, spend.id, status); } };
  }
  return { body: await credits_register_at_export(vectors(utf8(databasePath), work.subarray(4, 5))) };
}

let lastHandover = 0;
let lastResume = 0;

// Before the outbox drains: purchases left paid or mid-exchange are asked
// about again (every five minutes at most), and a priced inbox hands its
// contact address to new group members (every minute at most, and at once
// after the price changes).
async function beforeDrain(databasePath: string): Promise<void> {
  if (Date.now() - lastResume > 300_000) {
    lastResume = Date.now();
    void resumePurchases(databasePath).catch(() => {});
  }
  if (Date.now() - lastHandover < 60_000) return;
  lastHandover = Date.now();
  await credits_group_handover_export(vectors(utf8(databasePath)));
}

// Installed once the device has an account: spends everywhere credits pay.
export function installCredits(databasePath: string): void {
  setCreditHooks({ postage, firstContact, busySignup, beforeDrain });
  setCreditSource(attachmentCreditSource(
    async () => (await loadCredits(databasePath)).spendable,
    async (count) => parseSpend(await credits_spend_export(
      vectors(utf8(databasePath), Uint8Array.of(count), crypto.getRandomValues(new Uint8Array(32))),
    )),
    (id, status) => settle(databasePath, id, status),
  ));
}
