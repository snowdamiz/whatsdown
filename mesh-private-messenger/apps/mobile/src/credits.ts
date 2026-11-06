import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import {
  credit_discover_online_export, credit_purchase_continue_export,
  credit_action_continue_export, credit_signup_policy_online_export,
  credit_prepare_export,
  credit_payment_export, credit_recover_export, credit_purchases_export,
  credit_balance_export, credit_reserve_export, credit_reservation_export,
  credit_retention_export,
  credit_payment_url_export, credit_payment_signature_export,
  credit_prepare_again_export,
  create_signup_draft_export, signup_draft_state_export, signup_draft_rename_export, signup_draft_free_export, signup_draft_free_complete_export,
  credit_signup_export, credit_signup_recover_export,
  credit_action_recovery_export,
} from '../modules/mesh-messenger';
import { accountRequest } from './codec.ts';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export // Framing only. Issuer admission, prices, token choice, signatures and durable
// transitions stay inside Mesh. No bearer-token database lives in JavaScript.
function creditPacket(parts: Uint8Array[]): Uint8Array {
  const size = 4 + parts.reduce((sum, value) => sum + 4 + value.length, 0);
  if (size > 1_100_000) throw new Error('invalid_credit_request');
  const output = new Uint8Array(size);
  const view = new DataView(output.buffer);
  view.setUint32(0, parts.length);
  let offset = 4;
  for (const part of parts) { view.setUint32(offset, part.length); output.set(part, offset + 4); offset += 4 + part.length; }
  return output;
}
function parts(input: Uint8Array, maximumCount: number): Uint8Array[] {
  if (input.length < 4 || input.length > 1_100_000) throw new Error('invalid_credit_response');
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const count = view.getUint32(0);
  if (count > maximumCount) throw new Error('invalid_credit_response');
  let offset = 4;
  const output: Uint8Array[] = [];
  for (let index = 0; index < count; index++) {
    if (offset + 4 > input.length) throw new Error('invalid_credit_response');
    const size = view.getUint32(offset); offset += 4;
    if (size > input.length - offset) throw new Error('invalid_credit_response');
    output.push(input.slice(offset, offset + size)); offset += size;
  }
  if (offset !== input.length) throw new Error('invalid_credit_response');
  return output;
}
export type CreditPurchasePlan = {
  purchaseId: Uint8Array;
  stage: number;
  credits: number;
  asset: 0 | 1 | 2;
  revision: bigint;
  origin: string;
  path: string;
  body: Uint8Array;
  quote: Uint8Array;
};
function purchase(input: Uint8Array): CreditPurchasePlan {
  const value = parts(input, 10);
  if (value.length !== 10 || decoder.decode(value[0]) !== '\u0002MCP' || value[1]!.length !== 32 ||
      value[2]!.length !== 1 || value[2]![0]! > 4 || value[3]!.length !== 2 || value[4]!.length !== 8 ||
      value[9]!.length !== 1 || value[9]![0]! > 2 ||
      (value[2]![0] === 4 && (value[9]![0] !== 2 || value[6]!.length !== 0 || value[7]!.length !== 0))) {
    throw new Error('invalid_credit_response');
  }
  return { purchaseId: value[1]!, stage: value[2]![0]!, credits: new DataView(value[3]!.buffer).getUint16(0),
    revision: new DataView(value[4]!.buffer).getBigUint64(0), origin: decoder.decode(value[5]),
    path: decoder.decode(value[6]), body: value[7]!, quote: value[8]!, asset: value[9]![0]! as 0 | 1 | 2 };
}
function packet(database: string, ...fields: Uint8Array[]) { return creditPacket([encoder.encode(database), ...fields]); }
export type CreditRetentionPlan = {
  operationId: Uint8Array;
  status: number;
  revision: bigint;
  origin: string;
  path: string;
  body: Uint8Array;
};
function retention(input: Uint8Array): CreditRetentionPlan {
  const value = parts(input, 7);
  if (value.length !== 7 || decoder.decode(value[0]) !== '\u0001MCT' || value[1]!.length !== 32 ||
      value[2]!.length !== 1 || value[2]![0]! > 2 || value[3]!.length !== 8) throw new Error('invalid_credit_response');
  return { operationId: value[1]!, status: value[2]![0]!, revision: new DataView(value[3]!.buffer).getBigUint64(0),
    origin: decoder.decode(value[4]), path: decoder.decode(value[5]), body: value[6]! };
}
export type CreditBalance = { available: number; delayed: number; reserved: number; expired: number; pendingPurchases: number; purpose: 'live' | 'test'; lightningNetwork: number | undefined };
export type CreditSignupDraftState = 0 | 1 | 2 | 3;
export type CreditSignupPolicy = {
  enabled: boolean;
  purpose: 'live' | 'test';
  baseDifficulty: number;
  currentDifficulty: number;
  price: number;
  expiresAt: bigint;
  statement: Uint8Array;
};
export // Only the native plan callback may identify an intentionally disabled build.
// An edge/network error with the same text must never authorize base fallback.
class CreditConfigurationDisabled extends Error {
  constructor() { super('credits_disabled'); this.name = 'CreditConfigurationDisabled'; }
}
export type CreditSignupPlan = CreditRetentionPlan;
function signup(input: Uint8Array): CreditSignupPlan {
  const value = parts(input, 7);
  if (value.length !== 7 || decoder.decode(value[0]) !== '\u0001MCS' || value[1]!.length !== 32 ||
      value[2]!.length !== 1 || value[2]![0]! > 2 || value[3]!.length !== 8) throw new Error('invalid_credit_response');
  const status = value[2]![0]!;
  const path = decoder.decode(value[5]);
  if (status === 0 ? path !== '/v1/credits/signup' || value[6]!.length === 0 : path !== '' || value[6]!.length !== 0) throw new Error('invalid_credit_response');
  return { operationId: value[1]!, status, revision: new DataView(value[3]!.buffer).getBigUint64(0), origin: decoder.decode(value[4]), path, body: value[6]! };
}
export type CreditActionRecovery = CreditRetentionPlan & { kind: 1 | 2 | 4 };
function actionRecovery(input: Uint8Array, operationId: Uint8Array): CreditActionRecovery {
  const value = parts(input, 8);
  if (value.length !== 8 || decoder.decode(value[0]) !== '\u0001MCE' || value[1]!.length !== 32 ||
      value[1]!.some((byte, index) => byte !== operationId[index]) || value[2]!.length !== 1 || value[2]![0]! > 2 ||
      value[3]!.length !== 1 || ![1, 2, 4].includes(value[3]![0]!) || value[4]!.length !== 8) throw new Error('invalid_credit_response');
  const status = value[2]![0]!;
  const path = decoder.decode(value[6]);
  if (status === 0 ? path !== '/v1/credits/reconcile' || value[7]!.length === 0 : path !== '' || value[7]!.length !== 0) throw new Error('invalid_credit_response');
  return { operationId: value[1]!, status, kind: value[3]![0] as 1 | 2 | 4, revision: new DataView(value[4]!.buffer).getBigUint64(0),
    origin: decoder.decode(value[5]), path, body: value[7]! };
}
export function createCreditServices(deps: Pick<ScopedClient, 'runPrivate' | 'create_signup_draft_export' | 'credit_action_continue_export' | 'credit_action_recovery_export' | 'credit_balance_export' | 'credit_discover_online_export' | 'credit_payment_export' | 'credit_payment_signature_export' | 'credit_payment_url_export' | 'credit_prepare_again_export' | 'credit_prepare_export' | 'credit_purchase_continue_export' | 'credit_purchases_export' | 'credit_recover_export' | 'credit_reservation_export' | 'credit_reserve_export' | 'credit_retention_export' | 'credit_signup_export' | 'credit_signup_policy_online_export' | 'credit_signup_recover_export' | 'onDispose' | 'signup_draft_free_complete_export' | 'signup_draft_free_export' | 'signup_draft_rename_export' | 'signup_draft_state_export'>) {
const { credit_discover_online_export, credit_purchase_continue_export, credit_action_continue_export, credit_signup_policy_online_export, credit_prepare_export, credit_payment_export, credit_recover_export, credit_purchases_export, credit_balance_export, credit_reserve_export, credit_reservation_export, credit_retention_export, credit_payment_url_export, credit_payment_signature_export, credit_prepare_again_export, create_signup_draft_export, signup_draft_state_export, signup_draft_rename_export, signup_draft_free_export, signup_draft_free_complete_export, credit_signup_export, credit_signup_recover_export, credit_action_recovery_export } = deps;
async function discoverCreditIssuer(database: string): Promise<void> {
  await credit_discover_online_export(packet(database));
}
async function prepareCreditPurchase(database: string, credits: number, asset: number): Promise<CreditPurchasePlan> {
  if (!Number.isInteger(credits) || credits < 0 || credits > 0xffffffff || !Number.isInteger(asset) || asset < 0 || asset > 255) throw new Error('invalid_credit_request');
  const count = new Uint8Array(4); new DataView(count.buffer).setUint32(0, credits);
  return purchase(await credit_prepare_export(packet(database, count, Uint8Array.of(asset))));
}
async function prepareCreditPurchaseAgain(database: string, credits: number, asset: number): Promise<CreditPurchasePlan> {
  if (![100, 500, 2000].includes(credits) || ![0, 1, 2].includes(asset)) throw new Error('invalid_credit_request');
  const count = new Uint8Array(4); new DataView(count.buffer).setUint32(0, credits);
  return purchase(await credit_prepare_again_export(packet(database, count, Uint8Array.of(asset))));
}
async function recoverCreditPurchase(database: string, purchaseId: Uint8Array): Promise<CreditPurchasePlan> {
  return purchase(await credit_recover_export(packet(database, purchaseId)));
}
async function recordCreditPayment(database: string, purchaseId: Uint8Array, signature: Uint8Array): Promise<CreditPurchasePlan> {
  return purchase(await credit_payment_export(packet(database, purchaseId, signature)));
}
// Every network attempt starts by recovering the exact native journal entry.
// A timeout, 425, or other refusal leaves it pending; no replacement is minted.
async function continueCreditPurchase(database: string, purchaseId: Uint8Array): Promise<CreditPurchasePlan> {
  return purchase(await credit_purchase_continue_export(packet(database, purchaseId)));
}
const creditPurchases = (database: string): Promise<Uint8Array> => credit_purchases_export(packet(database));
const creditBalance = (database: string): Promise<Uint8Array> => credit_balance_export(packet(database));
const reserveCreditSpend = (database: string, action: Uint8Array, body: Uint8Array): Promise<Uint8Array> =>
  credit_reserve_export(packet(database, action, body));
const recoverCreditReservation = (database: string, operationId: Uint8Array): Promise<Uint8Array> =>
  credit_reservation_export(packet(database, operationId));
// The UI does not enable this operation. Paid route activation joins the
// server mode with the native retirement and receipt gates.
async function prepareCreditRetention(database: string, days: number): Promise<CreditRetentionPlan> {
  if (!Number.isInteger(days) || days < 0 || days > 0xffffffff) throw new Error('invalid_credit_request');
  const value = new Uint8Array(4); new DataView(value.buffer).setUint32(0, days);
  return retention(await credit_retention_export(packet(database, value)));
}
async function continueCreditRetention(database: string, operationId: Uint8Array): Promise<CreditRetentionPlan> {
  return retention(await credit_action_continue_export(packet(database, operationId, Uint8Array.of(0))));
}
async function creditPaymentUrl(database: string, purchaseId: Uint8Array): Promise<string> {
  return decoder.decode(await credit_payment_url_export(packet(database, purchaseId)));
}
async function recordCreditPaymentSignature(database: string, purchaseId: Uint8Array, signature: string): Promise<CreditPurchasePlan> {
  return purchase(await credit_payment_signature_export(packet(database, purchaseId, encoder.encode(signature))));
}
async function creditPurchaseIds(database: string): Promise<Uint8Array[]> {
  const value = parts(await creditPurchases(database), 2049);
  if (!value.length || decoder.decode(value[0]) !== '\u0001MCL' || value.slice(1).some(id => id.length !== 32)) throw new Error('invalid_credit_response');
  return value.slice(1);
}
async function readCreditBalance(database: string): Promise<CreditBalance> {
  const value = parts(await creditBalance(database), 8);
  if (value.length !== 8 || decoder.decode(value[0]) !== '\u0003MCB' || value.slice(1, 6).some(count => count.length !== 4) ||
      value[6]!.length !== 1 || value[6]![0]! > 1 || value[7]!.length !== 1 ||
      ![0, 1, 2, 3, 4, 255].includes(value[7]![0]!)) throw new Error('invalid_credit_response');
  const network = value[7]![0]!;
  if (network !== 255 && ((value[6]![0] === 0 && network !== 0) || (value[6]![0] === 1 && network === 0))) throw new Error('invalid_credit_response');
  const counts = value.slice(1, 6).map(count => new DataView(count.buffer, count.byteOffset, count.byteLength).getUint32(0));
  return { available: counts[0]!, delayed: counts[1]!, reserved: counts[2]!, expired: counts[3]!, pendingPurchases: counts[4]!, purpose: value[6]![0] === 0 ? 'live' : 'test', lightningNetwork: network === 255 ? undefined : network };
}
async function readCreditSignupDraftState(database: string): Promise<CreditSignupDraftState> {
  const value = await signup_draft_state_export(encoder.encode(database));
  if (value.length !== 1 || value[0]! > 3) throw new Error('invalid_credit_response');
  return value[0] as CreditSignupDraftState;
}
const createCreditSignupDraft = (database: string, username: string): Promise<Uint8Array> =>
  create_signup_draft_export(accountRequest(database, username));
const renameCreditSignupDraft = (database: string, username: string): Promise<Uint8Array> =>
  signup_draft_rename_export(packet(database, encoder.encode(username)));
const completeFreeCreditSignup = (database: string): Promise<Uint8Array> => signup_draft_free_complete_export(packet(database));
const selectFreeCreditSignup = (database: string): Promise<Uint8Array> => signup_draft_free_export(packet(database));
async function loadCreditSignupPolicy(database: string): Promise<CreditSignupPolicy> {
  let wire: Uint8Array;
  try { wire = await credit_signup_policy_online_export(packet(database)); }
  catch (caught) {
    const message = caught instanceof Error ? caught.message : String(caught);
    if (/(?:^|: )credits_disabled$/.test(message)) throw new CreditConfigurationDisabled();
    throw caught;
  }
  const value = parts(wire, 8);
  if (value.length !== 8 || decoder.decode(value[0]) !== '\u0002SPV' || value.slice(1, 5).some(field => field.length !== 1) ||
      value[1]![0]! > 1 || value[2]![0]! > 1 || value[5]!.length !== 2 || value[6]!.length !== 8 || value[7]!.length !== 88) throw new Error('invalid_credit_response');
  return { enabled: value[1]![0] === 1, purpose: value[2]![0] === 0 ? 'live' : 'test', baseDifficulty: value[3]![0]!,
    currentDifficulty: value[4]![0]!, price: new DataView(value[5]!.buffer).getUint16(0),
    expiresAt: new DataView(value[6]!.buffer).getBigUint64(0), statement: value[7]! };
}
async function prepareCreditSignup(database: string, signedPolicy: Uint8Array): Promise<CreditSignupPlan> {
  if (signedPolicy.length !== 88) throw new Error('invalid_credit_request');
  return signup(await credit_signup_export(packet(database, signedPolicy)));
}
async function recoverCreditSignup(database: string): Promise<CreditSignupPlan> {
  return signup(await credit_signup_recover_export(packet(database)));
}
async function continueCreditSignup(database: string): Promise<CreditSignupPlan> {
  const plan = await recoverCreditSignup(database);
  if (plan.status !== 0) return plan;
  return signup(await credit_action_continue_export(packet(database, plan.operationId, Uint8Array.of(1))));
}
async function recoverCreditAction(database: string, operationId: Uint8Array): Promise<CreditActionRecovery> {
  if (operationId.length !== 32) throw new Error('invalid_credit_request');
  return actionRecovery(await credit_action_recovery_export(packet(database, operationId)), operationId);
}
async function continueCreditActionRecovery(database: string, operationId: Uint8Array): Promise<CreditActionRecovery> {
  if (operationId.length !== 32) throw new Error('invalid_credit_request');
  return actionRecovery(await credit_action_continue_export(packet(database, operationId, Uint8Array.of(2))), operationId);
}
return Object.freeze({
  discoverCreditIssuer: (...args: Parameters<typeof discoverCreditIssuer>) => deps.runPrivate(() => discoverCreditIssuer(...args)),
  prepareCreditPurchase: (...args: Parameters<typeof prepareCreditPurchase>) => deps.runPrivate(() => prepareCreditPurchase(...args)),
  prepareCreditPurchaseAgain: (...args: Parameters<typeof prepareCreditPurchaseAgain>) => deps.runPrivate(() => prepareCreditPurchaseAgain(...args)),
  recoverCreditPurchase: (...args: Parameters<typeof recoverCreditPurchase>) => deps.runPrivate(() => recoverCreditPurchase(...args)),
  recordCreditPayment: (...args: Parameters<typeof recordCreditPayment>) => deps.runPrivate(() => recordCreditPayment(...args)),
  continueCreditPurchase: (...args: Parameters<typeof continueCreditPurchase>) => deps.runPrivate(() => continueCreditPurchase(...args)),
  creditPurchases: (...args: Parameters<typeof creditPurchases>) => deps.runPrivate(() => creditPurchases(...args)),
  creditBalance: (...args: Parameters<typeof creditBalance>) => deps.runPrivate(() => creditBalance(...args)),
  reserveCreditSpend: (...args: Parameters<typeof reserveCreditSpend>) => deps.runPrivate(() => reserveCreditSpend(...args)),
  recoverCreditReservation: (...args: Parameters<typeof recoverCreditReservation>) => deps.runPrivate(() => recoverCreditReservation(...args)),
  prepareCreditRetention: (...args: Parameters<typeof prepareCreditRetention>) => deps.runPrivate(() => prepareCreditRetention(...args)),
  continueCreditRetention: (...args: Parameters<typeof continueCreditRetention>) => deps.runPrivate(() => continueCreditRetention(...args)),
  creditPaymentUrl: (...args: Parameters<typeof creditPaymentUrl>) => deps.runPrivate(() => creditPaymentUrl(...args)),
  recordCreditPaymentSignature: (...args: Parameters<typeof recordCreditPaymentSignature>) => deps.runPrivate(() => recordCreditPaymentSignature(...args)),
  creditPurchaseIds: (...args: Parameters<typeof creditPurchaseIds>) => deps.runPrivate(() => creditPurchaseIds(...args)),
  readCreditBalance: (...args: Parameters<typeof readCreditBalance>) => deps.runPrivate(() => readCreditBalance(...args)),
  readCreditSignupDraftState: (...args: Parameters<typeof readCreditSignupDraftState>) => deps.runPrivate(() => readCreditSignupDraftState(...args)),
  createCreditSignupDraft: (...args: Parameters<typeof createCreditSignupDraft>) => deps.runPrivate(() => createCreditSignupDraft(...args)),
  renameCreditSignupDraft: (...args: Parameters<typeof renameCreditSignupDraft>) => deps.runPrivate(() => renameCreditSignupDraft(...args)),
  completeFreeCreditSignup: (...args: Parameters<typeof completeFreeCreditSignup>) => deps.runPrivate(() => completeFreeCreditSignup(...args)),
  selectFreeCreditSignup: (...args: Parameters<typeof selectFreeCreditSignup>) => deps.runPrivate(() => selectFreeCreditSignup(...args)),
  loadCreditSignupPolicy: (...args: Parameters<typeof loadCreditSignupPolicy>) => deps.runPrivate(() => loadCreditSignupPolicy(...args)),
  prepareCreditSignup: (...args: Parameters<typeof prepareCreditSignup>) => deps.runPrivate(() => prepareCreditSignup(...args)),
  recoverCreditSignup: (...args: Parameters<typeof recoverCreditSignup>) => deps.runPrivate(() => recoverCreditSignup(...args)),
  continueCreditSignup: (...args: Parameters<typeof continueCreditSignup>) => deps.runPrivate(() => continueCreditSignup(...args)),
  recoverCreditAction: (...args: Parameters<typeof recoverCreditAction>) => deps.runPrivate(() => recoverCreditAction(...args)),
  continueCreditActionRecovery: (...args: Parameters<typeof continueCreditActionRecovery>) => deps.runPrivate(() => continueCreditActionRecovery(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createCreditServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createCreditServices({ runPrivate: operation => operation(), onDispose: () => () => {}, credit_discover_online_export, credit_purchase_continue_export, credit_action_continue_export, credit_signup_policy_online_export, credit_prepare_export, credit_payment_export, credit_recover_export, credit_purchases_export, credit_balance_export, credit_reserve_export, credit_reservation_export, credit_retention_export, credit_payment_url_export, credit_payment_signature_export, credit_prepare_again_export, create_signup_draft_export, signup_draft_state_export, signup_draft_rename_export, signup_draft_free_export, signup_draft_free_complete_export, credit_signup_export, credit_signup_recover_export, credit_action_recovery_export });
}
export const discoverCreditIssuer: ReturnType<typeof createCreditServices>['discoverCreditIssuer'] = (...args) => desktopCompatibility().discoverCreditIssuer(...args);
export const prepareCreditPurchase: ReturnType<typeof createCreditServices>['prepareCreditPurchase'] = (...args) => desktopCompatibility().prepareCreditPurchase(...args);
export const prepareCreditPurchaseAgain: ReturnType<typeof createCreditServices>['prepareCreditPurchaseAgain'] = (...args) => desktopCompatibility().prepareCreditPurchaseAgain(...args);
export const recoverCreditPurchase: ReturnType<typeof createCreditServices>['recoverCreditPurchase'] = (...args) => desktopCompatibility().recoverCreditPurchase(...args);
export const recordCreditPayment: ReturnType<typeof createCreditServices>['recordCreditPayment'] = (...args) => desktopCompatibility().recordCreditPayment(...args);
export const continueCreditPurchase: ReturnType<typeof createCreditServices>['continueCreditPurchase'] = (...args) => desktopCompatibility().continueCreditPurchase(...args);
export const creditPurchases: ReturnType<typeof createCreditServices>['creditPurchases'] = (...args) => desktopCompatibility().creditPurchases(...args);
export const creditBalance: ReturnType<typeof createCreditServices>['creditBalance'] = (...args) => desktopCompatibility().creditBalance(...args);
export const reserveCreditSpend: ReturnType<typeof createCreditServices>['reserveCreditSpend'] = (...args) => desktopCompatibility().reserveCreditSpend(...args);
export const recoverCreditReservation: ReturnType<typeof createCreditServices>['recoverCreditReservation'] = (...args) => desktopCompatibility().recoverCreditReservation(...args);
export const prepareCreditRetention: ReturnType<typeof createCreditServices>['prepareCreditRetention'] = (...args) => desktopCompatibility().prepareCreditRetention(...args);
export const continueCreditRetention: ReturnType<typeof createCreditServices>['continueCreditRetention'] = (...args) => desktopCompatibility().continueCreditRetention(...args);
export const creditPaymentUrl: ReturnType<typeof createCreditServices>['creditPaymentUrl'] = (...args) => desktopCompatibility().creditPaymentUrl(...args);
export const recordCreditPaymentSignature: ReturnType<typeof createCreditServices>['recordCreditPaymentSignature'] = (...args) => desktopCompatibility().recordCreditPaymentSignature(...args);
export const creditPurchaseIds: ReturnType<typeof createCreditServices>['creditPurchaseIds'] = (...args) => desktopCompatibility().creditPurchaseIds(...args);
export const readCreditBalance: ReturnType<typeof createCreditServices>['readCreditBalance'] = (...args) => desktopCompatibility().readCreditBalance(...args);
export const readCreditSignupDraftState: ReturnType<typeof createCreditServices>['readCreditSignupDraftState'] = (...args) => desktopCompatibility().readCreditSignupDraftState(...args);
export const createCreditSignupDraft: ReturnType<typeof createCreditServices>['createCreditSignupDraft'] = (...args) => desktopCompatibility().createCreditSignupDraft(...args);
export const renameCreditSignupDraft: ReturnType<typeof createCreditServices>['renameCreditSignupDraft'] = (...args) => desktopCompatibility().renameCreditSignupDraft(...args);
export const completeFreeCreditSignup: ReturnType<typeof createCreditServices>['completeFreeCreditSignup'] = (...args) => desktopCompatibility().completeFreeCreditSignup(...args);
export const selectFreeCreditSignup: ReturnType<typeof createCreditServices>['selectFreeCreditSignup'] = (...args) => desktopCompatibility().selectFreeCreditSignup(...args);
export const loadCreditSignupPolicy: ReturnType<typeof createCreditServices>['loadCreditSignupPolicy'] = (...args) => desktopCompatibility().loadCreditSignupPolicy(...args);
export const prepareCreditSignup: ReturnType<typeof createCreditServices>['prepareCreditSignup'] = (...args) => desktopCompatibility().prepareCreditSignup(...args);
export const recoverCreditSignup: ReturnType<typeof createCreditServices>['recoverCreditSignup'] = (...args) => desktopCompatibility().recoverCreditSignup(...args);
export const continueCreditSignup: ReturnType<typeof createCreditServices>['continueCreditSignup'] = (...args) => desktopCompatibility().continueCreditSignup(...args);
export const recoverCreditAction: ReturnType<typeof createCreditServices>['recoverCreditAction'] = (...args) => desktopCompatibility().recoverCreditAction(...args);
export const continueCreditActionRecovery: ReturnType<typeof createCreditServices>['continueCreditActionRecovery'] = (...args) => desktopCompatibility().continueCreditActionRecovery(...args);
