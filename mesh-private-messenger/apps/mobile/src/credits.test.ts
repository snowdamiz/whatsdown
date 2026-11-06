import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const calls: { name: string; body: Uint8Array }[] = [];
const requests: { url: string; options: RequestInit }[] = [];
let stage = 0;
let asset = 0;
let status = 200;
let fail = false;
let retentionStatus = 0;
let badReceipt = false;
let balanceWire: Uint8Array | undefined;
let signupStatus = 0;
let recoveryStatus = 0;
let draftWire = Uint8Array.of(1);
let policyWire: Uint8Array | undefined;
let signupWire: Uint8Array | undefined;
let recoveryWire: Uint8Array | undefined;
let receiptStatus = 1;
const signedPolicy = new Uint8Array(88).fill(42);
const u64 = (value: bigint) => { const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, value); return bytes; };
const id = new Uint8Array(32).fill(7);
const committed = Uint8Array.of(9, 8, 7, 6);
function packet(parts: Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(4 + parts.reduce((sum, part) => sum + 4 + part.length, 0));
  const view = new DataView(bytes.buffer); view.setUint32(0, parts.length);
  let offset = 4;
  for (const part of parts) { view.setUint32(offset, part.length); bytes.set(part, offset + 4); offset += 4 + part.length; }
  return bytes;
}
const text = (value: string) => new TextEncoder().encode(value);
function plan() {
  return packet([Uint8Array.of(2, 77, 67, 80), id, Uint8Array.of(stage), Uint8Array.of(0, 100), new Uint8Array(8),
    text('https://edge.example'), text(stage === 0 ? '/v1/credits/quote' : stage === 2 ? '/v1/credits/issue' : ''),
    stage === 0 || stage === 2 ? committed : new Uint8Array(), stage > 0 ? Uint8Array.of(2) : new Uint8Array(), Uint8Array.of(asset)]);
}
const retentionPlan = () => packet([text('\u0001MCT'), id, Uint8Array.of(retentionStatus), new Uint8Array(8), text('https://edge.example'), text(retentionStatus === 0 ? '/v1/credits/retention' : ''), retentionStatus === 0 ? committed : new Uint8Array()]);
const signupPlan = () => signupWire ?? packet([text('\u0001MCS'), id, Uint8Array.of(signupStatus), u64(19n), text('https://edge.example'), text(signupStatus === 0 ? '/v1/credits/signup' : ''), signupStatus === 0 ? committed : new Uint8Array()]);
const recoveryPlan = () => recoveryWire ?? packet([text('\u0001MCE'), id, Uint8Array.of(recoveryStatus), Uint8Array.of(4), u64(19n), text('https://edge.example'), text(recoveryStatus === 0 ? '/v1/credits/reconcile' : ''), recoveryStatus === 0 ? committed : new Uint8Array()]);
Object.assign(globalThis, {
  __creditNative: async (name: string, body: Uint8Array) => {
    calls.push({ name, body });
    if (name === 'discover_online') return new Uint8Array();
    if (name === 'purchase_continue') {
      if (fail) throw new Error('unknown network outcome');
      if (stage === 0 || stage === 2) {
        if (status !== 200) throw new Error('credit_http_' + status);
        stage = stage === 0 ? 1 : 3;
      }
      return plan();
    }
    if (name === 'signup_policy_online') {
      if (fail) throw new Error('credit_transport_unavailable');
      return policyWire ?? packet([text('\u0002SPV'), Uint8Array.of(1), Uint8Array.of(1), Uint8Array.of(18), Uint8Array.of(22), Uint8Array.of(0, 20), u64(18446744073709551615n), signedPolicy]);
    }
    if (name === 'action_continue') {
      const mode = body.at(-1);
      const pending = (mode === 0 ? retentionStatus : mode === 1 ? signupStatus : recoveryStatus) === 0;
      if (pending) {
        if (fail) throw new Error('unknown network outcome');
        if (status !== 200 && !(status === 201 && mode !== 2)) throw new Error('credit_http_' + status);
        if (badReceipt) throw new Error('unverified_credit_receipt');
        if (mode === 0) retentionStatus = receiptStatus;
        else if (mode === 1) signupStatus = receiptStatus;
        else recoveryStatus = receiptStatus;
      }
      return mode === 0 ? retentionPlan() : mode === 1 ? signupPlan() : recoveryPlan();
    }
    if (name === 'signup_draft_state') return draftWire;
    if (name === 'create_signup_draft' || name === 'signup_draft_rename' || name === 'signup_draft_free') return Uint8Array.of(6, 7);
    if (name === 'signup_policy') return packet([text('\u0001MCY'), text('https://edge.example'), text('/v1/credits/signup-policy'), new Uint8Array()]);
    if (name === 'signup_policy_view') return policyWire ?? packet([text('\u0001SPV'), Uint8Array.of(1), Uint8Array.of(1), Uint8Array.of(18), Uint8Array.of(22), Uint8Array.of(0, 20), u64(18446744073709551615n)]);
    if (name === 'signup' || name === 'signup_recover') return signupPlan();
    if (name === 'action_recovery') return recoveryPlan();
    if (name === 'receipt') {
      if (badReceipt) throw new Error('unverified_credit_receipt');
      retentionStatus = 1; signupStatus = receiptStatus; recoveryStatus = receiptStatus;
    }
    if (name.startsWith('retention')) return retentionPlan();
    if (name === 'payment_url') return text('solana:verified-native-owner?amount=5.000000');
    if (name === 'purchases') return packet([Uint8Array.of(1, 77, 67, 76), id]);
    if (name === 'balance') return balanceWire ?? packet([Uint8Array.of(3, 77, 67, 66), ...[11, 22, 33, 44, 55].map(value => { const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, value); return bytes; }), Uint8Array.of(1), Uint8Array.of(255)]);
    if (name === 'payment_signature') stage = 2;
    if (name === 'quote') stage = 1;
    if (name === 'finalize') stage = 3;
    return plan();
  },
  __creditFetch: async (url: string, options: RequestInit) => {
    requests.push({ url, options });
    if (fail) throw new Error('unknown network outcome');
    return new Response(status === 200 ? (url.endsWith('/signup-policy') ? signedPolicy : Uint8Array.of(4, 5)) : null, { status });
  },
});
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,export const isLegacyDesktopBridge=false;' +
    ['discover_online', 'purchase_continue', 'action_continue', 'signup_policy_online', 'discovery', 'admit', 'prepare', 'prepare_again', 'quote', 'payment', 'finalize', 'recover', 'purchases', 'balance', 'reserve', 'reservation', 'retention', 'retention_recover', 'receipt', 'payment_url', 'payment_signature', 'signup', 'signup_recover', 'signup_policy', 'signup_policy_view', 'action_recovery']
      .map((name) => `export const credit_${name}_export = (body) => globalThis.__creditNative('${name}', body);`).join('') + ['create_signup_draft', 'signup_draft_state', 'signup_draft_rename', 'signup_draft_free', 'signup_draft_free_complete'].map(name => `export const ${name}_export = (body) => globalThis.__creditNative('${name}', body);`).join('') };
  if (specifier === './transport') return { shortCircuit: true, url: 'data:text/javascript,export const fetch = globalThis.__creditFetch;' };
  return next(specifier, context);
} });
const creditsModule = await import('./credits.ts');
const { scope } = scopeFixture();
const credits = { ...creditsModule, ...creditsModule.createCreditServices({ ...await import('../modules/mesh-messenger'), ...scope }) };

test('purchase network attempts pass only the saved journal identity to Mesh', async () => {
  requests.length = 0; calls.length = 0;
  fail = true;
  await assert.rejects(() => credits.continueCreditPurchase('/app/state.db', id), /unknown network outcome/);
  assert.equal(stage, 0);
  assert.equal(calls.at(-1)?.name, 'purchase_continue');
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db'), id]));
  fail = false;
  assert.equal((await credits.continueCreditPurchase('/app/state.db', id)).stage, 1);
  assert.equal((await credits.continueCreditPurchase('/app/state.db', id)).stage, 1);
  stage = 2; status = 425;
  await assert.rejects(() => credits.continueCreditPurchase('/app/state.db', id), /425/);
  assert.equal(stage, 2);
  status = 200;
  assert.equal((await credits.continueCreditPurchase('/app/state.db', id)).stage, 3);
  await credits.discoverCreditIssuer('/app/state.db');
  assert.equal(calls.at(-1)?.name, 'discover_online');
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db')]));
  assert.equal(requests.length, 0, 'JavaScript must perform no discovery or purchase HTTP');
  assert(!calls.some(call => ['prepare', 'quote', 'finalize', 'admit'].includes(call.name)));
});

test('paid action retries never send credit frames through JavaScript HTTP', async () => {
  requests.length = 0; calls.length = 0; retentionStatus = 0; status = 200; badReceipt = false;
  await credits.continueCreditRetention('/app/state.db', id);
  assert.equal(requests.length, 0);
  assert.deepEqual(calls[0], { name: 'action_continue', body: packet([text('/app/state.db'), id, Uint8Array.of(0)]) });
});


test('paid retention preserves the exact reservation until Mesh authenticates the receipt', async () => {
  retentionStatus = 0; status = 201; badReceipt = true; receiptStatus = 1;
  await assert.rejects(() => credits.continueCreditRetention('/app/state.db', id), /unverified_credit_receipt/);
  assert.equal(retentionStatus, 0);
  const before = calls.at(-1)!;
  assert.equal(before.name, 'action_continue');
  assert.deepEqual(before.body, packet([text('/app/state.db'), id, Uint8Array.of(0)]));
  badReceipt = false;
  const result = await credits.continueCreditRetention('/app/state.db', id);
  assert.equal(result.status, 1);
  assert.deepEqual(before.body, calls.at(-1)!.body);
  const sent = requests.length;
  await credits.continueCreditRetention('/app/state.db', id);
  assert.equal(requests.length, sent);
  assert(!calls.some((call) => call.name === 'retention'));
});

test('native signed cancellation is terminal without claiming paid completion', async () => {
  retentionStatus = 2;
  const sent = requests.length;
  const receipts = calls.filter(call => call.name === 'receipt').length;
  const result = await credits.continueCreditRetention('/app/state.db', id);
  assert.equal(result.status, 2);
  assert.equal(result.path, '');
  assert.equal(result.body.length, 0);
  assert.equal(requests.length, sent);
  assert.equal(calls.filter(call => call.name === 'receipt').length, receipts);
});


test('payment presentation and signature input delegate to the native verified purchase journal', async () => {
  assert.equal(await credits.creditPaymentUrl('/app/state.db', id), 'solana:verified-native-owner?amount=5.000000');
  assert.equal(calls.at(-1)?.name, 'payment_url');
  const signature = 'canonical-base58-validated-natively';
  assert.equal((await credits.recordCreditPaymentSignature('/app/state.db', id, signature)).stage, 2);
  assert.equal(calls.at(-1)?.name, 'payment_signature');
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db'), id, text(signature)]));
  assert.deepEqual(await credits.creditPurchaseIds('/app/state.db'), [id]);
  assert.deepEqual(await credits.readCreditBalance('/app/state.db'), { available: 11, delayed: 22, reserved: 33, expired: 44, pendingPurchases: 55, purpose: 'test', lightningNetwork: undefined });
});

test('credit balance requires explicit native purpose and an exact versioned frame', async () => {
  const counts = Array.from({ length: 5 }, () => new Uint8Array(4));
  for (const input of [
    packet([text('\u0001MCB'), ...counts]),
    packet([text('\u0003MCB'), ...counts]),
    packet([text('\u0003MCB'), ...counts, Uint8Array.of(2)]),
    packet([text('\u0003MCB'), ...counts, Uint8Array.of(1, 0)]),
    packet([text('\u0003MCB'), ...counts, Uint8Array.of(1), new Uint8Array()]),
  ]) {
    balanceWire = input;
    await assert.rejects(() => credits.readCreditBalance('/app/state.db'), /invalid_credit_response/);
  }
  balanceWire = packet([text('\u0003MCB'), ...counts, Uint8Array.of(0), Uint8Array.of(255)]);
  assert.equal((await credits.readCreditBalance('/app/state.db')).purpose, 'live');
  balanceWire = undefined;
});


test('signup shows only native verified policy and passes the exact signed statement back to Mesh', async () => {
  status = 200; fail = false; signupStatus = 0;
  const policy = await credits.loadCreditSignupPolicy('/app/state.db');
  assert.deepEqual(policy, { enabled: true, purpose: 'test', baseDifficulty: 18, currentDifficulty: 22, price: 20, expiresAt: 18446744073709551615n, statement: signedPolicy });
  assert.equal(calls.at(-1)?.name, 'signup_policy_online');
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db')]));
  const prepared = await credits.prepareCreditSignup('/app/state.db', policy.statement);
  assert.equal(prepared.status, 0);
  assert.equal(prepared.revision, 19n);
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db'), signedPolicy]));
  assert.equal(requests.length, 0);
});

test('paid signup and reconciliation replay saved CAP and keep signed cancellation terminal', async () => {
  signupStatus = 0; recoveryStatus = 0; fail = true;
  await assert.rejects(() => credits.continueCreditSignup('/app/state.db'), /unknown network outcome/);
  const original = calls.at(-1)!;
  assert.equal(original.name, 'action_continue');
  assert.deepEqual(original.body, packet([text('/app/state.db'), id, Uint8Array.of(1)]));
  fail = false; receiptStatus = 1;
  assert.equal((await credits.continueCreditSignup('/app/state.db')).status, 1);
  assert.deepEqual(calls.at(-1)?.body, original.body);
  const sent = requests.length;
  await credits.continueCreditSignup('/app/state.db');
  assert.equal(requests.length, sent);
  recoveryStatus = 0; receiptStatus = 2;
  const cancelled = await credits.continueCreditActionRecovery('/app/state.db', id);
  assert.equal(cancelled.status, 2);
  assert.equal(cancelled.kind, 4);
  assert.equal(cancelled.path, '');
  assert.deepEqual(calls.at(-1)?.body, packet([text('/app/state.db'), id, Uint8Array.of(2)]));
  assert.equal(requests.length, 0);
  const recovered = requests.length;
  await credits.continueCreditActionRecovery('/app/state.db', id);
  assert.equal(requests.length, recovered);
});

test('signup framing fails closed on ambiguous versions, terminal bodies and invalid native draft states', async () => {
  const policyFields = [text('\u0002SPV'), Uint8Array.of(1), Uint8Array.of(0), Uint8Array.of(18), Uint8Array.of(22), Uint8Array.of(0, 20), u64(100n), signedPolicy];
  for (const bad of [packet(policyFields.slice(0, 6)), packet([text('\u0001SPV'), ...policyFields.slice(1)]), packet([policyFields[0]!, Uint8Array.of(2), ...policyFields.slice(2)]), packet([...policyFields.slice(0, 5), Uint8Array.of(20), policyFields[6]!])]) {
    policyWire = bad;
    await assert.rejects(() => credits.loadCreditSignupPolicy('/app/state.db'), /invalid_credit_response/);
  }
  policyWire = undefined;
  signupWire = packet([text('\u0001MCS'), id, Uint8Array.of(2), u64(1n), text('https://edge.example'), text('/v1/credits/signup'), committed]);
  await assert.rejects(() => credits.recoverCreditSignup('/app/state.db'), /invalid_credit_response/);
  signupWire = undefined;
  recoveryWire = packet([text('\u0001MCE'), id, Uint8Array.of(0), Uint8Array.of(3), u64(1n), text('https://edge.example'), text('/v1/credits/reconcile'), committed]);
  await assert.rejects(() => credits.recoverCreditAction('/app/state.db', id), /invalid_credit_response/);
  recoveryWire = undefined;
  for (const bad of [new Uint8Array(), Uint8Array.of(4), Uint8Array.of(1, 0)]) {
    draftWire = bad;
    await assert.rejects(() => credits.readCreditSignupDraftState('/app/state.db'), /invalid_credit_response/);
  }
  draftWire = Uint8Array.of(1);
  assert.equal(await credits.readCreditSignupDraftState('/app/state.db'), 1);
  assert.deepEqual(calls.at(-1)?.body, text('/app/state.db'));
});


test('native cancellation is terminal, retains its purchase identity and is Lightning-only', async () => {
  calls.length = 0; requests.length = 0; fail = false; status = 200;
  stage = 4; asset = 2;
  const canceled = await credits.continueCreditPurchase('/app/state.db', id);
  assert.equal(canceled.stage, 4);
  assert.equal(canceled.asset, 2);
  assert.deepEqual(canceled.purchaseId, id);
  assert.equal(canceled.path, '');
  assert.equal(canceled.body.length, 0);
  assert.equal(requests.length, 0);
  asset = 0;
  await assert.rejects(() => credits.continueCreditPurchase('/app/state.db', id), /invalid_credit_response/);
  stage = 5; asset = 2;
  await assert.rejects(() => credits.continueCreditPurchase('/app/state.db', id), /invalid_credit_response/);
  stage = 3; asset = 0;
});
