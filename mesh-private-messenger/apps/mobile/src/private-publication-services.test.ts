import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
import { utf8, vectors, writeU32 } from './codec.ts';

const nativeNames = [
  'openNativeCreditPayment', 'credit_discover_online_export', 'credit_purchase_continue_export',
  'credit_action_continue_export', 'credit_signup_policy_online_export', 'credit_prepare_export',
  'credit_payment_export', 'credit_recover_export', 'credit_purchases_export', 'credit_balance_export',
  'credit_reserve_export', 'credit_reservation_export', 'credit_retention_export',
  'credit_payment_url_export', 'credit_payment_signature_export', 'credit_prepare_again_export',
  'create_signup_draft_export', 'signup_draft_state_export', 'signup_draft_rename_export',
  'signup_draft_free_export', 'signup_draft_free_complete_export', 'credit_signup_export',
  'credit_signup_recover_export', 'credit_action_recovery_export',
];
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '../modules/mesh-messenger') return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(
    'export const isLegacyDesktopBridge=false;' + nativeNames.map(name => `export const ${name}=()=>{throw Error("global_bridge_called")};`).join('')) };
  if (specifier === 'expo-notifications') return { shortCircuit: true, url: 'data:text/javascript,export const unsupported=true;' };
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createCreditPaymentServices } = await import('./credit-payment-link.ts');
const { createNotificationServices } = await import('./notification-delivery.ts');
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
function fixture() {
  let resolve: () => void = () => { throw Error('resolver_not_initialized'); };
  const gate = new Promise<void>(done => { resolve = done; }); let checks = 0;
  const scope = createDesktopPrivateSession({
    async check() { if (++checks === 1) await gate; },
    invoke: unused, invokeWallet: unused, copyProtectedText: unused,
  });
  return { scope, resolve };
}

test('payment sheet dispatch awaits enclosing native authority and preserves its exact request', async () => {
  const f = fixture(); const requests: Uint8Array[] = [];
  const service = createCreditPaymentServices({ ...f.scope,
    async openNativeCreditPayment(request: Uint8Array) { requests.push(request); },
  });
  const purchase = new Uint8Array(32).fill(3);
  const opening = service.openCreditPayment('/captured/db', purchase);
  await tick(); const early = requests.length; f.resolve(); await opening; await tick(); f.scope.dispose();
  assert.equal(early, 0);
  assert.deepEqual(requests, [Uint8Array.from([...writeU32(2), ...vectors(utf8('/captured/db'), purchase)])]);
});

test('private notification publication awaits enclosing native authority', async () => {
  const f = fixture(); const notices: unknown[] = [];
  const service = createNotificationServices({ ...f.scope,
    async publishMessageNotice(notice: unknown) { notices.push(notice); },
  });
  const notice = { id: 'chat/message', scope: 'chat', title: 'Private name', body: 'Private message', mention: false };
  const showing = service.showMessageNotification(notice);
  await tick(); const early = notices.length; f.resolve(); await showing; await tick(); f.scope.dispose();
  assert.equal(early, 0); assert.deepEqual(notices, [{ version: 1, ...notice }]);
});
