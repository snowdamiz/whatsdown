import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { invokeWallet } from '../modules/mesh-messenger';
import { creditPacket } from './credits';
export function createWalletServices(deps: Pick<ScopedClient, 'runPrivate' | 'invokeWallet' | 'onDispose'>) {
const { invokeWallet } = deps;
// Native confirmation and OS custody are mandatory. The signing wrapper takes
// a journal ID; it cannot accept a caller-supplied quote or arbitrary message.
const walletCreate = (): Promise<Uint8Array> => invokeWallet(1, new Uint8Array());
const walletAddress = (): Promise<Uint8Array> => invokeWallet(2, new Uint8Array());
function walletPayCreditPurchase(database: string, purchaseId: Uint8Array): Promise<Uint8Array> {
  return invokeWallet(5, creditPacket([new TextEncoder().encode(database), purchaseId]));
}
function walletRecoverCreditPurchase(database: string, purchaseId: Uint8Array): Promise<Uint8Array> {
  return invokeWallet(6, creditPacket([new TextEncoder().encode(database), purchaseId]));
}
// Public-address display encoding only. Private material, payment parsing and
// signature decisions never enter this module.
async function walletAddressText(): Promise<string> {
  const bytes = await walletAddress();
  if (bytes.length !== 32) throw new Error('invalid_wallet_address');
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let output = '';
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  while (value > 0n) { output = alphabet[Number(value % 58n)] + output; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; output = '1' + output; }
  return output;
}
return Object.freeze({
  walletCreate: (...args: Parameters<typeof walletCreate>) => deps.runPrivate(() => walletCreate(...args)),
  walletAddress: (...args: Parameters<typeof walletAddress>) => deps.runPrivate(() => walletAddress(...args)),
  walletPayCreditPurchase: (...args: Parameters<typeof walletPayCreditPurchase>) => deps.runPrivate(() => walletPayCreditPurchase(...args)),
  walletRecoverCreditPurchase: (...args: Parameters<typeof walletRecoverCreditPurchase>) => deps.runPrivate(() => walletRecoverCreditPurchase(...args)),
  walletAddressText: (...args: Parameters<typeof walletAddressText>) => deps.runPrivate(() => walletAddressText(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createWalletServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createWalletServices({ runPrivate: operation => operation(), onDispose: () => () => {}, invokeWallet });
}
export const walletCreate: ReturnType<typeof createWalletServices>['walletCreate'] = (...args) => desktopCompatibility().walletCreate(...args);
export const walletAddress: ReturnType<typeof createWalletServices>['walletAddress'] = (...args) => desktopCompatibility().walletAddress(...args);
export const walletPayCreditPurchase: ReturnType<typeof createWalletServices>['walletPayCreditPurchase'] = (...args) => desktopCompatibility().walletPayCreditPurchase(...args);
export const walletRecoverCreditPurchase: ReturnType<typeof createWalletServices>['walletRecoverCreditPurchase'] = (...args) => desktopCompatibility().walletRecoverCreditPurchase(...args);
export const walletAddressText: ReturnType<typeof createWalletServices>['walletAddressText'] = (...args) => desktopCompatibility().walletAddressText(...args);
