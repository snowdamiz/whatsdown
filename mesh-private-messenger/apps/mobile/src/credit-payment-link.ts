import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { openNativeCreditPayment } from '../modules/mesh-messenger';
import { creditPacket } from './credits';
export function createCreditPaymentServices(deps: Pick<ScopedClient, 'runPrivate' | 'openNativeCreditPayment'>) {
const { openNativeCreditPayment } = deps;
async function openCreditPayment(database: string, purchaseId: Uint8Array): Promise<void> {
  await openNativeCreditPayment(creditPacket([new TextEncoder().encode(database), purchaseId]));
}
return Object.freeze({ openCreditPayment: (...args: Parameters<typeof openCreditPayment>) => deps.runPrivate(() => openCreditPayment(...args)) });
}
let legacyScopeServices: ReturnType<typeof createCreditPaymentServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createCreditPaymentServices({ runPrivate: operation => operation(), openNativeCreditPayment });
}
export const openCreditPayment: ReturnType<typeof createCreditPaymentServices>['openCreditPayment'] = (...args) => desktopCompatibility().openCreditPayment(...args);
