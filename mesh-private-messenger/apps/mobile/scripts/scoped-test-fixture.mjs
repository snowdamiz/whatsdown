import { registerHooks } from 'node:module';
import { existsSync } from 'node:fs';
import { createAppLockSession } from '../src/app-lock.ts';

// Metro resolves these actual TypeScript sources; plain Node requires their
// extensions. Never replace the scope implementation or load a mobile barrel.
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL);
    if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });

export function scopeFixture(overrides = {}) {
  const epoch = 'd355922a-069b-4c7b-ab9f-cecfefb8db4c';
  let active = true;
  const unexpected = () => { throw Error('unexpected native test call'); };
  const native = {
    getAppLockState: unexpected, authenticateAppLock: unexpected,
    cancelAppLockAuthentication: unexpected, lockApp: unexpected, setAppLockEnabled: unexpected,
    activateAppLockScope: unexpected,
    checkAppLockScope(expected) { if (!active || expected !== epoch) throw Error('stale_epoch'); },
    consumeAppLockInboxIntent: unexpected, consumeAppLockNotificationIntent: unexpected,
    invokeScoped: unexpected, walletScoped: unexpected,
    primePushTokenScoped: unexpected, clearPushTokenScoped: unexpected, openCreditPaymentScoped: unexpected,
    protectedFile: unexpected, publishMessageNotice: unexpected, publishEncryptedWakeup: unexpected,
    copyProtectedText: unexpected, readLegacyPreference: unexpected, removeLegacyPreference: unexpected,
    forgetLegacyPreferences: unexpected, addListener: unexpected,
    ...overrides,
  };
  const scope = createAppLockSession(native, epoch);
  return { scope, revoke() { active = false; }, native };
}
