// Expected epochs only narrow authority. Native OS state remains authoritative.
export type AppLockEpoch = string;
export type AppLockState = Readonly<{
  version: 1;
  policy: 'disabled' | 'enable_pending' | 'enabled' | 'disable_pending' | 'unknown';
  phase: 'booting' | 'locked' | 'authenticating' | 'unlocked' | 'disabled' | 'error';
  capability: 'available' | 'unavailable' | 'unknown';
  epoch: AppLockEpoch;
  requestId?: string;
  error?: string;
}>;
type Subscription = { remove(): void };
export type AppLockNativePort = {
  getAppLockState(): Promise<unknown>;
  authenticateAppLock(expectedEpoch: AppLockEpoch): Promise<unknown>;
  cancelAppLockAuthentication(requestId: string): Promise<void>;
  lockApp(): Promise<void>;
  setAppLockEnabled(enabled: boolean, expectedEpoch: AppLockEpoch): Promise<unknown>;
  activateAppLockScope(expectedEpoch: AppLockEpoch): Promise<void>;
  checkAppLockScope(expectedEpoch: AppLockEpoch): void;
  consumeAppLockInboxIntent(expectedEpoch: AppLockEpoch): boolean;
  // Required by both mobile broker paths. Missing native capability refuses
  // rather than reading a retained response from the JavaScript runtime.
  consumeAppLockNotificationIntent?(expectedEpoch: AppLockEpoch): string;
  invokeScoped(symbol: string, request: Uint8Array, expectedEpoch: AppLockEpoch): Promise<Uint8Array>;
  walletScoped(operation: number, request: Uint8Array, expectedEpoch: AppLockEpoch): Promise<Uint8Array>;
  primePushTokenScoped(request: Uint8Array, expectedEpoch: AppLockEpoch): Promise<void>;
  clearPushTokenScoped(request: Uint8Array, expectedEpoch: AppLockEpoch): Promise<void>;
  openCreditPaymentScoped(request: Uint8Array, expectedEpoch: AppLockEpoch): Promise<void>;
  protectedFile(operation: string, frame: string, bytes: Uint8Array, expectedEpoch: AppLockEpoch): Promise<unknown>;
  publishMessageNotice(frame: string, expectedEpoch: AppLockEpoch): Promise<void>;
  publishEncryptedWakeup(): Promise<void>;
  copyProtectedText(text: string, expectedEpoch: AppLockEpoch): Promise<void>;
  readLegacyPreference(profile: Uint8Array, kind: string, expectedEpoch: AppLockEpoch): string | null;
  removeLegacyPreference(profile: Uint8Array, kind: string, expectedEpoch: AppLockEpoch): void;
  forgetLegacyPreferences(account: string, expectedEpoch: AppLockEpoch): void;
  addListener(event: string, listener: (value: unknown) => void): Subscription;
};
export type AppLockNativeOwner = Omit<AppLockNativePort, 'addListener' | 'publishEncryptedWakeup'> & { release(): void };
// Capture the native SharedObject once. An old service never consults a newer
// view ref or public epoch when an asynchronous operation resumes.
export function bindAppLockOwnerPort(owner: AppLockNativeOwner,
  shared: Pick<AppLockNativePort, 'addListener' | 'publishEncryptedWakeup'>, expected: AppLockEpoch) {
  let released = false;
  const open = () => { if (released) throw stale(); };
  const exact = (value: AppLockEpoch) => { open(); if (value !== expected) throw stale(); };
  const port: AppLockNativePort = Object.freeze({
    getAppLockState: () => { open(); return owner.getAppLockState(); },
    authenticateAppLock: value => { exact(value); return owner.authenticateAppLock(value); },
    setAppLockEnabled: (enabled, value) => { exact(value); return owner.setAppLockEnabled(enabled, value); },
    cancelAppLockAuthentication: request => { open(); return owner.cancelAppLockAuthentication(request); },
    lockApp: () => { open(); return owner.lockApp(); },
    activateAppLockScope: value => { exact(value); return owner.activateAppLockScope(value); },
    checkAppLockScope: value => { exact(value); owner.checkAppLockScope(value); },
    consumeAppLockInboxIntent: value => { exact(value); return owner.consumeAppLockInboxIntent(value); },
    consumeAppLockNotificationIntent: value => {
      exact(value); if (!owner.consumeAppLockNotificationIntent) throw Error('notification_intent_unavailable');
      return owner.consumeAppLockNotificationIntent(value);
    },
    invokeScoped: (symbol, request, value) => { exact(value); return owner.invokeScoped(symbol, request, value); },
    walletScoped: (operation, request, value) => { exact(value); return owner.walletScoped(operation, request, value); },
    primePushTokenScoped: (request, value) => { exact(value); return owner.primePushTokenScoped(request, value); },
    clearPushTokenScoped: (request, value) => { exact(value); return owner.clearPushTokenScoped(request, value); },
    openCreditPaymentScoped: (request, value) => { exact(value); return owner.openCreditPaymentScoped(request, value); },
    protectedFile: (operation, frame, bytes, value) => { exact(value); return owner.protectedFile(operation, frame, bytes, value); },
    publishMessageNotice: (frame, value) => { exact(value); return owner.publishMessageNotice(frame, value); },
    publishEncryptedWakeup: () => shared.publishEncryptedWakeup(),
    copyProtectedText: (text, value) => { exact(value); return owner.copyProtectedText(text, value); },
    readLegacyPreference: (profile, kind, value) => { exact(value); return owner.readLegacyPreference(profile, kind, value); },
    removeLegacyPreference: (profile, kind, value) => { exact(value); owner.removeLegacyPreference(profile, kind, value); },
    forgetLegacyPreferences: (account, value) => { exact(value); owner.forgetLegacyPreferences(account, value); },
    addListener: (event, listener) => { open(); return shared.addListener(event, listener); },
  });
  return Object.freeze({ port, release() { if (!released) { released = true; owner.release(); } } });
}
const epochPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const opaque = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function protectedMetadata(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'string' || value.length > 16_384) throw new Error('invalid_file_response');
  const result: unknown = JSON.parse(value);
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('invalid_file_response');
  const row = result as Record<string, unknown>;
  if (row.version !== 1 || Object.keys(row).some(key => key !== 'version' && !keys.includes(key))) throw new Error('invalid_file_response');
  return row;
}
export function protectedHandle(value: unknown): string {
  if (typeof value !== 'string' || !opaque.test(value)) throw new Error('invalid_file_handle');
  return value;
}
const stale = () => new Error('stale_epoch');
type NotificationIntent = Readonly<{ kind: 'none' }> | Readonly<{ kind: 'inbox' }> | Readonly<{ kind: 'scope'; scope: string }>;
function parseNotificationIntent(value: unknown): NotificationIntent {
  if (typeof value !== 'string' || value.length > 160) throw new Error('invalid_notification_intent');
  const row: unknown = JSON.parse(value);
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('invalid_notification_intent');
  const intent = row as Record<string, unknown>;
  let canonical: string;
  let result: NotificationIntent;
  if (intent.version !== 1) throw new Error('invalid_notification_intent');
  if (intent.kind === 'none' || intent.kind === 'inbox') {
    canonical = JSON.stringify({ version: 1, kind: intent.kind });
    result = { kind: intent.kind };
  } else if (intent.kind === 'scope' && typeof intent.scope === 'string' &&
      intent.scope.length === (intent.scope.startsWith('chat/') ? 37 : 70) &&
      /^(?:chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/.test(intent.scope)) {
    canonical = JSON.stringify({ version: 1, kind: 'scope', scope: intent.scope });
    result = { kind: 'scope', scope: intent.scope };
  } else throw new Error('invalid_notification_intent');
  // Accepted native frames are canonical ASCII, so length is also UTF-8 bytes.
  // Exact comparison rejects extra keys, duplicate keys and escaped aliases.
  if (value !== canonical) throw new Error('invalid_notification_intent');
  return Object.freeze(result);
}
export function parseAppLockState(value: unknown): AppLockState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_lock_state');
  const state = value as Record<string, unknown>;
  if (Object.keys(state).some(key => !['version','policy','phase','capability','epoch','requestId','error'].includes(key)) ||
      state.version !== 1 || typeof state.epoch !== 'string' || !epochPattern.test(state.epoch) ||
      !['disabled','enable_pending','enabled','disable_pending','unknown'].includes(String(state.policy)) ||
      !['booting','locked','authenticating','unlocked','disabled','error'].includes(String(state.phase)) ||
      !['available','unavailable','unknown'].includes(String(state.capability)) ||
      (state.phase === 'disabled' && state.policy !== 'disabled') ||
      (state.phase === 'unlocked' && state.policy !== 'enabled') ||
      (state.requestId !== undefined && (typeof state.requestId !== 'string' || !epochPattern.test(state.requestId))) ||
      (state.error !== undefined && (typeof state.error !== 'string' || !/^[a-z_]{1,64}$/.test(state.error)))) {
    throw new Error('invalid_lock_state');
  }
  return Object.freeze({ ...state }) as AppLockState;
}
export function createAppLockSession(native: AppLockNativePort, expectedEpoch: AppLockEpoch) {
  if (!epochPattern.test(expectedEpoch)) throw new Error('invalid_epoch');
  let disposed = false;
  const subscriptions = new Set<Subscription>();
  const cleanups = new Set<() => void>();
  const assertActive = () => {
    if (disposed) throw stale();
    // A cached/no-op helper path still needs current native authority, even
    // when the native revoke event has not reached the JS thread yet.
    native.checkAppLockScope(expectedEpoch);
    if (disposed) throw stale();
  };
  async function complete<T>(operation: () => Promise<T>, discard?: (value: T) => void | Promise<void>): Promise<T> {
    assertActive();
    let result: { kind: 'value'; value: T } | { kind: 'failure'; error: unknown };
    try { result = { kind: 'value', value: await operation() }; }
    catch (error) { result = { kind: 'failure', error }; }
    try { assertActive(); } catch (error) {
      if (result.kind === 'value') {
        if (result.value instanceof Uint8Array) result.value.fill(0);
        try { await discard?.(result.value); } catch { /* Preserve the original stale failure, never cleanup detail. */ }
      }
      throw error;
    }
    if (result.kind === 'failure') throw result.error;
    return result.value;
  }
  function frame(value: unknown): string {
    const text = JSON.stringify(value);
    if (typeof text !== 'string' || text.length > 16_384) throw new Error('invalid_frame');
    return text;
  }
  async function discardOwnedFileResponse(operation: string, value: unknown): Promise<void> {
    let cleanup: 'closeSource' | 'abortExport' | 'releasePreview';
    let keys: readonly string[];
    switch (operation) {
      case 'claimSource': cleanup = 'closeSource'; keys = ['handle', 'size']; break;
      case 'beginExport': cleanup = 'abortExport'; keys = ['handle']; break;
      case 'writePreview': cleanup = 'releasePreview'; keys = ['handle', 'uri']; break;
      default: return;
    }
    const handle = protectedHandle(protectedMetadata(value, keys).handle);
    // Cleanup only, bound to this captured epoch even after local disposal or
    // native revocation. No returned URI/context/operation becomes authority.
    await native.protectedFile(cleanup, frame({ version: 1, handle }), new Uint8Array(), expectedEpoch);
  }
  function immediate<T>(operation: () => T): T {
    assertActive();
    const value = operation();
    assertActive();
    return value;
  }
  return Object.freeze({
    epoch: expectedEpoch,
    assertActive,
    assertCurrent: assertActive,
    runPrivate: <T>(operation: () => Promise<T>) => complete(operation),
    dispose() {
      if (disposed) return;
      disposed = true;
      for (const subscription of subscriptions) subscription.remove();
      subscriptions.clear();
      for (const cleanup of cleanups) cleanup();
      cleanups.clear();
    },
    onDispose(cleanup: () => void) { assertActive(); cleanups.add(cleanup); return () => { cleanups.delete(cleanup); }; },
    invoke: (symbol: string, request: Uint8Array) => complete(() => native.invokeScoped(symbol, request, expectedEpoch)),
    invokeWallet: (operation: number, request: Uint8Array) => complete(() => native.walletScoped(operation, request, expectedEpoch)),
    primePushToken: (request: Uint8Array) => complete(() => native.primePushTokenScoped(request, expectedEpoch)),
    clearPushToken: (request: Uint8Array) => complete(() => native.clearPushTokenScoped(request, expectedEpoch)),
    openNativeCreditPayment: (request: Uint8Array) => complete(() => native.openCreditPaymentScoped(request, expectedEpoch)),
    protectedFile: (operation: string, context: unknown, bytes: Parameters<AppLockNativePort['protectedFile']>[2] = new Uint8Array()) =>
      complete(() => native.protectedFile(operation, frame(context), bytes, expectedEpoch),
        value => discardOwnedFileResponse(operation, value)),
    // Cleanup can only discard native-owned resources belonging to this old
    // epoch. It cannot read/write/publish or delete a later scope's resources.
    cleanupProtectedFile(operation: 'abortExport' | 'releasePreview' | 'closeSource' | 'discardPreviews', context: unknown) {
      if (!['abortExport','releasePreview','closeSource','discardPreviews'].includes(operation)) return Promise.reject(new Error('invalid_cleanup'));
      return native.protectedFile(operation, frame(context), new Uint8Array(), expectedEpoch);
    },
    onInboxOpen(listener: () => void) {
      assertActive();
      const deliver = () => {
        if (disposed) return;
        try { assertActive(); if (!native.consumeAppLockInboxIntent(expectedEpoch)) return; } catch { return; }
        listener();
      };
      const subscription = native.addListener('onAppLockInboxOpen', deliver);
      subscriptions.add(subscription);
      deliver(); // A cold-launch tap waits natively until this fresh scope.
      return () => { subscriptions.delete(subscription); subscription.remove(); };
    },
    onNotificationOpen(listener: (intent: Exclude<NotificationIntent, { kind: 'none' }>) => void) {
      assertActive();
      const consume = native.consumeAppLockNotificationIntent;
      if (typeof consume !== 'function') throw new Error('notification_intent_unavailable');
      let closed = false;
      const deliver = () => {
        if (closed || disposed) return;
        let intent: NotificationIntent;
        try {
          assertActive();
          const value = consume.call(native, expectedEpoch);
          assertActive();
          intent = parseNotificationIntent(value);
          assertActive();
        } catch { return; }
        if (intent.kind !== 'none') listener(intent);
      };
      // The native event is only an empty wake. Read the bounded current intent
      // after subscribing; never retain a scope copied from an event payload.
      const subscription = native.addListener('onAppLockInboxOpen', deliver);
      if (disposed) { subscription.remove(); throw stale(); }
      subscriptions.add(subscription);
      deliver();
      return () => {
        if (closed) return;
        closed = true; subscriptions.delete(subscription); subscription.remove();
      };
    },
    copyProtectedText: (text: string) => complete(() => native.copyProtectedText(text, expectedEpoch)),
    publishMessageNotice: (context: unknown) => complete(() => native.publishMessageNotice(frame(context), expectedEpoch)),
    readLegacyPreference: (profile: Uint8Array, kind: string) => immediate(() => native.readLegacyPreference(profile, kind, expectedEpoch)),
    removeLegacyPreference: (profile: Uint8Array, kind: string) => immediate(() => native.removeLegacyPreference(profile, kind, expectedEpoch)),
    forgetLegacyPreferences: (account: string) => immediate(() => native.forgetLegacyPreferences(account, expectedEpoch)),
    onPushRegistrationChanged(listener: () => void) {
      assertActive();
      const subscription = native.addListener('onPushRegistrationChanged', () => {
        if (disposed) return;
        try { assertActive(); } catch { return; }
        listener();
      });
      subscriptions.add(subscription);
      return () => { subscriptions.delete(subscription); subscription.remove(); };
    },
  });
}
export type AppLockSession = ReturnType<typeof createAppLockSession>;

// Bind completion as well as entry: an existing helper can resolve entirely
// from a cache/queue without invoking any private bridge method itself.
export function bindAppLockFunctions<T extends object>(scope: Pick<AppLockSession, 'assertActive'>, functions: T): T {
  const publish = (value: unknown) => {
    try { scope.assertActive(); }
    catch (error) {
      if (value instanceof Uint8Array) value.fill(0);
      throw error;
    }
    return value;
  };
  const refuse = (error: unknown): never => { scope.assertActive(); throw error; };
  const bound = Object.fromEntries(Object.entries(functions).map(([name, handler]) => [name,
    typeof handler !== 'function' ? handler : (...args: unknown[]) => {
      scope.assertActive();
      let result: unknown;
      try { result = handler(...args); } catch (error) { return refuse(error); }
      if (((typeof result === 'object' && result !== null) || typeof result === 'function') &&
          'then' in result && typeof result.then === 'function') return Promise.resolve(result).then(publish, refuse);
      return publish(result);
    },
  ]));
  return Object.freeze(bound) as T;
}
