import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Text, View } from 'react-native';
import { AppLockOwnerView, getAppLockNativePort, onAppLockChanged, type AppLockOwnerHandle } from '../modules/mesh-messenger';
import { bindAppLockOwnerPort, parseAppLockState, type AppLockNativePort, type AppLockState } from './app-lock';
import { Button } from './ui';
import { useI18n } from './language';

type OwnerBinding = {
  epoch: string; view: AppLockOwnerHandle; observation: number;
  phase: 'pending' | 'failed' | 'bound'; retryQueued: boolean;
};

// Mounting private App is a consequence of native state, never a JS auth flag.
export function AppLockGate({ children }: { children: (state: AppLockState, native: AppLockNativePort) => ReactNode }) {
  const { t } = useI18n();
  const [state, setState] = useState<AppLockState>();
  const [error, setError] = useState(false);
  const ownerView = useRef<AppLockOwnerHandle | null>(null);
  const [attachment, setAttachment] = useState(0);
  const [bindingRetry, setBindingRetry] = useState(0);
  const binding = useRef<OwnerBinding | undefined>(undefined);
  const [bound, setBound] = useState<{ epoch: string; attachment: number; port: AppLockNativePort }>();
  // A stable callback is required by React's imperative ref lifecycle.
  const attach = useCallback((view: AppLockOwnerHandle | null) => {
    ownerView.current = view; setAttachment(value => value + 1);
  }, []);
  const authority = useRef<{ alive: boolean; generation: number; epoch?: string }>({ alive: false, generation: 0 });
  useEffect(() => {
    authority.current.alive = true;
    let alive = true; let observed = 0;
    const accept = (value: unknown) => {
      if (!alive) return;
      authority.current.generation++;
      try {
        const parsed = parseAppLockState(value);
        authority.current.epoch = parsed.epoch;
        setState(parsed); setError(false);
        if (binding.current) retryObservedBinding(binding.current);
      } catch { authority.current.epoch = undefined; setState(undefined); setError(true); }
    };
    const remove = onAppLockChanged(value => { observed++; accept(value); });
    const before = observed;
    void getAppLockNativePort().getAppLockState().then(value => {
      if (before === observed) accept(value);
    }).catch(() => { if (alive && before === observed) { setState(undefined); setError(true); } });
    return () => { alive = false; authority.current.alive = false; authority.current.generation++; remove(); };
  }, []);
  const epoch = state?.epoch;
  useEffect(() => {
    let alive = true;
    let release: (() => void) | undefined;
    setBound(undefined);
    if (!epoch) return;
    const shared = getAppLockNativePort();
    if (!AppLockOwnerView) { setBound({ epoch, attachment, port: shared }); return; }
    const view = ownerView.current;
    if (!view) return;
    const attempt: OwnerBinding = { epoch, view, observation: authority.current.generation, phase: 'pending', retryQueued: false };
    binding.current = attempt;
    void view.bindOwner(epoch).then(owner => {
      const owned = bindAppLockOwnerPort(owner, shared, epoch);
      if (!alive || binding.current !== attempt) { owned.release(); return; }
      attempt.phase = 'bound';
      release = owned.release;
      setBound({ epoch, attachment, port: owned.port });
    }).catch(() => {
      if (!alive || binding.current !== attempt) return;
      attempt.phase = 'failed'; setBound(undefined); retryObservedBinding(attempt);
    });
    return () => { alive = false; if (binding.current === attempt) binding.current = undefined; release?.(); };
  }, [epoch, attachment, bindingRetry]);
  function retryObservedBinding(attempt: OwnerBinding) {
    if (binding.current !== attempt || attempt.phase !== 'failed' || attempt.retryQueued ||
      !authority.current.alive || authority.current.epoch !== attempt.epoch || ownerView.current !== attempt.view ||
      authority.current.generation <= attempt.observation) return;
    attempt.retryQueued = true; setBindingRetry(value => value + 1);
  }
  const native = bound && bound.epoch === epoch && bound.attachment === attachment ? bound.port : undefined;
  const command = async (operation: (expected: string) => Promise<unknown>) => {
    if (!state || !native) return;
    const expected = state.epoch;
    const generation = authority.current.generation;
    try {
      // Native owns request/result lifecycle and emits the resulting state. The
      // returned promise cannot resurrect an older state after a newer event.
      await operation(expected);
    } catch {
      if (authority.current.alive && authority.current.epoch === expected && authority.current.generation === generation) setError(true);
    }
  };
  const authenticate = (enable?: boolean) => {
    if (!native) return;
    return command(expected => enable === undefined
      ? native.authenticateAppLock(expected) : native.setAppLockEnabled(enable, expected));
  };
  const content = !error && state && native && (state.phase === 'disabled' || state.phase === 'unlocked') ? children(state, native)
    : <View accessibilityViewIsModal style={{ flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24 }}>
    <Text accessibilityRole="header">{t('Morse is locked')}</Text>
    {error || state?.error ? <Text>{t('Could not unlock. Your messages remain protected.')}</Text> : null}
    {state?.phase === 'authenticating' ? <Button label={t('Cancel authentication')} onPress={() => {
      const request = state.requestId;
      if (request && native) void command(() => native.cancelAppLockAuthentication(request));
    }} /> : state?.policy === 'enable_pending' || state?.policy === 'disable_pending' ? <>
      <Button label={t('Finish enabling app lock')} onPress={() => { void authenticate(true); }} />
      <Button label={t('Turn off app lock')} onPress={() => { void authenticate(false); }} />
    </> : <Button label={t('Unlock with device authentication')} disabled={!state || !native || state.phase === 'booting'} onPress={() => { void authenticate(); }} />}
  </View>;
  return AppLockOwnerView ? <AppLockOwnerView ref={attach} style={{ flex: 1 }}
    onOwnerAttached={() => setAttachment(value => value + 1)}>{content}</AppLockOwnerView> : content;
}
