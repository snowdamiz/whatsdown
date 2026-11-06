import { Component, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import App from "./App";
import { loadAppearance, saveAppearance } from "./appearance-store";
import { KeyboardProvider } from "./keyboard";
import { LanguageProvider } from "./language";
import { AppearanceProvider } from "./theme";
import { AppLockGate } from './AppLockGate';
import { createAppLockSession, type AppLockNativePort, type AppLockState } from './app-lock';
import { createAppServices } from './app-lock-services';

type ActivationAttempt = {
  native: AppLockNativePort; observation: number; phase: 'pending' | 'failed' | 'succeeded';
};

class ProtectedAppBoundary extends Component<{
  native: AppLockNativePort; epoch: string; children: ReactNode;
}, { retired: boolean }> {
  state = { retired: false };
  static getDerivedStateFromError() { return { retired: true }; }
  componentDidCatch(error: unknown) {
    // Native revocation can precede the event that replaces this React tree.
    // Retire its complete scope without unmounting Gate's state subscription.
    // Gate still owns this captured port after the child scope is disposed.
    try { this.props.native.checkAppLockScope(this.props.epoch); }
    catch { return; }
    throw error;
  }
  render() { return this.state.retired ? null : this.props.children; }
}

function ProtectedApp({ state, native, notice, onAccountErased }: { state: AppLockState; native: AppLockNativePort; notice?: string; onAccountErased: (notice?: string) => void }) {
  const [scope] = useState(() => createAppLockSession(native, state.epoch));
  const [services] = useState(() => createAppServices(scope, native, state.policy !== 'disabled'));
  const observation = useRef(0);
  const activation = useRef<ActivationAttempt | undefined>(undefined);
  const [activationRetry, setActivationRetry] = useState(0);
  useLayoutEffect(() => () => {
    activation.current = undefined;
    scope.dispose();
  }, [scope]);
  useLayoutEffect(() => { observation.current++; }, [state]);
  useLayoutEffect(() => {
    const previous = activation.current;
    if (previous?.native === native && (previous.phase !== 'failed' ||
      observation.current <= previous.observation)) return;
    const attempt: ActivationAttempt = { native, observation: observation.current, phase: 'pending' };
    activation.current = attempt;
    // Native keeps its cover until this protected tree has committed. A fresh
    // observation can retry an inactive refusal; native still checks the exact
    // owner and already-authorized epoch. Success may itself emit an observation.
    void (async () => {
      try {
        await native.activateAppLockScope(scope.epoch);
        if (activation.current === attempt) attempt.phase = 'succeeded';
      } catch {
        if (activation.current !== attempt) return;
        attempt.phase = 'failed';
        if (observation.current > attempt.observation) setActivationRetry(value => value + 1);
      }
    })();
  }, [scope, native, state, activationRetry]);
  return <App services={services} environment={{ kind: 'mobile', scope }} notice={notice} onAccountErased={onAccountErased} />;
}

export default function Root() {
  // An erased account restarts the app, so nothing of it stays in memory.
  const [session, setSession] = useState<{ generation: number; notice?: string }>({ generation: 0 });
  return (
    <KeyboardProvider>
      <LanguageProvider>
        <AppearanceProvider load={loadAppearance} save={saveAppearance}>
          <AppLockGate>{(state, native) => <ProtectedAppBoundary key={`${state.epoch}/${session.generation}`} epoch={state.epoch} native={native}>
            <ProtectedApp state={state} native={native} notice={session.notice}
              onAccountErased={(notice) => setSession(({ generation }) => ({ generation: generation + 1, notice }))} />
          </ProtectedAppBoundary>}</AppLockGate>
        </AppearanceProvider>
      </LanguageProvider>
    </KeyboardProvider>
  );
}
