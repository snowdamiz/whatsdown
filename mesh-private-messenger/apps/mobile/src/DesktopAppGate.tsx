import { Component, useEffect, useLayoutEffect, useState, type ReactNode } from 'react';
import { bindDesktopOwner, type DesktopOwnerClient, type DesktopOwnerTransport } from './desktop-owner-client.ts';
import type { DesktopLockSnapshot } from './desktop-lock-protocol.ts';
import { createDesktopAppServices as createScopedDesktopAppServices } from './app-lock-services.web.ts';
import type { AppServices } from './app-services.ts';

type OwnedServices = Awaited<ReturnType<typeof createScopedDesktopAppServices>>;
type Presentation = { kind: 'pending'; activate?: () => void } | { kind: 'failed' } |
  { kind: 'private'; services: AppServices; fail(): void };
type GateView = { transport: DesktopOwnerTransport; presentation: Presentation };
class PrivateBoundary extends Component<{ children: ReactNode; onFailure(): void }, { retired: boolean }> {
  state = { retired: false };
  static getDerivedStateFromError() { return { retired: true }; }
  componentDidCatch() { this.props.onFailure(); }
  render() { return this.state.retired ? null : this.props.children; }
}
function PrivateContent({ services, render }: { services: AppServices; render(services: AppServices): ReactNode }) {
  return render(services);
}
export function DesktopAppGate({ transport, pending, failed, children }: {
  transport: DesktopOwnerTransport;
  pending: ReactNode;
  failed: ReactNode;
  children(services: AppServices): ReactNode;
}) {
  const [view, setView] = useState<GateView>({ transport, presentation: { kind: 'pending' } });
  useEffect(() => {
    const show = (presentation: Presentation) => setView({ transport, presentation });
    const abort = new AbortController(), cleanup = new Set<Promise<boolean>>();
    let open = true;
    let client: DesktopOwnerClient | undefined;
    let latest: DesktopLockSnapshot | undefined;
    let owned: { key: string; value: OwnedServices } | undefined;
    let construction: { key: string } | undefined;
    let activation: { epoch: string; revision: bigint; pending: boolean } | undefined;
    function retire(value: OwnedServices) {
      const closing = value.close(); // Retires private admission synchronously.
      cleanup.add(closing);
      void closing.then(() => { cleanup.delete(closing); }, () => { cleanup.delete(closing); });
    }
    function retireTree() {
      if (owned) { const value = owned.value; owned = undefined; retire(value); }
    }
    function fail() {
      construction = undefined;
      activation = undefined;
      retireTree();
      if (open) show({ kind: 'failed' });
    }
    function observe(snapshot: DesktopLockSnapshot) {
      if (!open) return;
      latest = snapshot;
      if (!client) return;
      const capturedClient = client;
      const { state } = snapshot;
      if (state.phase !== 'activated' || !state.foreground) {
        construction = undefined;
        retireTree();
        if (state.phase === 'error') { activation = undefined; show({ kind: 'failed' }); return; }
        if (!state.foreground || (state.phase !== 'disabled' && state.phase !== 'awaiting_activation')) {
          activation = undefined; show({ kind: 'pending' }); return;
        }
        show({ kind: 'pending', activate() {
          if (!open || latest !== snapshot) return;
          const revision = BigInt(snapshot.revision);
          if (activation?.epoch === state.epoch && (activation.pending || revision <= activation.revision)) return;
          const attempt = { epoch: state.epoch, revision, pending: true };
          activation = attempt;
          void capturedClient.activate(state.epoch).then(() => {
            if (activation === attempt) attempt.pending = false;
          }, () => {
            if (!open || activation !== attempt) return;
            attempt.pending = false;
            // A focus/state observation can arrive while activation is pending.
            // Retry only after that new observation has committed a public tree.
            if (latest && BigInt(latest.revision) > revision) observe(latest);
          });
        } });
        return;
      }
      activation = undefined;
      const key = `${snapshot.owner}/${state.epoch}/${state.policy}/${state.capability}`;
      if (owned?.key === key || construction?.key === key) return;
      retireTree();
      show({ kind: 'pending' });
      const request = { key }; construction = request;
      void createScopedDesktopAppServices(capturedClient).then(value => {
        if (!open || construction !== request) { retire(value); return; }
        construction = undefined;
        owned = { key, value };
        show({ kind: 'private', services: value.services, fail() { fail(); void capturedClient.close(); } });
      }, () => {
        if (open && construction === request) { fail(); void capturedClient.close(); }
      });
    }
    void bindDesktopOwner(transport, { signal: abort.signal, onSnapshot: observe,
      onRetired() { if (open) fail(); },
    }).then(value => {
      client = value;
      if (!open) { void value.close(); return; }
      observe(value.snapshot());
    }, () => { if (open) fail(); });
    return () => {
      open = false;
      const preparing = construction !== undefined;
      construction = undefined; activation = undefined;
      retireTree();
      if (!client) { abort.abort(); return; }
      const captured = client;
      // Preparing factories have not returned a session disposer yet. Closing
      // their owner retires that admission and makes late setup clean itself.
      if (preparing) { void captured.close(); return; }
      void (async () => {
        while (cleanup.size) await Promise.allSettled([...cleanup]);
        await captured.close();
      })();
    };
  }, [transport]);
  const shown: Presentation = view.transport === transport ? view.presentation : { kind: 'pending' };
  useLayoutEffect(() => {
    if (view.transport === transport && view.presentation.kind === 'pending') view.presentation.activate?.();
  }, [view, transport]);
  if (shown.kind === 'private') return <PrivateBoundary onFailure={shown.fail}>
    <PrivateContent services={shown.services} render={children} />
  </PrivateBoundary>;
  return shown.kind === 'failed' ? failed : pending;
}
