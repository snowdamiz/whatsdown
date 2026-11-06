import { createContext, useContext, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { Modal, Platform, StyleSheet, TextInput, View, useWindowDimensions, type ModalProps, type ViewInstance } from 'react-native';
import type { AppLockSession } from './app-lock';

type Scope = Pick<AppLockSession, 'assertActive' | 'onDispose'>;
type Input = ReturnType<typeof TextInput.State.currentlyFocusedInput>;
type Entry = { identity: symbol; order: number; content: ReactNode; close: () => void; previousInput: Input; returnTo: symbol | undefined };
type Viewport = { x: number; y: number; width: number; height: number };
type Lease = {
  readonly generation: number;
  readonly closed: boolean;
  register(identity: symbol, content: ReactNode, close: () => void): void;
  update(identity: symbol, content: ReactNode, close: () => void): void;
  remove(identity: symbol): void;
  dismissTop(): boolean;
  restoreFocus(): void;
  retire(): void;
};
const LeaseContext = createContext<Lease | null | undefined>(undefined);
const InteractiveContext = createContext(true);
const ViewportContext = createContext<Viewport | null>(null);

// This is scoped UI state, never native authority. Each API captures one
// immutable effect-mount lease, so StrictMode cannot revive an older callback.
function createLease(generation: number, scope: Scope, current: () => boolean,
  publish: (entries: Entry[]) => void): Lease {
  let closed = false, sequence = 0;
  const entries = new Map<symbol, Entry>();
  let pendingFocus: { target: Input; owner: symbol | undefined } | undefined;
  const active = () => !closed && current();
  const top = () => [...entries.values()].at(-1);
  const changed = () => { if (current()) publish([...entries.values()]); };
  const retire = () => { if (closed) return; closed = true; entries.clear(); pendingFocus = undefined; changed(); };
  return {
    generation, get closed() { return closed; },
    register(identity, content, close) {
      if (!active() || entries.has(identity)) return;
      scope.assertActive();
      const focusedInput = TextInput.State.currentlyFocusedInput();
      // A removed overlay may still own native focus until this commit ends.
      const previousInput = pendingFocus ? pendingFocus.target : focusedInput;
      const returnTo = top()?.identity;
      pendingFocus = undefined;
      focusedInput?.blur();
      // Native blur can synchronously run callbacks, including scope disposal.
      if (!active()) return;
      scope.assertActive();
      entries.set(identity, { identity, content, close, order: ++sequence, previousInput, returnTo }); changed();
    },
    update(identity, content, close) {
      if (!active()) return;
      const entry = entries.get(identity); if (!entry) return;
      scope.assertActive(); entries.set(identity, { ...entry, content, close }); changed();
    },
    remove(identity) {
      if (!active()) return;
      const entry = entries.get(identity); if (!entry) return;
      const wasTop = top() === entry;
      entries.delete(identity);
      // Removing a lower overlay cannot leave a return target in its old form.
      for (const [key, child] of entries) if (child.returnTo === identity) entries.set(key,
        { ...child, previousInput: entry.previousInput, returnTo: entry.returnTo });
      if (wasTop) pendingFocus = { target: entry.previousInput, owner: entry.returnTo };
      changed();
    },
    restoreFocus() {
      if (!active() || !pendingFocus) return;
      const pending = pendingFocus; pendingFocus = undefined;
      if (top()?.identity !== pending.owner) return;
      try { scope.assertActive(); } catch { retire(); return; }
      if (active()) pending.target?.focus();
    },
    dismissTop() {
      // A queued callback from an older effect mount consumes no new action.
      if (!active()) return true;
      const entry = top(); if (!entry) return false;
      try { scope.assertActive(); } catch { retire(); return true; }
      entry.close(); return true;
    },
    retire,
  };
}

export function useActivityOverlayInteractive() { return useContext(InteractiveContext); }
export function useActivityOverlay() { return useContext(LeaseContext); }
export function useActivityOverlayViewport(): Viewport {
  const host = useContext(ViewportContext), window = useWindowDimensions();
  return host ?? { x: 0, y: 0, width: window.width, height: window.height };
}

function AndroidOverlayHost({ scope, children }: { scope: Scope; children: ReactNode }) {
  const window = useWindowDimensions();
  const view = useRef<ViewInstance | null>(null), current = useRef<Lease | null>(null), generation = useRef(0);
  const [lease, setLease] = useState<Lease | null>(null);
  const [snapshot, setSnapshot] = useState<{ lease: Lease | null; entries: Entry[] }>({ lease: null, entries: [] });
  const [viewport, setViewport] = useState<Viewport>({ x: 0, y: 0, width: window.width, height: window.height });
  function measure(expected: Lease | null) {
    const measured = view.current;
    measured?.measureInWindow((x, y, width, height) => {
      if (!expected || expected.closed || current.current !== expected || view.current !== measured || width <= 0 || height <= 0) return;
      setViewport(previous => previous.x === x && previous.y === y && previous.width === width && previous.height === height
        ? previous : { x, y, width, height });
    });
  }
  useLayoutEffect(() => {
    const mounted = createLease(++generation.current, scope, () => current.current === mounted,
      entries => { if (current.current === mounted) setSnapshot({ lease: mounted, entries }); });
    current.current = mounted; setLease(mounted); setSnapshot({ lease: mounted, entries: [] });
    let remove: () => void;
    try { remove = scope.onDispose(mounted.retire); }
    catch (error) { current.current = null; mounted.retire(); throw error; }
    measure(mounted);
    return () => { if (current.current === mounted) current.current = null; mounted.retire(); remove(); };
  }, [scope]);
  useLayoutEffect(() => { if (snapshot.lease === lease) lease?.restoreFocus(); }, [snapshot, lease]);
  const entries = lease && !lease.closed && snapshot.lease === lease ? snapshot.entries : [];
  return <LeaseContext.Provider value={lease}><ViewportContext.Provider value={viewport}>
    <View ref={view} collapsable={false} style={styles.fill} onLayout={() => measure(current.current)}>
      <View style={styles.fill} testID="protected-activity-content" accessibilityElementsHidden={entries.length > 0}
        importantForAccessibility={entries.length ? 'no-hide-descendants' : 'auto'} pointerEvents={entries.length ? 'none' : 'auto'}>
        <InteractiveContext.Provider value={!entries.length}>{children}</InteractiveContext.Provider>
      </View>
      {entries.map((entry, index) => <View key={`${lease?.generation}/${entry.order}`} style={StyleSheet.absoluteFill}
        testID="protected-activity-overlay" accessibilityViewIsModal={index === entries.length - 1}
        accessibilityElementsHidden={index !== entries.length - 1}
        importantForAccessibility={index === entries.length - 1 ? 'auto' : 'no-hide-descendants'}
        pointerEvents={index === entries.length - 1 ? 'auto' : 'none'}>
        <InteractiveContext.Provider value={index === entries.length - 1}>{entry.content}</InteractiveContext.Provider>
      </View>)}
    </View>
  </ViewportContext.Provider></LeaseContext.Provider>;
}
export function ActivityOverlayHost(props: { scope: Scope; children: ReactNode }) {
  return Platform.OS === 'android' ? <AndroidOverlayHost {...props} /> : <>{props.children}</>;
}
function AndroidOverlay({ children, onRequestClose }: { children: ReactNode; onRequestClose: () => void }) {
  const lease = useContext(LeaseContext), [identity] = useState(() => Symbol());
  if (lease === undefined) throw Error('protected_activity_overlay_host_required');
  useLayoutEffect(() => {
    lease?.register(identity, children, onRequestClose);
    return () => lease?.remove(identity);
  }, [lease, identity]);
  useLayoutEffect(() => { lease?.update(identity, children, onRequestClose); }, [lease, identity, children, onRequestClose]);
  return null;
}
export function ActivityModal({ onRequestClose, ...props }: Omit<ModalProps, 'onRequestClose'> & { onRequestClose: () => void }) {
  if (Platform.OS !== 'android') return <Modal {...props} onRequestClose={onRequestClose} />;
  return props.visible === false ? null : <AndroidOverlay onRequestClose={onRequestClose}>{props.children}</AndroidOverlay>;
}
const styles = StyleSheet.create({ fill: { flex: 1 } });
