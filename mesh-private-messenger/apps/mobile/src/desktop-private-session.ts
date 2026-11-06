// This port captures one native page binding and epoch. Every method still
// validates native authority; a JavaScript session cannot grant access.
export type DesktopPrivatePort = Readonly<{
  check(): Promise<void>;
  invoke(symbol: string, request: Uint8Array): Promise<Uint8Array>;
  invokeWallet(operation: number, request: Uint8Array): Promise<Uint8Array>;
  copyProtectedText(text: string): Promise<void>;
}>;

export function createDesktopPrivateSession(port: DesktopPrivatePort) {
  const check = port.check.bind(port);
  const invoke = port.invoke.bind(port);
  const wallet = port.invokeWallet.bind(port);
  const copy = port.copyProtectedText.bind(port);
  let open = true;
  let clean = true;
  const cleanups = new Set<() => void>();
  function requireOpen() { if (!open) throw Error('stale_epoch'); }
  async function assertActive() {
    requireOpen();
    await check();
    requireOpen();
  }
  async function complete<T>(operation: () => Promise<T>): Promise<T> {
    await assertActive();
    requireOpen();
    let result: { kind: 'value'; value: T } | { kind: 'failure'; error: unknown };
    try { result = { kind: 'value', value: await operation() }; }
    catch (error) { result = { kind: 'failure', error }; }
    try { await assertActive(); requireOpen(); }
    catch (error) {
      if (result.kind === 'value' && result.value instanceof Uint8Array) result.value.fill(0);
      throw error;
    }
    // A native failure can contain private detail too. Publish it only after
    // the same completion fence used for successful bytes.
    if (result.kind === 'failure') throw result.error;
    return result.value;
  }
  return Object.freeze({
    assertActive,
    assertCurrent: requireOpen,
    runPrivate: complete,
    invoke: (symbol: string, request: Uint8Array) => complete(() => invoke(symbol, request)),
    invokeWallet: (operation: number, request: Uint8Array) => complete(() => wallet(operation, request)),
    copyProtectedText: (text: string) => complete(() => copy(text)),
    onDispose(cleanup: () => void) {
      requireOpen(); cleanups.add(cleanup);
      return () => { cleanups.delete(cleanup); };
    },
    dispose() {
      if (!open) return clean;
      open = false;
      const pending = [...cleanups]; cleanups.clear();
      for (const cleanup of pending) {
        try { cleanup(); } catch { clean = false; }
      }
      return clean;
    },
  });
}
export type DesktopPrivateSession = ReturnType<typeof createDesktopPrivateSession>;
