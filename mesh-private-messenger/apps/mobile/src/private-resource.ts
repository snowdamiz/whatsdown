import type { AppLockSession } from './app-lock';

// The operation may create a resource before its final native check refuses.
// Retain cleanup ownership until that check accepts the result.
export async function runPrivateOwned<T>({ scope, operation, discard }: {
  scope: Pick<AppLockSession, 'runPrivate' | 'assertCurrent'>;
  operation: () => Promise<T>;
  discard: (value: T) => void | Promise<void>;
}): Promise<T> {
  const held: { result?: { value: T } } = {};
  try {
    const result = await scope.runPrivate(async () => {
      const value = await operation(); held.result = { value }; return value;
    });
    scope.assertCurrent();
    return result;
  } catch (error) {
    if (held.result) {
      if (held.result.value instanceof Uint8Array) held.result.value.fill(0);
      try { await discard(held.result.value); } catch { /* Cleanup cannot publish a different private error. */ }
      finally { if (held.result.value instanceof Uint8Array) held.result.value.fill(0); }
    }
    scope.assertCurrent();
    throw error;
  }
}
