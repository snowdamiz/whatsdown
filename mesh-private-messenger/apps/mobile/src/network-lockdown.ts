const constructors = ['XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection'];

// Tauri's installed IPC protocol falls back to its native postMessage bridge
// when fetch rejects. Throwing before returning a Promise would break that path.
async function blockedFetch(): Promise<never> {
  throw new Error('native_network_required');
}

function blockedTransport(): never {
  throw new Error('native_network_required');
}

function names(name: string): string[] {
  // React Native and Expo retain differently cased development backups. Replace
  // descriptors directly: reading a lazy backup can restore the original API.
  return [...new Set([name, `original${name.charAt(0).toUpperCase()}${name.slice(1)}`, `original${name}`])];
}

/** Locks ordinary JS transports; native modules require a separate inventory. */
export function installNetworkLockdown(target: object = globalThis): void {
  try {
    const slots: [object, string, unknown][] = [];
    for (const name of names('fetch')) slots.push([target, name, blockedFetch]);
    for (const name of constructors) for (const alias of names(name)) slots.push([target, alias, blockedTransport]);
    const navigator = Reflect.get(target, 'navigator');
    if (navigator && (typeof navigator === 'object' || typeof navigator === 'function')) {
      for (const name of names('sendBeacon')) slots.push([navigator, name, blockedTransport]);
    }
    for (const [object, name, value] of slots) {
      const descriptor = Object.getOwnPropertyDescriptor(object, name);
      if (descriptor && !descriptor.configurable &&
        (!('value' in descriptor) || descriptor.value !== value || descriptor.writable)) {
        throw new Error('network_lockdown_failed');
      }
    }
    for (const [object, name, value] of slots) {
      Object.defineProperty(object, name, { value, configurable: false, writable: false, enumerable: false });
    }
  } catch {
    // Fail before app/background modules evaluate; never continue with a live
    // transport or put a URL/request value into an error or log.
    throw new Error('network_lockdown_failed');
  }
}
