// IPC serialization follows Tauri 2's documented custom invoke system and
// __TAURI_TO_IPC_KEY__ contract. Transport is always the native postMessage
// bridge, including channel data; it never probes a fetch-based protocol.
;(function () {
  // Tauri substitutes this token before installing the script. Keep the key
  // outside the function exposed to the page, just as Tauri's default does.
  const invokeKey = __INVOKE_KEY__;

  function send(message) {
    const { cmd, callback, error, payload, options } = message;
    const serialized = JSON.stringify({
      cmd, callback, error, payload,
      options: { ...options, customProtocolIpcBlocked: true },
      __TAURI_INVOKE_KEY__: invokeKey,
    }, (_key, value) => {
      if (value instanceof Map) return Object.fromEntries(value.entries());
      if (value instanceof Uint8Array) return Array.from(value);
      if (value instanceof ArrayBuffer) return Array.from(new Uint8Array(value));
      if (value !== null && typeof value === 'object' && '__TAURI_TO_IPC_KEY__' in value) {
        return value.__TAURI_TO_IPC_KEY__();
      }
      return value;
    });
    window.ipc.postMessage(serialized);
  }

  Object.defineProperty(window.__TAURI_INTERNALS__, 'postMessage', { value: send });
})();
