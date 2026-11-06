// Matches the largest generic native response, mesh_messenger_load_history.
export const MAX_DESKTOP_REPLY = 16_794_632;

// Takes ownership of the parsed IPC reply. macOS postMessage supplies a JSON
// byte array; other Tauri transports can supply an ArrayBuffer.
export function takeDesktopBytes(value: unknown, maximum: number, failure: string): Uint8Array {
  if (value instanceof ArrayBuffer) {
    const bytes = new Uint8Array(value);
    if (bytes.length > maximum) { bytes.fill(0); throw Error(failure); }
    return bytes;
  }
  if (!Array.isArray(value)) throw Error(failure);
  const array: unknown[] = value;
  let bytes: Uint8Array | undefined;
  try {
    if (array.length > maximum) throw Error(failure);
    bytes = new Uint8Array(array.length);
    for (let i = 0; i < array.length; i++) {
      const byte = array[i];
      if (!Object.hasOwn(array, i) || typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) throw Error(failure);
      bytes[i] = byte;
    }
    return bytes;
  } catch {
    bytes?.fill(0);
    throw Error(failure);
  } finally {
    array.fill(0);
  }
}
