import { invoke } from '@tauri-apps/api/core';

// Wire frames travel as the raw IPC body; only the symbol name rides in a header.
export async function invokeMesh(symbol: string, request: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await invoke<ArrayBuffer>('mesh_invoke', request, { headers: { 'X-Mesh-Symbol': symbol } }));
  } catch (error) { throw new Error(String(error)); }
}
