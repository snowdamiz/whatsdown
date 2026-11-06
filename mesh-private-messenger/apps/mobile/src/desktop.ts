import { invoke } from '@tauri-apps/api/core';
import { MAX_DESKTOP_REPLY, takeDesktopBytes } from './desktop-binary-reply.ts';

// Wire frames travel as the raw IPC body; only the symbol name rides in a header.
export async function invokeMesh(symbol: string, request: Uint8Array): Promise<Uint8Array> {
  try {
    return takeDesktopBytes(await invoke<unknown>('mesh_invoke', request, { headers: { 'X-Mesh-Symbol': symbol } }), MAX_DESKTOP_REPLY, 'invalid_desktop_private_reply');
  } catch (error) { throw new Error(String(error)); }
}

export async function invokeWallet(operation: number, request: Uint8Array): Promise<Uint8Array> {
  try {
    return takeDesktopBytes(await invoke<unknown>('wallet_invoke', request, { headers: { 'X-Wallet-Operation': String(operation) } }), MAX_DESKTOP_REPLY, 'invalid_desktop_private_reply');
  } catch (error) { throw new Error(String(error)); }
}
