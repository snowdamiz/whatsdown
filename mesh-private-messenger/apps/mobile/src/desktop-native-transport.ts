import { captureDesktopDocument } from './desktop-document.ts';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { MAX_DESKTOP_REPLY, takeDesktopBytes } from './desktop-binary-reply.ts';
import type { DesktopOwnerTransport } from './desktop-owner-client.ts';

function unit(value: unknown) {
  if (value !== null) throw Error('invalid_desktop_private_reply');
}

export function createDesktopOwnerTransport(): DesktopOwnerTransport {
  let document: Promise<string> | undefined;
  return Object.freeze({
    async command(name, body, headers) {
      if (name === 'app_lock_bind') {
        document ??= captureDesktopDocument();
        return invoke<unknown>(name, body, { headers: { ...headers, 'X-Morse-Document': await document } });
      }
      return invoke<unknown>(name, body, { headers });
    },
    async listen(receive) {
      const remove = await listen<unknown>('app-lock-changed', event => { receive(event.payload); });
      // The installed Tauri API returns an async function at runtime, even
      // though UnlistenFn's declaration says void. Preserve its completion.
      return async () => { await remove(); };
    },
    privatePort(owner, epoch) {
      const headers = Object.freeze({ 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': epoch });
      return Object.freeze({
        async check() { unit(await invoke<unknown>('app_lock_check', {}, { headers })); },
        async invoke(symbol: string, request: Uint8Array) {
          return takeDesktopBytes(await invoke<unknown>('mesh_invoke', request, { headers: { ...headers, 'X-Mesh-Symbol': symbol } }), symbol === 'mesh_messenger_backup_create' ? 16_801_001 : symbol === 'mesh_messenger_backup_pending_resume' ? 16_796_869 : MAX_DESKTOP_REPLY, 'invalid_desktop_private_reply');
        },
        async invokeWallet(operation: number, request: Uint8Array) {
          if (!Number.isInteger(operation) || operation < 0 || operation > 4294967295) throw Error('invalid_wallet_operation');
          return takeDesktopBytes(await invoke<unknown>('wallet_invoke', request, { headers: { ...headers, 'X-Wallet-Operation': String(operation) } }), MAX_DESKTOP_REPLY, 'invalid_desktop_private_reply');
        },
        async copyProtectedText(text: string) {
          unit(await invoke<unknown>('app_lock_copy_text', { text }, { headers }));
        },
      });
    },
  } satisfies DesktopOwnerTransport);
}
