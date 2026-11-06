import { invoke } from '@tauri-apps/api/core';
import { takeDesktopBytes } from './desktop-binary-reply.ts';
import type { DesktopOwner, DesktopEpoch } from './desktop-lock-protocol.ts';
import type { DesktopPrivateSession } from './desktop-private-session.ts';
import type { NativeMailboxBridge } from './native-mailbox.ts';

function closeTicketFromRequest(request: Uint8Array): Uint8Array {
  if (request.length < 45 || request.length > 16_428) throw Error('invalid_mailbox_stream_request');
  const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
  const databaseLength = view.getUint32(4, false);
  if (view.getUint32(0, false) !== 2 || databaseLength < 1 || databaseLength > 16_384 ||
      databaseLength + 44 !== request.length || view.getUint32(8 + databaseLength, false) !== 32) {
    throw Error('invalid_mailbox_stream_request');
  }
  return request.slice(12 + databaseLength);
}

export function createDesktopMailboxPort({ owner, epoch, scope }: {
  owner: DesktopOwner; epoch: DesktopEpoch;
  scope: Pick<DesktopPrivateSession, 'runPrivate' | 'assertCurrent'>;
}): NativeMailboxBridge {
  const headers = Object.freeze({ 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': epoch });
  async function release(ticket: Uint8Array) {
    const reply = await invoke<unknown>('app_lock_close_mailbox', ticket, { headers });
    if (reply !== null) throw Error('invalid_desktop_private_reply');
  }
  async function call(symbol: string, request: Uint8Array) {
    return takeDesktopBytes(await invoke<unknown>('mesh_invoke', request,
      { headers: { ...headers, 'X-Mesh-Symbol': symbol } }), 32, 'invalid_mailbox_stream_reply');
  }
  return Object.freeze({
    async open(request: Uint8Array) {
      scope.assertCurrent();
      const held = request.slice();
      let ticket: Uint8Array | undefined;
      try {
        // Keep cleanup identity outside the generic byte-result wipe until
        // the original scope admits the newly created native stream.
        const result = await scope.runPrivate(async () => {
          ticket = await call('mesh_messenger_mailbox_stream_open', held);
          if (ticket.length !== 32) throw Error('invalid_mailbox_stream_ticket');
          return { ticket };
        });
        scope.assertCurrent();
        return result.ticket;
      } catch (error) {
        if (ticket?.length === 32) {
          try { await release(ticket); } catch { /* Preserve the original refusal. */ }
        }
        ticket?.fill(0);
        scope.assertCurrent();
        throw error;
      } finally { held.fill(0); }
    },
    async poll(request: Uint8Array) {
      scope.assertCurrent();
      const held = request.slice();
      let result: Uint8Array | undefined;
      try {
        result = await scope.runPrivate(() => call('mesh_messenger_mailbox_stream_poll', held));
        scope.assertCurrent();
        return result;
      } catch (error) { result?.fill(0); scope.assertCurrent(); throw error; }
      finally { held.fill(0); }
    },
    async close(request: Uint8Array) {
      // This finite cleanup remains valid after local disposal. Native checks
      // the original page/epoch registry and derives its own DB/job from ticket.
      const ticket = closeTicketFromRequest(request);
      try { await release(ticket); return new Uint8Array(); }
      finally { ticket.fill(0); }
    },
  });
}
