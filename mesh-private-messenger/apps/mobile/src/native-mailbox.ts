import { decodeUtf8, utf8, vectors, writeU32 } from './codec.ts';
import type { MailboxSocket } from './mailbox-sync.ts';

export type NativeMailboxBridge = {
  open(request: Uint8Array): Promise<Uint8Array>;
  poll(request: Uint8Array): Promise<Uint8Array>;
  close(request: Uint8Array): Promise<Uint8Array>;
};

// Polling here reads bounded native wakeups. The socket, signed authorization,
// URL, queue and account/configuration fences remain inside Mesh.
export async function openNativeMailboxSocket(database: string, bridge: NativeMailboxBridge): Promise<MailboxSocket> {
  const ticket = await bridge.open(utf8(database));
  if (ticket.length !== 32) throw new Error('invalid_mailbox_stream_ticket');
  const request = new Uint8Array([...writeU32(2), ...vectors(utf8(database), ticket)]);
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const socket: MailboxSocket = {
    onmessage: null, onerror: null, onclose: null,
    close() {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      void bridge.close(request).catch(() => {});
    },
  };
  async function poll() {
    if (closed) return;
    try {
      const wire = await bridge.poll(request);
      if (closed) return;
      if (wire.length > 32) throw new Error('invalid_mailbox_stream_event');
      const event = decodeUtf8(wire);
      if (event !== '' && event !== 'ready' && event !== 'encrypted-wakeup') {
        throw new Error('invalid_mailbox_stream_event');
      }
      if (event) socket.onmessage?.call(socket as WebSocket, { data: event } as MessageEvent);
      if (!closed) timer = setTimeout(() => void poll(), event ? 0 : 250);
    } catch {
      if (closed) return;
      socket.close();
      socket.onerror?.call(socket as WebSocket, new Event('error'));
    }
  }
  // Let createMailboxSync install listeners before delivering native readiness.
  timer = setTimeout(() => void poll(), 0);
  return socket;
}
