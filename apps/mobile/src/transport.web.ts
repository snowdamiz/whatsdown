import { Channel, invoke } from '@tauri-apps/api/core';
import type { MailboxSocket } from './mailbox-sync';

let nextSocketId = 0;
export const isDevelopmentBuild = (): boolean => process.env.EXPO_PUBLIC_DESKTOP_DEVELOPMENT === 'true';

// The host answers with the HTTP status as two big-endian bytes, then the body.
export async function fetch(url: string, options: RequestInit): Promise<Response> {
  const headers: Record<string, string> = { 'X-Service-Url': url, 'X-Service-Method': options.method ?? 'GET' };
  const capability = new Headers(options.headers).get('X-Object-Capability');
  if (capability) headers['X-Object-Capability'] = capability;
  const body = options.body instanceof ArrayBuffer ? new Uint8Array(options.body) : new Uint8Array(0);
  const framed = new Uint8Array(await invoke<ArrayBuffer>('binary_request', body, { headers })
    .catch((error) => { throw new Error(String(error)); }));
  if (framed.length < 2) throw new Error('invalid_service_response');
  const status = (framed[0]! << 8) | framed[1]!;
  return new Response(framed.length > 2 ? framed.subarray(2) : null, { status });
}

export async function openMailboxSocket(_url: string, authorization: string): Promise<MailboxSocket> {
  const id = ++nextSocketId;
  let closed = false;
  let attached = false;
  const pending: string[] = [];
  const socket: MailboxSocket = {
    onmessage: null, onerror: null, onclose: null,
    close() {
      closed = true;
      pending.length = 0;
      void invoke('mailbox_disconnect', { id }).catch(() => {});
    },
  };
  const events = new Channel<string>();
  events.onmessage = (data) => {
    if (closed) return;
    if (!attached) { pending.push(data); return; }
    if (data === 'error') socket.onerror?.call(socket as WebSocket, new Event('error'));
    else if (data === 'closed') socket.onclose?.call(socket as WebSocket, new CloseEvent('close'));
    else socket.onmessage?.call(socket as WebSocket, new MessageEvent('message', { data }));
  };
  await invoke('mailbox_connect', { id, authorization, events });
  // IPC may deliver readiness before the caller resumes and installs listeners.
  setTimeout(() => {
    attached = true;
    pending.splice(0).forEach(events.onmessage);
  }, 0);
  return socket;
}
