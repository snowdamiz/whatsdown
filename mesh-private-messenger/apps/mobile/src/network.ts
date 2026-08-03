import {
  directory_entry_export,
  directory_lookup_export,
  import_contact_export,
  mailbox_fetch_export,
  process_delivery_batch_export,
} from '../modules/mesh-messenger';
import { batchRequest, utf8 } from './codec';

const baseUrl = (process.env.EXPO_PUBLIC_MESSENGER_BASE_URL ?? 'http://127.0.0.1:18086').replace(
  /\/$/,
  '',
);

async function binaryRequest(path: string, body: Uint8Array, method = 'POST'): Promise<Uint8Array> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  const payload = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: { 'Content-Type': 'application/octet-stream' },
      body: payload,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Server returned ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  } finally {
    clearTimeout(timeout);
  }
}

export async function registerDirectory(databasePath: string): Promise<void> {
  const entry = await directory_entry_export(utf8(databasePath));
  await binaryRequest('/v1/directory/register', entry, 'PUT');
}

export async function resolveContact(username: string): Promise<Uint8Array> {
  const lookup = await directory_lookup_export(utf8(username));
  const entry = await binaryRequest('/v1/directory/resolve', lookup);
  return import_contact_export(entry);
}

export async function submitEnvelope(envelope: Uint8Array): Promise<void> {
  await binaryRequest('/v1/envelopes/batch', envelope);
}

export async function synchronizeMailbox(databasePath: string): Promise<void> {
  const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
  const batch = await binaryRequest('/v1/mailbox/fetch', fetchRequest);
  const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
  await binaryRequest('/v1/mailbox/ack', acknowledgement);
}
