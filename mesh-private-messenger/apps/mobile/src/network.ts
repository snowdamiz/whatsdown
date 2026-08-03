import {
  authorize_device_link_for_set_export,
  create_device_revocation_export,
  directory_entry_export,
  directory_lookup_export,
  inspect_device_set_export,
  load_profile_export,
  mailbox_fetch_export,
  process_delivery_batch_export,
  send_fanout_export,
} from '../modules/mesh-messenger';
import {
  batchRequest,
  DeviceSetSummary,
  parseByteList,
  parseDeviceSetSummary,
  parseProfileSummary,
  utf8,
  vectors,
} from './codec';

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
  await binaryRequest('/v1/devices/register', entry, 'PUT');
}

export async function resolveDeviceSet(username: string): Promise<Uint8Array> {
  const lookup = await directory_lookup_export(utf8(username));
  return binaryRequest('/v1/devices/resolve', lookup);
}

export async function inspectDeviceSet(
  databasePath: string,
  deviceSet: Uint8Array,
): Promise<DeviceSetSummary> {
  const encoded = await inspect_device_set_export(batchRequest(databasePath, deviceSet));
  return parseDeviceSetSummary(encoded);
}

export async function loadAccountDevices(
  databasePath: string,
  profile: Uint8Array,
): Promise<{ wire: Uint8Array; summary: DeviceSetSummary }> {
  const wire = await resolveDeviceSet(parseProfileSummary(profile).username);
  return { wire, summary: await inspectDeviceSet(databasePath, wire) };
}

export async function authorizeDeviceLink(
  databasePath: string,
  deviceSet: Uint8Array,
  linkRequest: Uint8Array,
): Promise<Uint8Array> {
  return authorize_device_link_for_set_export(
    vectors(utf8(databasePath), deviceSet, linkRequest),
  );
}

export async function revokeDevice(
  databasePath: string,
  deviceSet: Uint8Array,
  deviceId: Uint8Array,
): Promise<void> {
  const revocation = await create_device_revocation_export(
    vectors(utf8(databasePath), deviceSet, deviceId),
  );
  await binaryRequest('/v1/devices/revoke', revocation);
}

export async function submitEnvelope(envelope: Uint8Array): Promise<void> {
  await binaryRequest('/v1/envelopes/batch', envelope);
}

export async function sendFanout(
  databasePath: string,
  peerUsername: string,
  body: string,
): Promise<boolean> {
  const localProfile = await load_profile_export(utf8(databasePath));
  const [peerSet, localSet] = await Promise.all([
    resolveDeviceSet(peerUsername),
    resolveDeviceSet(parseProfileSummary(localProfile).username),
  ]);
  const [peerSummary] = await Promise.all([
    inspectDeviceSet(databasePath, peerSet),
    inspectDeviceSet(databasePath, localSet),
  ]);
  const encoded = await send_fanout_export(
    vectors(utf8(databasePath), peerSet, localSet, utf8(body)),
  );
  const envelopes = parseByteList(encoded, 80, 65_606);
  await Promise.all(envelopes.map(submitEnvelope));
  return peerSummary.changed;
}

export async function synchronizeMailbox(databasePath: string): Promise<void> {
  const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
  const batch = await binaryRequest('/v1/mailbox/fetch', fetchRequest);
  const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
  await binaryRequest('/v1/mailbox/ack', acknowledgement);
}
