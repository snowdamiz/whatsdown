import {
  authorize_device_link_for_set_export,
  create_device_revocation_export,
  directory_entry_export,
  inspect_device_set_export,
  load_profile_export,
  mailbox_fetch_export,
  outbox_ack_export,
  outbox_list_export,
  privacy_submission_export,
  process_delivery_batch_export,
  reconcile_prekeys_export,
  replenish_prekeys_export,
  send_fanout_export,
  transparency_lookup_export,
  verify_transparency_export,
} from '../modules/mesh-messenger';
import {
  batchRequest,
  boundedInteger,
  DeviceSetSummary,
  hexBytes,
  parseByteList,
  parseDeviceSetSummary,
  parseProfileSummary,
  parsePrekeyCount,
  utf8,
  vectors,
  writeU32,
} from './codec';
import { createKeyedSingleFlight } from './single-flight';

const baseUrl = (process.env.EXPO_PUBLIC_MESSENGER_BASE_URL ?? 'http://127.0.0.1:18086').replace(
  /\/$/,
  '',
);
const synchronizePrekeysByDatabase = createKeyedSingleFlight<string, void>();

async function binaryRequest(
  path: string,
  body: Uint8Array,
  method = 'POST',
  root = baseUrl,
): Promise<Uint8Array> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  const payload = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
  try {
    const response = await fetch(`${root}${path}`, {
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
  await synchronizePrekeys(databasePath);
}

async function publishPrekeys(databasePath: string, count: number): Promise<number> {
  const publication = await replenish_prekeys_export(
    batchRequest(databasePath, writeU32(count)),
  );
  const acknowledgement = await binaryRequest('/v1/prekeys/one-time/batch', publication);
  return parsePrekeyCount(
    await reconcile_prekeys_export(vectors(utf8(databasePath), acknowledgement)),
  );
}

async function synchronizePrekeysOnce(databasePath: string): Promise<void> {
  const active = await publishPrekeys(databasePath, 0);
  if (active < 64 && (await publishPrekeys(databasePath, 64 - active)) !== 64) {
    throw new Error('Server did not accept the complete prekey refill');
  }
}

export function synchronizePrekeys(databasePath: string): Promise<void> {
  return synchronizePrekeysByDatabase(databasePath, () => synchronizePrekeysOnce(databasePath));
}

export async function resolveDeviceSet(
  databasePath: string,
  username: string,
): Promise<Uint8Array> {
  const lookup = await transparency_lookup_export(batchRequest(databasePath, utf8(username)));
  const evidence = await binaryRequest('/v1/devices/resolve', lookup);
  return verify_transparency_export(
    vectors(
      utf8(databasePath),
      utf8(username),
      evidence,
      hexBytes(process.env.EXPO_PUBLIC_MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX, 32),
      hexBytes(process.env.EXPO_PUBLIC_MESSENGER_WITNESS_A_PUBLIC_KEY_HEX, 32),
      hexBytes(process.env.EXPO_PUBLIC_MESSENGER_WITNESS_B_PUBLIC_KEY_HEX, 32),
    ),
  );
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
  const wire = await resolveDeviceSet(databasePath, parseProfileSummary(profile).username);
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
  const edgeUrl = process.env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL?.replace(/\/$/, '');
  if (!edgeUrl) throw new Error('EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL is required');
  const submission = await privacy_submission_export(
    vectors(
      envelope,
      hexBytes(process.env.EXPO_PUBLIC_MESSENGER_DELIVERY_PUBLIC_KEY_HEX, 32),
      Uint8Array.of(
        boundedInteger(process.env.EXPO_PUBLIC_MESSENGER_ABUSE_DIFFICULTY, 16, 1, 24),
      ),
    ),
  );
  await binaryRequest('/v1/envelopes/batch', submission, 'POST', edgeUrl);
}

export async function drainOutbox(databasePath: string): Promise<void> {
  for (;;) {
    const envelopes = parseByteList(await outbox_list_export(utf8(databasePath)), 8, 65_606);
    if (envelopes.length === 0) return;
    for (const envelope of envelopes) {
      await submitEnvelope(envelope);
      await outbox_ack_export(batchRequest(databasePath, envelope));
    }
  }
}

export async function sendFanout(
  databasePath: string,
  peerUsername: string,
  body: string,
): Promise<boolean> {
  const localProfile = await load_profile_export(utf8(databasePath));
  const [peerSet, localSet] = await Promise.all([
    resolveDeviceSet(databasePath, peerUsername),
    resolveDeviceSet(databasePath, parseProfileSummary(localProfile).username),
  ]);
  const [peerSummary] = await Promise.all([
    inspectDeviceSet(databasePath, peerSet),
    inspectDeviceSet(databasePath, localSet),
  ]);
  await send_fanout_export(
    vectors(utf8(databasePath), peerSet, localSet, utf8(body)),
  );
  await drainOutbox(databasePath);
  return peerSummary.changed;
}

export async function synchronizeMailbox(databasePath: string): Promise<void> {
  await drainOutbox(databasePath);
  const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
  const batch = await binaryRequest('/v1/mailbox/fetch', fetchRequest);
  const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
  await binaryRequest('/v1/mailbox/ack', acknowledgement);
  await synchronizePrekeys(databasePath);
}
