import { fetch } from 'expo/fetch';
import {
  authorize_device_link_for_set_export,
  create_device_revocation_export,
  directory_entry_export,
  group_add_export,
  group_create_export,
  group_history_export,
  group_inspect_export,
  group_key_package_export,
  group_list_export,
  group_remove_export,
  group_send_export,
  inspect_device_set_export,
  load_profile_export,
  mailbox_fetch_export,
  outbox_ack_export,
  outbox_list_export,
  privacy_submission_export,
  process_delivery_batch_export,
  prepare_fanout_prekeys_export,
  reconcile_prekeys_export,
  replenish_prekeys_export,
  send_fanout_export,
  transparency_lookup_export,
  verify_transparency_export,
} from '../modules/mesh-messenger';
import {
  batchRequest,
  type DeviceSetSummary,
  type GroupHistoryMessage,
  type GroupDetails,
  type GroupSummary,
  parseByteList,
  parseDeviceSetSummary,
  parseGroupHistory,
  parseGroupDetails,
  parseGroupList,
  parseProfileSummary,
  parsePrekeyCount,
  utf8,
  vectors,
  writeU32,
} from './codec';
import {
  createKeyedSerialQueue,
  createKeyedSingleFlight,
} from './single-flight';

const baseUrl = (process.env.EXPO_PUBLIC_MESSENGER_BASE_URL ?? 'http://127.0.0.1:18086').replace(
  /\/$/,
  '',
);
const synchronizePrekeysByDatabase = createKeyedSingleFlight<string, void>();
const resolveTransparencyByDatabase = createKeyedSerialQueue<string>();
const sendFanoutByDatabase = createKeyedSerialQueue<string>();
export const GROUP_KEY_PACKAGE_LENGTH = 369;

function serviceUrl(value: string): string {
  const url = new URL(value);
  const octets = url.hostname.split('.').map(Number);
  const privateIPv4 = octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) &&
    (octets[0] === 127 || octets[0] === 10 ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31));
  const local = url.hostname === 'localhost' || url.hostname === '[::1]' || privateIPv4;
  const developmentHttp = typeof __DEV__ !== 'undefined' && __DEV__ && local && url.protocol === 'http:';
  if ((url.protocol !== 'https:' && !developmentHttp) || url.username || url.password || url.search || url.hash) {
    throw new Error('Messenger services require HTTPS; local HTTP is allowed only in development builds');
  }
  return url.toString().replace(/\/$/, '');
}

async function binaryRequest(
  path: string,
  body: Uint8Array,
  method = 'POST',
  root = baseUrl,
): Promise<Uint8Array> {
  const url = `${serviceUrl(root)}${path}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  const payload = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
  try {
    const response = await fetch(url, {
      method,
      redirect: 'error',
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

export async function submitPushBind(wire: Uint8Array): Promise<void> {
  if (wire.length === 0) throw new Error('Push bind wire must not be empty');
  await binaryRequest('/v1/push/bind', wire, 'PUT');
}

export async function submitPushUnbind(wire: Uint8Array): Promise<void> {
  if (wire.length === 0) throw new Error('Push unbind wire must not be empty');
  await binaryRequest('/v1/push/unbind', wire);
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
  return resolveTransparencyByDatabase(databasePath, async () => {
    const lookup = await transparency_lookup_export(
      batchRequest(databasePath, utf8(username)),
    );
    const evidence = await binaryRequest('/v1/devices/resolve', lookup);
    return verify_transparency_export(
      vectors(utf8(databasePath), utf8(username), evidence),
    );
  });
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
  const root = serviceUrl(edgeUrl);
  const submission = await privacy_submission_export(envelope);
  await binaryRequest('/v1/envelopes/batch', submission, 'POST', root);
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

export async function listGroups(databasePath: string): Promise<GroupSummary[]> {
  return parseGroupList(await group_list_export(utf8(databasePath)));
}

export async function createGroup(databasePath: string): Promise<Uint8Array> {
  const groupId = await group_create_export(utf8(databasePath));
  if (groupId.length !== 32) throw new Error('Mesh returned an invalid group ID');
  return groupId;
}

export async function getGroupKeyPackage(databasePath: string): Promise<Uint8Array> {
  const keyPackage = await group_key_package_export(utf8(databasePath));
  if (keyPackage.length !== GROUP_KEY_PACKAGE_LENGTH) {
    throw new Error('Mesh returned an invalid group key package');
  }
  return keyPackage;
}

export async function loadGroupHistory(
  databasePath: string,
  groupId: Uint8Array,
): Promise<GroupHistoryMessage[]> {
  return parseGroupHistory(await group_history_export(vectors(utf8(databasePath), groupId)));
}

export async function inspectGroup(
  databasePath: string,
  groupId: Uint8Array,
): Promise<GroupDetails> {
  return parseGroupDetails(await group_inspect_export(vectors(utf8(databasePath), groupId)));
}

export async function addGroupMember(
  databasePath: string,
  groupId: Uint8Array,
  username: string,
  keyPackage: Uint8Array,
): Promise<void> {
  const deviceSet = await resolveDeviceSet(databasePath, username);
  await group_add_export(vectors(utf8(databasePath), groupId, deviceSet, keyPackage));
  await drainOutbox(databasePath);
}

export async function sendGroupMessage(
  databasePath: string,
  groupId: Uint8Array,
  body: string,
): Promise<void> {
  await group_send_export(vectors(utf8(databasePath), groupId, utf8(body)));
  await drainOutbox(databasePath);
}

export async function removeGroupMember(
  databasePath: string,
  groupId: Uint8Array,
  accountId: Uint8Array,
  deviceId: Uint8Array,
): Promise<void> {
  await group_remove_export(vectors(utf8(databasePath), groupId, accountId, deviceId));
  await drainOutbox(databasePath);
}

export function sendFanout(
  databasePath: string,
  peerUsername: string,
  body: string,
): Promise<boolean> {
  return sendFanoutByDatabase(databasePath, async () => {
    const localProfile = await load_profile_export(utf8(databasePath));
    const peerSet = await resolveDeviceSet(databasePath, peerUsername);
    const localSet = await resolveDeviceSet(
      databasePath,
      parseProfileSummary(localProfile).username,
    );
    const peerSummary = await inspectDeviceSet(databasePath, peerSet);
    await inspectDeviceSet(databasePath, localSet);
    await prepare_fanout_prekeys_export(
      vectors(utf8(databasePath), peerSet, localSet, utf8(serviceUrl(baseUrl))),
    );
    await send_fanout_export(
      vectors(
        utf8(databasePath),
        peerSet,
        localSet,
        utf8(body),
      ),
    );
    await drainOutbox(databasePath);
    return peerSummary.changed;
  });
}

export async function synchronizeMailbox(databasePath: string): Promise<void> {
  await drainOutbox(databasePath);
  const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
  const batch = await binaryRequest('/v1/mailbox/fetch', fetchRequest);
  const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
  if (acknowledgement.length > 0) await binaryRequest('/v1/mailbox/ack', acknowledgement);
  await synchronizePrekeys(databasePath);
}
