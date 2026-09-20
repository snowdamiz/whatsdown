import { attachmentSelectionError } from './attachments.ts';
import { fetch, openMailboxSocket, isDevelopmentBuild } from './transport';
import type { MailboxSocket } from './mailbox-sync';
import {
  attachment_open_chunk_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
  authorize_device_link_for_set_export,
  create_device_revocation_export,
  register_request_export,
  group_add_export,
  group_create_export,
  group_history_export,
  group_inspect_export,
  group_key_package_export,
  group_invite_export,
  group_invitation_accept_export,
  group_invitation_complete_export,
  group_invitation_decline_export,
  group_invitations_export,
  group_list_export,
  group_remove_export,
  group_send_export,
  inspect_device_set_export,
  load_profile_export,
  mailbox_fetch_export,
  outbox_ack_export,
  outbox_fail_export,
  outbox_page_export,
  privacy_submission_export,
  process_delivery_batch_export,
  prepare_fanout_prekeys_export,
  reconcile_prekeys_export,
  replenish_prekeys_export,
  send_fanout_export,
  resolve_request_export,
  verify_transparency_export,
} from '../modules/mesh-messenger';
import {
  ATTACHMENT_CHUNK_SIZE,
  encodeAttachmentReferences,
  envelopeExpiresAt,
  envelopeQueuedAt,
  type AttachmentSummary,
  batchRequest,
  hex,
  type DeviceSetSummary,
  type GroupHistoryMessage,
  type GroupDetails,
  type GroupSummary,
  type GroupInvitation,
  parseByteList,
  parseDeviceSetSummary,
  parseGroupHistory,
  parseGroupDetails,
  parseGroupList,
  parseGroupInvitations,
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
// Encrypted attachment parts live in the object store, which production serves from the messenger origin.
const objectUrl = (process.env.EXPO_PUBLIC_MESSENGER_OBJECT_URL || baseUrl).replace(/\/$/, '');
const synchronizePrekeysByDatabase = createKeyedSingleFlight<string, void>();
const synchronizeMailboxByDatabase = createKeyedSingleFlight<string, void>();
const drainOutboxByDatabase = createKeyedSingleFlight<string, void>();
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
  const developmentHttp = isDevelopmentBuild() && local && url.protocol === 'http:';
  if ((url.protocol !== 'https:' && !developmentHttp) || url.username || url.password || url.search || url.hash) {
    throw new Error('Messenger services require HTTPS; local HTTP is allowed only in development builds');
  }
  return url.toString().replace(/\/$/, '');
}

class ServerStatusError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`Server returned ${status}`);
    this.status = status;
  }
}

async function binaryRequest(
  path: string,
  body: Uint8Array,
  method = 'POST',
  root = baseUrl,
  headers: Record<string, string> = {},
): Promise<Uint8Array> {
  const url = `${serviceUrl(root)}${path}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  const payload = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
  try {
    const response = await fetch(url, {
      method,
      redirect: 'error',
      headers: { 'Content-Type': 'application/octet-stream', ...headers },
      ...(method === 'GET' ? {} : { body: payload }),
      signal: controller.signal,
    });
    // A full pool still returns its active IDs for native identity/key validation.
    const prekeyRecovery = path === '/v1/prekeys/one-time/batch' && response.status === 429;
    if (!response.ok && !prekeyRecovery) throw new ServerStatusError(response.status);
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
  // Anonymous directory requests leave Mesh already wrapped in proof of work.
  const entry = await register_request_export(utf8(databasePath));
  await binaryRequest('/v1/devices/register', entry, 'PUT');
  await synchronizePrekeys(databasePath);
}

export async function connectMailboxStream(databasePath: string): Promise<MailboxSocket> {
  const configured = process.env.EXPO_PUBLIC_MESSENGER_STREAM_URL ?? `${baseUrl}/v1/mailbox/stream`;
  const url = serviceUrl(configured.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:'))
    .replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
  await registerDirectory(databasePath);
  const request = await mailbox_fetch_export(utf8(databasePath));
  return openMailboxSocket(url, `MeshMailbox ${hex(request)}`);
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
    const lookup = await resolve_request_export(
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

// An envelope the service will never accept is removed so it cannot hold up the
// queue, and reported so it does not vanish without the person knowing.
export type Undeliverable = { status: number; queuedAt: number };
const undeliverableListeners = new Set<(report: Undeliverable) => void>();

export function onUndeliverable(listener: (report: Undeliverable) => void): () => void {
  undeliverableListeners.add(listener);
  return () => { undeliverableListeners.delete(listener); };
}

// The service will never accept this envelope: its mailbox was revoked (410), or
// it expired while it waited, which explains a 400. Any other refusal may be
// about this build or this clock rather than this envelope, so it waits like a
// transient failure: discarding on it could empty the outbox for good.
function undeliverable(error: unknown, envelope: Uint8Array): Undeliverable | null {
  if (!(error instanceof ServerStatusError)) return null;
  const permanent = error.status === 410 || (error.status === 400 && Date.now() >= envelopeExpiresAt(envelope));
  return permanent ? { status: error.status, queuedAt: envelopeQueuedAt(envelope) } : null;
}

// Bytes 20..52 of an envelope are the mailbox it is addressed to.
const mailboxOf = (envelope: Uint8Array): string => hex(envelope.subarray(20, 52));

// Envelopes leave in the order they were queued, with two exceptions that never
// let one overtake another for the same recipient. One the service will never
// accept is refused in the core, which marks its message as not delivered. One
// the service cannot take right now (429: that mailbox is full, or being sent
// to too fast) stays queued, along with everything behind it for that mailbox,
// while other recipients carry on. Anything else stops the pass.
async function drainOutboxOnce(databasePath: string): Promise<void> {
  const waiting = new Set<string>();
  let kept = 0; // Envelopes left queued ahead of the next page.
  let turnedAway: unknown;
  for (;;) {
    const page = await outbox_page_export(batchRequest(databasePath, writeU32(kept)));
    const envelopes = parseByteList(page, 8, 65_606);
    if (envelopes.length === 0) break;
    for (const envelope of envelopes) {
      const mailbox = mailboxOf(envelope);
      if (waiting.has(mailbox)) {
        kept += 1;
        continue;
      }
      try {
        await submitEnvelope(envelope);
      } catch (error) {
        const report = undeliverable(error, envelope);
        if (report) {
          await outbox_fail_export(batchRequest(databasePath, envelope));
          for (const listener of undeliverableListeners) {
            // A listener that throws must not stall the outbox.
            try { listener(report); } catch { /* Reporting is best effort. */ }
          }
          continue;
        }
        if (!(error instanceof ServerStatusError) || error.status !== 429) throw error;
        waiting.add(mailbox);
        kept += 1;
        turnedAway = error;
        continue;
      }
      await outbox_ack_export(batchRequest(databasePath, envelope));
    }
  }
  // Something is still queued, so say so: callers retry later, as they always have.
  if (turnedAway) throw new Error('recipient_unavailable', { cause: turnedAway });
}

export function drainOutbox(databasePath: string): Promise<void> {
  return drainOutboxByDatabase(databasePath, () => drainOutboxOnce(databasePath));
}

export async function listGroups(databasePath: string): Promise<GroupSummary[]> {
  return parseGroupList(await group_list_export(utf8(databasePath)));
}

export async function createGroup(databasePath: string): Promise<Uint8Array> {
  const profile = parseProfileSummary(await load_profile_export(utf8(databasePath)));
  await resolveDeviceSet(databasePath, profile.username);
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

async function refreshGroupAuthorizations(
  databasePath: string,
  groupId: Uint8Array,
  removed?: { accountId: Uint8Array; deviceId: Uint8Array },
): Promise<void> {
  const group = await inspectGroup(databasePath, groupId);
  const members = group.members.filter(member => !removed || hex(member.accountId) !== hex(removed.accountId) || hex(member.deviceId) !== hex(removed.deviceId));
  for (const accountId of new Set(members.map(member => hex(member.accountId)))) {
    await resolveDeviceSet(databasePath, `@${accountId}`);
  }
}

export async function addGroupMember(
  databasePath: string,
  groupId: Uint8Array,
  username: string,
  keyPackage: Uint8Array,
): Promise<void> {
  const deviceSet = await resolveDeviceSet(databasePath, username);
  await refreshGroupAuthorizations(databasePath, groupId);
  await group_add_export(vectors(utf8(databasePath), groupId, deviceSet, keyPackage));
  await drainOutbox(databasePath);
}

export async function sendGroupMessage(
  databasePath: string,
  groupId: Uint8Array,
  body: string,
  attachment?: Uint8Array,
): Promise<void> {
  await refreshGroupAuthorizations(databasePath, groupId);
  await group_send_export(vectors(utf8(databasePath), groupId, utf8(body), ...(attachment ? [attachment] : [])));
  await drainOutbox(databasePath);
}

export type OutgoingAttachment = {
  filename: string;
  mimeType: string;
  bytes: Uint8Array;
};

export type UploadedAttachment = {
  // Opaque local reference: it travels in the message and unlocks the chunks on this device.
  reference: Uint8Array;
  // The stored object, as history will later name it.
  objectId: Uint8Array;
  // Removes the object again when the message it belongs to never leaves.
  discard: () => Promise<void>;
};

export type TransferProgress = (completed: number, total: number) => void;

// Every object grant carries a proof of work at the service's configured difficulty.
function objectWorkDifficulty(): number {
  const configured = process.env.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY || '16';
  const value = Number(configured);
  if (!/^\d+$/.test(configured) || value < 1 || value > 24) {
    throw new Error('EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY must be between 1 and 24');
  }
  return value;
}

const objectRequest = (path: string, body: Uint8Array, method = 'POST', capability?: Uint8Array): Promise<Uint8Array> =>
  binaryRequest(path, body, method, objectUrl, capability ? { 'X-Object-Capability': hex(capability) } : {});

export function describeAttachmentLimit(size: number): string | undefined {
  return attachmentSelectionError([size]);
}

// Encrypts and uploads one file: the sealed manifest is part 0 and each 64 KiB
// chunk follows. The object is completed only once every part is stored.
export async function uploadAttachment(
  databasePath: string,
  file: OutgoingAttachment,
  onProgress?: TransferProgress,
): Promise<UploadedAttachment> {
  const limit = describeAttachmentLimit(file.bytes.length);
  if (limit) throw new Error(limit);
  const [reference, objectId, uploadCapability, grant, complete, remove, manifest] = parseByteList(
    await attachment_prepare_export(vectors(
      utf8(databasePath), utf8(file.filename), utf8(file.mimeType), writeU32(file.bytes.length), writeU32(objectWorkDifficulty()),
    )),
    7,
    1_024,
  );
  if (!reference || !objectId || !uploadCapability || !grant || !complete || !remove || !manifest ||
    objectId.length !== 32 || uploadCapability.length !== 32) {
    throw new Error('Mesh returned an invalid attachment');
  }
  const discard = async (): Promise<void> => { await objectRequest('/v1/attachments/delete', remove); };
  const parts = `/v1/objects/${hex(objectId)}/parts/`;
  const chunkCount = Math.ceil(file.bytes.length / ATTACHMENT_CHUNK_SIZE);
  await objectRequest('/v1/attachments/grant', grant);
  try {
    await objectRequest(`${parts}0`, manifest, 'PUT', uploadCapability);
    for (let index = 0; index < chunkCount; index += 1) {
      const chunk = file.bytes.subarray(index * ATTACHMENT_CHUNK_SIZE, (index + 1) * ATTACHMENT_CHUNK_SIZE);
      const sealed = await attachment_seal_chunk_export(vectors(utf8(databasePath), reference, writeU32(index), chunk));
      await objectRequest(`${parts}${index + 1}`, sealed, 'PUT', uploadCapability);
      onProgress?.(index + 1, chunkCount);
    }
    await objectRequest('/v1/attachments/complete', complete);
  } catch (error) {
    await discard().catch(() => {});
    throw error;
  }
  return { reference, objectId, discard };
}

// Upload the whole selection before creating one message. Failed uploads can be
// removed; a failed send may already be in the durable outbox, so keep its objects.
export async function sendWithAttachments(
  databasePath: string,
  files: OutgoingAttachment[],
  send: (reference?: Uint8Array) => Promise<void>,
  onProgress?: TransferProgress,
): Promise<UploadedAttachment[]> {
  const error = attachmentSelectionError(files.map((file) => file.bytes.length));
  if (error) throw new Error(error);
  const uploaded: UploadedAttachment[] = [];
  try {
    for (const file of files) {
      uploaded.push(await uploadAttachment(databasePath, file, (completed, total) =>
        onProgress?.(uploaded.length + completed / total, files.length)));
    }
  } catch (error) {
    await Promise.allSettled(uploaded.map((file) => file.discard()));
    throw error;
  }
  await send(uploaded.length ? encodeAttachmentReferences(uploaded.map((file) => file.reference)) : undefined);
  return uploaded;
}

// Fetches and decrypts every chunk of a received attachment into one buffer.
export async function downloadAttachment(
  databasePath: string,
  attachment: AttachmentSummary,
  onProgress?: TransferProgress,
): Promise<Uint8Array> {
  const output = new Uint8Array(attachment.size);
  const parts = `/v1/objects/${hex(attachment.objectId)}/parts/`;
  let offset = 0;
  for (let index = 0; index < attachment.chunkCount; index += 1) {
    const sealed = await objectRequest(`${parts}${index + 1}`, new Uint8Array(), 'GET', attachment.downloadCapability);
    const chunk = await attachment_open_chunk_export(vectors(utf8(databasePath), attachment.reference, writeU32(index), sealed));
    if (offset + chunk.length > output.length) throw new Error('The attachment does not match its manifest');
    output.set(chunk, offset);
    offset += chunk.length;
    onProgress?.(index + 1, attachment.chunkCount);
  }
  if (offset !== output.length) throw new Error('The attachment does not match its manifest');
  return output;
}

export async function removeGroupMember(
  databasePath: string,
  groupId: Uint8Array,
  accountId: Uint8Array,
  deviceId: Uint8Array,
): Promise<void> {
  await refreshGroupAuthorizations(databasePath, groupId, { accountId, deviceId });
  await group_remove_export(vectors(utf8(databasePath), groupId, accountId, deviceId));
  await drainOutbox(databasePath);
}

function sendWithDevices(
  databasePath: string,
  peerUsername: string,
  body: Uint8Array,
  send: (request: Uint8Array) => Promise<Uint8Array>,
  expectedAccountId?: Uint8Array,
  attachment?: Uint8Array,
): Promise<boolean> {
  return sendFanoutByDatabase(databasePath, async () => {
    const localProfile = await load_profile_export(utf8(databasePath));
    const peerSet = await resolveDeviceSet(databasePath, peerUsername);
    const localSet = await resolveDeviceSet(
      databasePath,
      parseProfileSummary(localProfile).username,
    );
    const peerSummary = await inspectDeviceSet(databasePath, peerSet);
    if (expectedAccountId && (expectedAccountId.length !== 32 ||
      expectedAccountId.some((byte, index) => byte !== peerSummary.accountId[index]))) {
      throw new Error('The contact identity changed. Verify the contact before sending.');
    }
    await inspectDeviceSet(databasePath, localSet);
    await prepare_fanout_prekeys_export(
      vectors(utf8(databasePath), peerSet, localSet, utf8(serviceUrl(baseUrl))),
    );
    await send(
      vectors(
        utf8(databasePath),
        peerSet,
        localSet,
        body,
        ...(attachment ? [attachment] : []),
      ),
    );
    await drainOutbox(databasePath);
    return peerSummary.changed;
  });
}

export function sendFanout(
  databasePath: string,
  username: string,
  body: string,
  expectedAccountId?: Uint8Array,
  attachment?: Uint8Array,
): Promise<boolean> {
  return sendWithDevices(databasePath, username, utf8(body), send_fanout_export, expectedAccountId, attachment);
}

export function inviteToGroup(databasePath: string, groupId: Uint8Array, username: string): Promise<boolean> {
  return sendWithDevices(databasePath, username, groupId, group_invite_export);
}

export function acceptGroupInvitation(databasePath: string, invitation: GroupInvitation): Promise<boolean> {
  return sendWithDevices(databasePath, invitation.username, invitation.reference, group_invitation_accept_export, invitation.accountId);
}

export async function declineGroupInvitation(databasePath: string, reference: Uint8Array): Promise<void> {
  await group_invitation_decline_export(vectors(utf8(databasePath), reference));
}

export async function listGroupInvitations(databasePath: string): Promise<GroupInvitation[]> {
  return parseGroupInvitations(await group_invitations_export(utf8(databasePath)));
}

export function completeGroupInvitations(databasePath: string): Promise<void> {
  return sendFanoutByDatabase(databasePath, async () => {
    const invitations = await listGroupInvitations(databasePath);
    const failures: unknown[] = [];
    for (const invitation of invitations.filter((item) => item.state === 3)) {
      try {
        const devices = await resolveDeviceSet(databasePath, invitation.username);
        await group_invitation_complete_export(vectors(utf8(databasePath), devices, invitation.reference));
      } catch (error) {
        failures.push(error);
      }
    }
    await drainOutbox(databasePath);
    if (failures.length) throw failures[0];
  });
}

// The service hands over the oldest unacknowledged envelopes first, and Mesh
// leaves one it cannot open yet unacknowledged. Mesh therefore asks past what it
// has set aside, and a pass runs until the mailbox has nothing more behind it;
// stopping at the first batch it could not finish would let a few such
// envelopes, which anyone can send, be all this device ever receives.
async function receiveMailbox(databasePath: string): Promise<void> {
  let setAside = false;
  let asked: string | undefined;
  // 1,024 batches is twice what the largest mailbox holds.
  for (let batches = 0; batches < 1_024; batches += 1) {
    const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
    const batch = await binaryRequest('/v1/mailbox/fetch', fetchRequest);
    const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
    if (acknowledgement.length > 0) await binaryRequest('/v1/mailbox/ack', acknowledgement);
    // Mesh has validated both frames: byte 4 of a BAT is its delivery count,
    // byte 44 of an ACK how many of them Mesh is done with.
    const delivered = batch[4] ?? 0;
    if (delivered === 0) break;
    if ((acknowledgement[44] ?? 0) < delivered) setAside = true;
    // Bytes 36..44 of a FET are where it asks from. Nothing taken and the same
    // place asked again means Mesh is not getting past them: try again later.
    const position = hex(fetchRequest.subarray(36, 44));
    if (acknowledgement.length === 0 && position === asked) break;
    asked = position;
  }
  if (setAside) throw new Error('Message processing is pending. Retrying…');
}

export function synchronizeMailbox(databasePath: string): Promise<void> {
  return synchronizeMailboxByDatabase(databasePath, async () => {
    // A failed submission must not prevent receiving already-delivered messages.
    const results = await Promise.allSettled([
      receiveMailbox(databasePath), drainOutbox(databasePath), synchronizePrekeys(databasePath),
    ]);
    results.push(...await Promise.allSettled([completeGroupInvitations(databasePath)]));
    const failure = results.find((result) => result.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
  });
}
