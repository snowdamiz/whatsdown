import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import { attachmentSelectionError } from './attachments.ts';
import { t } from './i18n.ts';
import { nativeFanoutRequest, parseNativeFanoutStatus, type FanoutKind } from './native-fanout.ts';
import { openNativeMailboxSocket } from './native-mailbox.ts';
import { runPrivateOwned } from './private-resource.ts';
import { synchronizeNativeMailbox } from './native-mailbox-sync.ts';
import { registerNativeDirectory, synchronizeNativePrekeys, resolveNativeDirectory } from './native-directory.ts';
import { drainNativeOutbox } from './native-outbox.ts';
import { nativeAccountCapabilities, nativeDeleteAccount, nativeDiscardAccount, nativeRenewDevices, nativeRevokeDevice } from './native-account.ts';
import type { MailboxSocket } from './mailbox-sync';
import {
  fanout_send_export,
  account_delete_export,
  account_discard_export,
  account_capabilities_export,
  devices_renew_export,
  device_revoke_export,
  group_forget_export,
  attachment_fetch_chunk_export,
  attachment_upload_export,
  attachment_discard_export,
  authorize_device_link_for_set_export,
  directory_register_export,
  directory_resolve_export,
  prekeys_synchronize_export,
  group_add_export,
  group_create_export,
  group_history_export,
  group_policy_export,
  group_inspect_export,
  group_key_package_export,
  group_invitation_complete_export,
  group_invitation_decline_export,
  group_invitations_export,
  group_list_export,
  group_remove_export,
  group_send_export,
  inspect_device_set_export,
  load_profile_export,
  mailbox_stream_open_export,
  mailbox_stream_poll_export,
  mailbox_stream_close_export,
  mailbox_synchronize_export,
  outbox_drain_export,
} from '../modules/mesh-messenger';
import {
  ATTACHMENT_CHUNK_SIZE,
  encodeAttachmentReferences,
  type AttachmentSummary,
  batchRequest,
  hex,
  decodeUtf8,
  type DeviceSetSummary,
  type GroupHistoryMessage,
  type GroupDetails,
  type GroupSummary,
  type GroupInvitation,
  parseByteList,
  parseDeviceSetSummary,
  parseGroupHistory,
  parseGroupPolicy,
  parseGroupDetails,
  parseGroupList,
  parseGroupInvitations,
  parseProfileSummary,
  utf8,
  vectors,
  writeU32,
} from './codec';
import {
  createKeyedSerialQueue,
  createKeyedSingleFlight,
} from './single-flight';
export class PostageRequired extends Error {
  readonly triggerIds: Uint8Array[];
  constructor(triggerIds: Uint8Array[]) { super('postage_required'); this.triggerIds=triggerIds; }
}
export const GROUP_KEY_PACKAGE_LENGTH = 401;
export type Removal = 'account-deleted' | 'device-removed' | 'device-left';
const removals: Record<number, Removal> = { 1: 'account-deleted', 2: 'device-removed', 3: 'device-left' };
export // 409: the name, or this device's place in the account, is someone else's now;
// 410: this device is out of its account, with the proof. Unlike an outage,
// neither passes on a retry.
class VerifiedDirectoryRemoval extends Error {
  readonly removal: Removal;
  constructor(removal: Removal) { super('removed_from_account'); this.removal = removal; }
}
export // Mesh has already committed each refusal before this presentation report.
type Undeliverable = { status: number; queuedAt: number };
export type AttachmentRecipients = { username: string; expectedPeer?: Uint8Array } | { groupIds: Uint8Array[] };
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
function attachmentRequest(...parts: Uint8Array[]): Uint8Array {
  const payload = vectors(...parts);
  const request = new Uint8Array(4 + payload.length);
  request.set(writeU32(parts.length));
  request.set(payload, 4);
  return request;
}
export function describeAttachmentLimit(size: number): string | undefined {
  return attachmentSelectionError([size]);
}
export function createNetworkServices(deps: Pick<ScopedClient, 'account_capabilities_export' | 'account_delete_export' | 'account_discard_export' | 'assertCurrent' | 'runPrivate' | 'attachment_discard_export' | 'attachment_fetch_chunk_export' | 'attachment_upload_export' | 'authorize_device_link_for_set_export' | 'device_revoke_export' | 'devices_renew_export' | 'directory_register_export' | 'directory_resolve_export' | 'fanout_send_export' | 'group_add_export' | 'group_create_export' | 'group_forget_export' | 'group_history_export' | 'group_inspect_export' | 'group_invitation_complete_export' | 'group_invitation_decline_export' | 'group_invitations_export' | 'group_key_package_export' | 'group_list_export' | 'group_policy_export' | 'group_remove_export' | 'group_send_export' | 'inspect_device_set_export' | 'load_profile_export' | 'mailbox_stream_close_export' | 'mailbox_stream_open_export' | 'mailbox_stream_poll_export' | 'mailbox_synchronize_export' | 'onDispose' | 'outbox_drain_export' | 'prekeys_synchronize_export'>) {
const { fanout_send_export, account_delete_export, account_discard_export, account_capabilities_export, devices_renew_export, device_revoke_export, group_forget_export, attachment_fetch_chunk_export, attachment_upload_export, attachment_discard_export, authorize_device_link_for_set_export, directory_register_export, directory_resolve_export, prekeys_synchronize_export, group_add_export, group_create_export, group_history_export, group_policy_export, group_inspect_export, group_key_package_export, group_invitation_complete_export, group_invitation_decline_export, group_invitations_export, group_list_export, group_remove_export, group_send_export, inspect_device_set_export, load_profile_export, mailbox_stream_open_export, mailbox_stream_poll_export, mailbox_stream_close_export, mailbox_synchronize_export, outbox_drain_export } = deps;
const synchronizePrekeysByDatabase = createKeyedSingleFlight<string, void>();
const synchronizeMailboxByDatabase = createKeyedSingleFlight<string, void>();
const drainOutboxByDatabase = createKeyedSingleFlight<string, void>();
const outboxSerialByDatabase = createKeyedSerialQueue<string>();
const resolveTransparencyByDatabase = createKeyedSerialQueue<string>();
const sendFanoutByDatabase = createKeyedSerialQueue<string>();
const mailboxSockets = new Set<MailboxSocket>();
const postageListeners = new Set<(report: { triggerId: Uint8Array }) => void>();
function onPostageRequired(listener: (report: { triggerId: Uint8Array }) => void): () => void {
  deps.assertCurrent();
  const held = (report: { triggerId: Uint8Array }) => listener(report);
  postageListeners.add(held); return () => { postageListeners.delete(held); };
}
async function reportPostage(triggerId: Uint8Array): Promise<void> {
  for (const listener of postageListeners) {
    try { await deps.runPrivate(async () => {
      if (postageListeners.has(listener)) listener({ triggerId: triggerId.slice() });
    }); } catch { /* Reporting never settles an envelope. */ }
  }
}
async function registerDirectory(databasePath: string, _signedSignupPolicy?: Uint8Array): Promise<void> {
  const result = await registerNativeDirectory(databasePath, directory_register_export);
  if (result.removalKind !== 0) throw new VerifiedDirectoryRemoval(removals[result.removalKind]!);
}
// Native code checks the account/device shown by this UI action before it
// signs, sends or mutates anything. The eventual erase also guards the exact
// encrypted profile captured before HTTP.
function holdsAccountKey(databasePath: string, expectedProfile: Uint8Array): Promise<boolean> {
  return nativeAccountCapabilities(databasePath, expectedProfile, account_capabilities_export);
}
function discardAccount(databasePath: string, expectedProfile: Uint8Array): Promise<void> {
  return nativeDiscardAccount(databasePath, expectedProfile, account_discard_export);
}
async function deleteAccount(databasePath: string, expectedProfile: Uint8Array): Promise<void> {
  await nativeDeleteAccount(databasePath, expectedProfile, account_delete_export);
}
async function connectMailboxStream(databasePath: string): Promise<MailboxSocket> {
  await registerDirectory(databasePath);
  const socket = await openNativeMailboxSocket(databasePath, {
    open: mailbox_stream_open_export,
    poll: mailbox_stream_poll_export,
    close: mailbox_stream_close_export,
  });
  const close = socket.close.bind(socket);
  socket.close = () => { mailboxSockets.delete(socket); close(); };
  mailboxSockets.add(socket);
  return socket;
}
function synchronizePrekeys(databasePath: string): Promise<void> {
  return synchronizePrekeysByDatabase(databasePath, async () => {
    await synchronizeNativePrekeys(databasePath, prekeys_synchronize_export);
  });
}
// Mesh owns native destinations, work, migration fallback, witness waiting and
// atomic checkpoint admission. JS serializes local requests and displays results.
function resolveDeviceSet(databasePath: string, username: string): Promise<Uint8Array> {
  return resolveTransparencyByDatabase(databasePath, () =>
    resolveNativeDirectory(databasePath, username, directory_resolve_export));
}
async function inspectDeviceSet(
  databasePath: string,
  deviceSet: Uint8Array,
): Promise<DeviceSetSummary> {
  const encoded = await inspect_device_set_export(batchRequest(databasePath, deviceSet));
  return parseDeviceSetSummary(encoded);
}
async function loadAccountDevices(
  databasePath: string,
  profile: Uint8Array,
): Promise<{ wire: Uint8Array; summary: DeviceSetSummary }> {
  const wire = await resolveDeviceSet(databasePath, parseProfileSummary(profile).username);
  const summary = await inspectDeviceSet(databasePath, wire);
  await renewDevices(databasePath, wire);
  return { wire, summary };
}
// Native code persists exact ordered signed entries before any publication.
// Refused or unknown outcomes retain that queue for the next witnessed view.
async function renewDevices(databasePath: string, deviceSet: Uint8Array): Promise<void> {
  const result = await nativeRenewDevices(databasePath, deviceSet, devices_renew_export);
  if (result.removalKind !== 0) throw new VerifiedDirectoryRemoval(removals[result.removalKind]!);
}
async function authorizeDeviceLink(
  databasePath: string,
  deviceSet: Uint8Array,
  linkRequest: Uint8Array,
): Promise<Uint8Array> {
  return authorize_device_link_for_set_export(
    vectors(utf8(databasePath), deviceSet, linkRequest),
  );
}
async function revokeDevice(
  databasePath: string,
  deviceSet: Uint8Array,
  deviceId: Uint8Array,
): Promise<void> {
  await nativeRevokeDevice(databasePath, deviceSet, deviceId, device_revoke_export);
}
const undeliverableListeners = new Set<(report: Undeliverable) => void>();
deps.onDispose(() => {
  postageListeners.clear(); undeliverableListeners.clear();
  for (const socket of mailboxSockets) socket.close();
  mailboxSockets.clear();
});
function onUndeliverable(listener: (report: Undeliverable) => void): () => void {
  deps.assertCurrent();
  const held = (report: Undeliverable) => listener(report);
  undeliverableListeners.add(held);
  return () => { undeliverableListeners.delete(held); };
}
async function drainOutboxOnce(databasePath: string, retryFree: boolean): Promise<void> {
  const result = await drainNativeOutbox(databasePath, retryFree, outbox_drain_export);
  for (const report of result.failures) {
    for (const listener of undeliverableListeners) {
      try { await deps.runPrivate(async () => {
        if (undeliverableListeners.has(listener)) listener({ ...report });
      }); } catch { /* Presentation cannot stall native progress. */ }
    }
  }
  for (const trigger of result.postage) await reportPostage(trigger);
  if (result.postage.length) throw new PostageRequired(result.postage);
  if (result.status === 1) throw new Error('recipient_unavailable');
  if (result.status === 2) throw new Error('outbox_transport_unavailable');
  if (result.status === 3) throw new Error('outbox_transport_budget_exhausted');
}
function retryFreePostage(databasePath: string): Promise<void> {
  // An explicit retry follows an active ordinary pass; it must not be swallowed
  // by the automatic pass's single-flight promise. It never authorizes spending.
  return outboxSerialByDatabase(databasePath, () => drainOutboxOnce(databasePath, true));
}
function drainOutbox(databasePath: string): Promise<void> {
  return drainOutboxByDatabase(databasePath, () =>
    outboxSerialByDatabase(databasePath, () => drainOutboxOnce(databasePath, false)));
}
async function listGroups(databasePath: string): Promise<GroupSummary[]> {
  return parseGroupList(await group_list_export(utf8(databasePath)));
}
async function createGroup(databasePath: string): Promise<Uint8Array> {
  const profile = parseProfileSummary(await load_profile_export(utf8(databasePath)));
  await resolveDeviceSet(databasePath, profile.username);
  const groupId = await group_create_export(utf8(databasePath));
  if (groupId.length !== 32) throw new Error('Mesh returned an invalid group ID');
  return groupId;
}
async function getGroupKeyPackage(databasePath: string): Promise<Uint8Array> {
  const keyPackage = await group_key_package_export(utf8(databasePath));
  if (keyPackage.length !== GROUP_KEY_PACKAGE_LENGTH && keyPackage.length !== 369) {
    throw new Error('Mesh returned an invalid group key package');
  }
  return keyPackage;
}
async function loadGroupHistory(
  databasePath: string,
  groupId: Uint8Array,
): Promise<GroupHistoryMessage[]> {
  return parseGroupHistory(await group_history_export(vectors(utf8(databasePath), groupId)));
}
async function groupMessageTimer(databasePath: string, groupId: Uint8Array, seconds?: number): Promise<number> {
  if (seconds !== undefined && (!Number.isInteger(seconds) || seconds < 0 || seconds > 2_592_000)) throw Error('invalid_group_policy');
  const request = seconds === undefined ? vectors(utf8(databasePath), groupId) : vectors(utf8(databasePath), groupId, writeU32(seconds));
  return parseGroupPolicy(await group_policy_export(request), groupId);
}
async function inspectGroup(
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
async function addGroupMember(
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
async function sendGroupMessage(
  databasePath: string,
  groupId: Uint8Array,
  body: string,
  attachment?: Uint8Array,
): Promise<void> {
  await refreshGroupAuthorizations(databasePath, groupId);
  await group_send_export(vectors(utf8(databasePath), groupId, utf8(body), ...(attachment ? [attachment] : [])));
  await drainOutbox(databasePath);
}
// Mesh resolves and verifies signed device capabilities, then returns an opaque
// account-bound ticket. Upload and credit actions recheck it inside Mesh.
async function authorizeAttachmentRecipients(database: string, profile: Uint8Array, target: AttachmentRecipients): Promise<Uint8Array> {
  const groups = 'groupIds' in target;
  let payload = new Uint8Array();
  if (groups) {
    if (!target.groupIds.length || target.groupIds.length > 64 || target.groupIds.some(id => id.length !== 32)) throw new Error('invalid_attachment_recipients');
    payload = new Uint8Array(target.groupIds.length * 32);
    target.groupIds.forEach((id, index) => payload.set(id, index * 32));
  }
  const request = nativeFanoutRequest(database, profile,
    groups ? parseProfileSummary(profile).username : target.username,
    groups ? 5 : 4, payload, groups ? undefined : target.expectedPeer);
  const ticket = await fanout_send_export(request);
  if (!ticket.length || ticket.length > 40_000) throw new Error('invalid_attachment_recipients');
  return ticket;
}
// Encrypts and uploads one file: the sealed manifest is part 0 and each 64 KiB
// chunk follows. The object is completed only once every part is stored.
async function uploadAttachment(
  databasePath: string,
  file: OutgoingAttachment,
  authorization: Uint8Array,
  onProgress?: TransferProgress,
): Promise<UploadedAttachment> {
  const limit = describeAttachmentLimit(file.bytes.length);
  if (limit) throw new Error(limit);
  const chunkCount = Math.ceil(file.bytes.length / ATTACHMENT_CHUNK_SIZE);
  onProgress?.(0, chunkCount);
  const [reference, objectId, ticket] = parseByteList(await attachment_upload_export(attachmentRequest(
    utf8(databasePath), utf8(file.filename), utf8(file.mimeType), file.bytes, authorization,
  )), 3, 4_096);
  if (!reference?.length || !objectId || objectId.length !== 32 || !ticket?.length) {
    throw new Error('Mesh returned an invalid attachment');
  }
  onProgress?.(chunkCount, chunkCount);
  const discard = async (): Promise<void> => {
    const result = await attachment_discard_export(attachmentRequest(utf8(databasePath), ticket));
    if (result.length !== 0) throw new Error('Mesh returned an invalid attachment');
  };
  return { reference, objectId, discard };
}
// Upload the whole selection before creating one message. Failed uploads can be
// removed; a failed send may already be in the durable outbox, so keep its objects.
async function sendWithAttachments(
  databasePath: string,
  files: OutgoingAttachment[],
  authorization: Uint8Array,
  send: (reference?: Uint8Array) => Promise<void>,
  onProgress?: TransferProgress,
): Promise<UploadedAttachment[]> {
  const error = attachmentSelectionError(files.map((file) => file.bytes.length));
  if (error) throw new Error(error);
  const uploaded: UploadedAttachment[] = [];
  try {
    for (const file of files) {
      uploaded.push(await uploadAttachment(databasePath, file, authorization, (completed, total) =>
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
async function downloadAttachment(
  databasePath: string,
  attachment: AttachmentSummary,
  onProgress?: TransferProgress,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(attachment.size) || attachment.size < 1 || attachment.size > 16_777_216) {
    throw new Error('attachment_requires_range_download');
  }
  const output = new Uint8Array(attachment.size);
  const clear = () => output.fill(0);
  signal?.addEventListener('abort', clear, { once: true });
  let offset = 0;
  try {
    for (let index = 0; index < attachment.chunkCount; index += 1) {
      if (signal?.aborted) throw new Error('attachment_download_aborted');
      const chunk = await attachment_fetch_chunk_export(attachmentRequest(utf8(databasePath), attachment.reference, writeU32(index)));
      try {
        // Native calls already in flight cannot be recalled. Do not retain the
        // result or request another part after its conversation has closed.
        if (signal?.aborted) throw new Error('attachment_download_aborted');
        if (offset + chunk.length > output.length) throw new Error(t('The attachment does not match its manifest'));
        output.set(chunk, offset);
        offset += chunk.length;
      } finally { chunk.fill(0); }
      onProgress?.(index + 1, attachment.chunkCount);
    }
    if (signal?.aborted) throw new Error('attachment_download_aborted');
    if (offset !== output.length) throw new Error(t('The attachment does not match its manifest'));
    return output;
  } catch (error) { output.fill(0); throw error; }
  finally { signal?.removeEventListener('abort', clear); }
}
// Forgets a group on this device alone: its state, keys, history and records.
async function forgetGroup(databasePath: string, groupId: Uint8Array): Promise<void> {
  await group_forget_export(vectors(utf8(databasePath), groupId));
}
async function removeGroupMember(
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
  expectedLocalProfile: Uint8Array,
  peerUsername: string,
  kind: FanoutKind,
  body: Uint8Array,
  expectedAccountId?: Uint8Array,
  attachment?: Uint8Array,
): Promise<boolean> {
  const request = nativeFanoutRequest(databasePath, expectedLocalProfile, peerUsername, kind, body, expectedAccountId, attachment);
  return sendFanoutByDatabase(databasePath, async () => {
    const changed = parseNativeFanoutStatus(await fanout_send_export(request));
    await drainOutbox(databasePath);
    return changed;
  });
}
function sendFanout(
  databasePath: string,
  expectedLocalProfile: Uint8Array,
  username: string,
  body: string,
  expectedAccountId?: Uint8Array,
  attachment?: Uint8Array,
): Promise<boolean> {
  return sendWithDevices(databasePath, expectedLocalProfile, username, 1, utf8(body), expectedAccountId, attachment);
}
function inviteToGroup(databasePath: string, expectedLocalProfile: Uint8Array, groupId: Uint8Array, username: string): Promise<boolean> {
  return sendWithDevices(databasePath, expectedLocalProfile, username, 2, groupId);
}
function acceptGroupInvitation(databasePath: string, expectedLocalProfile: Uint8Array, invitation: GroupInvitation): Promise<boolean> {
  return sendWithDevices(databasePath, expectedLocalProfile, invitation.username, 3, invitation.reference, invitation.accountId);
}
async function declineGroupInvitation(databasePath: string, reference: Uint8Array): Promise<void> {
  await group_invitation_decline_export(vectors(utf8(databasePath), reference));
}
async function listGroupInvitations(databasePath: string): Promise<GroupInvitation[]> {
  return parseGroupInvitations(await group_invitations_export(utf8(databasePath)));
}
function completeGroupInvitations(databasePath: string): Promise<void> {
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
// Mesh owns the signed fetch, durable inbox processing and acknowledgement.
// JavaScript schedules bounded passes and displays public progress only.
async function receiveMailbox(databasePath: string): Promise<void> {
  const outcome = await synchronizeNativeMailbox(databasePath, mailbox_synchronize_export);
  if (outcome.pending) throw new Error(t('Message processing is pending. Retrying…'));
}
function synchronizeMailbox(databasePath: string): Promise<void> {
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
return Object.freeze({
  onPostageRequired,
  registerDirectory: (...args: Parameters<typeof registerDirectory>) => deps.runPrivate(() => registerDirectory(...args)),
  holdsAccountKey: (...args: Parameters<typeof holdsAccountKey>) => deps.runPrivate(() => holdsAccountKey(...args)),
  discardAccount: (...args: Parameters<typeof discardAccount>) => deps.runPrivate(() => discardAccount(...args)),
  deleteAccount: (...args: Parameters<typeof deleteAccount>) => deps.runPrivate(() => deleteAccount(...args)),
  connectMailboxStream: (...args: Parameters<typeof connectMailboxStream>) => runPrivateOwned({ scope: deps, operation: () => connectMailboxStream(...args), discard: socket => socket.close() }),
  synchronizePrekeys: (...args: Parameters<typeof synchronizePrekeys>) => deps.runPrivate(() => synchronizePrekeys(...args)),
  resolveDeviceSet: (...args: Parameters<typeof resolveDeviceSet>) => deps.runPrivate(() => resolveDeviceSet(...args)),
  inspectDeviceSet: (...args: Parameters<typeof inspectDeviceSet>) => deps.runPrivate(() => inspectDeviceSet(...args)),
  loadAccountDevices: (...args: Parameters<typeof loadAccountDevices>) => deps.runPrivate(() => loadAccountDevices(...args)),
  renewDevices: (...args: Parameters<typeof renewDevices>) => deps.runPrivate(() => renewDevices(...args)),
  authorizeDeviceLink: (...args: Parameters<typeof authorizeDeviceLink>) => deps.runPrivate(() => authorizeDeviceLink(...args)),
  revokeDevice: (...args: Parameters<typeof revokeDevice>) => deps.runPrivate(() => revokeDevice(...args)),
  onUndeliverable,
  retryFreePostage: (...args: Parameters<typeof retryFreePostage>) => deps.runPrivate(() => retryFreePostage(...args)),
  drainOutbox: (...args: Parameters<typeof drainOutbox>) => deps.runPrivate(() => drainOutbox(...args)),
  listGroups: (...args: Parameters<typeof listGroups>) => deps.runPrivate(() => listGroups(...args)),
  createGroup: (...args: Parameters<typeof createGroup>) => deps.runPrivate(() => createGroup(...args)),
  getGroupKeyPackage: (...args: Parameters<typeof getGroupKeyPackage>) => deps.runPrivate(() => getGroupKeyPackage(...args)),
  loadGroupHistory: (...args: Parameters<typeof loadGroupHistory>) => deps.runPrivate(() => loadGroupHistory(...args)),
  groupMessageTimer: (...args: Parameters<typeof groupMessageTimer>) => deps.runPrivate(() => groupMessageTimer(...args)),
  inspectGroup: (...args: Parameters<typeof inspectGroup>) => deps.runPrivate(() => inspectGroup(...args)),
  addGroupMember: (...args: Parameters<typeof addGroupMember>) => deps.runPrivate(() => addGroupMember(...args)),
  sendGroupMessage: (...args: Parameters<typeof sendGroupMessage>) => deps.runPrivate(() => sendGroupMessage(...args)),
  authorizeAttachmentRecipients: (...args: Parameters<typeof authorizeAttachmentRecipients>) => deps.runPrivate(() => authorizeAttachmentRecipients(...args)),
  uploadAttachment: (...args: Parameters<typeof uploadAttachment>) => deps.runPrivate(() => uploadAttachment(...args)),
  sendWithAttachments: (...args: Parameters<typeof sendWithAttachments>) => deps.runPrivate(() => sendWithAttachments(...args)),
  downloadAttachment: (...args: Parameters<typeof downloadAttachment>) => deps.runPrivate(() => downloadAttachment(...args)),
  forgetGroup: (...args: Parameters<typeof forgetGroup>) => deps.runPrivate(() => forgetGroup(...args)),
  removeGroupMember: (...args: Parameters<typeof removeGroupMember>) => deps.runPrivate(() => removeGroupMember(...args)),
  sendFanout: (...args: Parameters<typeof sendFanout>) => deps.runPrivate(() => sendFanout(...args)),
  inviteToGroup: (...args: Parameters<typeof inviteToGroup>) => deps.runPrivate(() => inviteToGroup(...args)),
  acceptGroupInvitation: (...args: Parameters<typeof acceptGroupInvitation>) => deps.runPrivate(() => acceptGroupInvitation(...args)),
  declineGroupInvitation: (...args: Parameters<typeof declineGroupInvitation>) => deps.runPrivate(() => declineGroupInvitation(...args)),
  listGroupInvitations: (...args: Parameters<typeof listGroupInvitations>) => deps.runPrivate(() => listGroupInvitations(...args)),
  completeGroupInvitations: (...args: Parameters<typeof completeGroupInvitations>) => deps.runPrivate(() => completeGroupInvitations(...args)),
  synchronizeMailbox: (...args: Parameters<typeof synchronizeMailbox>) => deps.runPrivate(() => synchronizeMailbox(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createNetworkServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createNetworkServices({ assertCurrent: () => {}, runPrivate: operation => operation(), onDispose: () => () => {}, fanout_send_export, account_delete_export, account_discard_export, account_capabilities_export, devices_renew_export, device_revoke_export, group_forget_export, attachment_fetch_chunk_export, attachment_upload_export, attachment_discard_export, authorize_device_link_for_set_export, directory_register_export, directory_resolve_export, prekeys_synchronize_export, group_add_export, group_create_export, group_history_export, group_policy_export, group_inspect_export, group_key_package_export, group_invitation_complete_export, group_invitation_decline_export, group_invitations_export, group_list_export, group_remove_export, group_send_export, inspect_device_set_export, load_profile_export, mailbox_stream_open_export, mailbox_stream_poll_export, mailbox_stream_close_export, mailbox_synchronize_export, outbox_drain_export });
}
export const onPostageRequired: ReturnType<typeof createNetworkServices>['onPostageRequired'] = (...args) => desktopCompatibility().onPostageRequired(...args);
export const registerDirectory: ReturnType<typeof createNetworkServices>['registerDirectory'] = (...args) => desktopCompatibility().registerDirectory(...args);
export const holdsAccountKey: ReturnType<typeof createNetworkServices>['holdsAccountKey'] = (...args) => desktopCompatibility().holdsAccountKey(...args);
export const discardAccount: ReturnType<typeof createNetworkServices>['discardAccount'] = (...args) => desktopCompatibility().discardAccount(...args);
export const deleteAccount: ReturnType<typeof createNetworkServices>['deleteAccount'] = (...args) => desktopCompatibility().deleteAccount(...args);
export const connectMailboxStream: ReturnType<typeof createNetworkServices>['connectMailboxStream'] = (...args) => desktopCompatibility().connectMailboxStream(...args);
export const synchronizePrekeys: ReturnType<typeof createNetworkServices>['synchronizePrekeys'] = (...args) => desktopCompatibility().synchronizePrekeys(...args);
export const resolveDeviceSet: ReturnType<typeof createNetworkServices>['resolveDeviceSet'] = (...args) => desktopCompatibility().resolveDeviceSet(...args);
export const inspectDeviceSet: ReturnType<typeof createNetworkServices>['inspectDeviceSet'] = (...args) => desktopCompatibility().inspectDeviceSet(...args);
export const loadAccountDevices: ReturnType<typeof createNetworkServices>['loadAccountDevices'] = (...args) => desktopCompatibility().loadAccountDevices(...args);
export const renewDevices: ReturnType<typeof createNetworkServices>['renewDevices'] = (...args) => desktopCompatibility().renewDevices(...args);
export const authorizeDeviceLink: ReturnType<typeof createNetworkServices>['authorizeDeviceLink'] = (...args) => desktopCompatibility().authorizeDeviceLink(...args);
export const revokeDevice: ReturnType<typeof createNetworkServices>['revokeDevice'] = (...args) => desktopCompatibility().revokeDevice(...args);
export const onUndeliverable: ReturnType<typeof createNetworkServices>['onUndeliverable'] = (...args) => desktopCompatibility().onUndeliverable(...args);
export const retryFreePostage: ReturnType<typeof createNetworkServices>['retryFreePostage'] = (...args) => desktopCompatibility().retryFreePostage(...args);
export const drainOutbox: ReturnType<typeof createNetworkServices>['drainOutbox'] = (...args) => desktopCompatibility().drainOutbox(...args);
export const listGroups: ReturnType<typeof createNetworkServices>['listGroups'] = (...args) => desktopCompatibility().listGroups(...args);
export const createGroup: ReturnType<typeof createNetworkServices>['createGroup'] = (...args) => desktopCompatibility().createGroup(...args);
export const getGroupKeyPackage: ReturnType<typeof createNetworkServices>['getGroupKeyPackage'] = (...args) => desktopCompatibility().getGroupKeyPackage(...args);
export const loadGroupHistory: ReturnType<typeof createNetworkServices>['loadGroupHistory'] = (...args) => desktopCompatibility().loadGroupHistory(...args);
export const groupMessageTimer: ReturnType<typeof createNetworkServices>['groupMessageTimer'] = (...args) => desktopCompatibility().groupMessageTimer(...args);
export const inspectGroup: ReturnType<typeof createNetworkServices>['inspectGroup'] = (...args) => desktopCompatibility().inspectGroup(...args);
export const addGroupMember: ReturnType<typeof createNetworkServices>['addGroupMember'] = (...args) => desktopCompatibility().addGroupMember(...args);
export const sendGroupMessage: ReturnType<typeof createNetworkServices>['sendGroupMessage'] = (...args) => desktopCompatibility().sendGroupMessage(...args);
export const authorizeAttachmentRecipients: ReturnType<typeof createNetworkServices>['authorizeAttachmentRecipients'] = (...args) => desktopCompatibility().authorizeAttachmentRecipients(...args);
export const uploadAttachment: ReturnType<typeof createNetworkServices>['uploadAttachment'] = (...args) => desktopCompatibility().uploadAttachment(...args);
export const sendWithAttachments: ReturnType<typeof createNetworkServices>['sendWithAttachments'] = (...args) => desktopCompatibility().sendWithAttachments(...args);
export const downloadAttachment: ReturnType<typeof createNetworkServices>['downloadAttachment'] = (...args) => desktopCompatibility().downloadAttachment(...args);
export const forgetGroup: ReturnType<typeof createNetworkServices>['forgetGroup'] = (...args) => desktopCompatibility().forgetGroup(...args);
export const removeGroupMember: ReturnType<typeof createNetworkServices>['removeGroupMember'] = (...args) => desktopCompatibility().removeGroupMember(...args);
export const sendFanout: ReturnType<typeof createNetworkServices>['sendFanout'] = (...args) => desktopCompatibility().sendFanout(...args);
export const inviteToGroup: ReturnType<typeof createNetworkServices>['inviteToGroup'] = (...args) => desktopCompatibility().inviteToGroup(...args);
export const acceptGroupInvitation: ReturnType<typeof createNetworkServices>['acceptGroupInvitation'] = (...args) => desktopCompatibility().acceptGroupInvitation(...args);
export const declineGroupInvitation: ReturnType<typeof createNetworkServices>['declineGroupInvitation'] = (...args) => desktopCompatibility().declineGroupInvitation(...args);
export const listGroupInvitations: ReturnType<typeof createNetworkServices>['listGroupInvitations'] = (...args) => desktopCompatibility().listGroupInvitations(...args);
export const completeGroupInvitations: ReturnType<typeof createNetworkServices>['completeGroupInvitations'] = (...args) => desktopCompatibility().completeGroupInvitations(...args);
export const synchronizeMailbox: ReturnType<typeof createNetworkServices>['synchronizeMailbox'] = (...args) => desktopCompatibility().synchronizeMailbox(...args);
