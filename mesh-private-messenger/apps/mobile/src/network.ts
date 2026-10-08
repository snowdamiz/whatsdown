import { attachmentCreditCost, attachmentSelectionError, creditShortfall } from './attachments.ts';
import { fetch, openMailboxSocket, isDevelopmentBuild } from './transport';
import type { MailboxSocket } from './mailbox-sync';
import {
  account_deletion_export,
  backup_disable_export,
  group_forget_export,
  attachment_open_chunk_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
  authorize_device_link_for_set_export,
  create_device_revocation_export,
  device_departure_export,
  erase_account_export,
  forget_on_proof_export,
  register_request_export,
  renew_devices_export,
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
  transparency_anchor_requests_export,
  transparency_anchor_proof_export,
  network_status_export,
  oblivious_decapsulate_export,
  oblivious_encapsulate_export,
  anchor_check_export,
  gossip_check_export,
  trust_alarm_details_export,
  credits_postage_quote_export,
  credits_register_at_export,
  group_send_view_once_export,
  group_timer_export,
  send_view_once_export,
} from '../modules/mesh-messenger';
import { parseNetworkStatus, type NetworkStatus } from './witnesses.ts';
import {
  anchorCheckDue,
  encodeAnchorExchange,
  encodeAnchorExchanges,
  parseAnchorStep,
  parseTrustDetails,
  type AnchorRequest,
  type CheckReason,
  type TrustDetails,
} from './public-record.ts';
import {
  ATTACHMENT_CHUNK_SIZE,
  MAXIMUM_ATTACHMENT_SIZE,
  encodeAttachmentReferences,
  envelopeExpiresAt,
  envelopeQueuedAt,
  type AttachmentSummary,
  batchRequest,
  hex,
  Reader,
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
const checkPublicRecordByDatabase = createKeyedSingleFlight<string, void>();
const exchangeCheckpointsByDatabase = createKeyedSingleFlight<string, void>();
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

export class ServerStatusError extends Error {
  readonly status: number;
  readonly body: Uint8Array;

  constructor(status: number, body = new Uint8Array()) {
    super(`Server returned ${status}`);
    this.status = status;
    this.body = body;
  }
}

// This device is out of its account for good: the account was deleted, or the
// device removed or left. The statement is the signed proof, which the core
// checks before this device erases itself.
export class RemovedFromAccount extends Error {
  readonly statement: Uint8Array;

  constructor(statement: Uint8Array) {
    super('removed_from_account');
    this.statement = statement;
  }
}

export type Removal = 'account-deleted' | 'device-removed' | 'device-left';
const removals: Record<number, Removal> = { 1: 'account-deleted', 2: 'device-removed', 3: 'device-left' };

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
    if (!response.ok && !prekeyRecovery) {
      throw new ServerStatusError(response.status, new Uint8Array(await response.arrayBuffer()));
    }
    return new Uint8Array(await response.arrayBuffer());
  } finally {
    clearTimeout(timeout);
  }
}

// Oblivious HTTP (RFC 9458, protocol/ohttp-v1.md) for the stateless requests
// and the signed mailbox fetch and acknowledgement: Mesh seals each one to the
// gateway key this build pins, this code carries it to the pinned relay (the
// privacy edge) and back, and Mesh opens the answer. The response key stays in
// Mesh, sealed to the device. The backend sees the edge's connection, not this
// device's. A development build that pins no gateway sends them directly; a
// release build always pins one.
async function obliviousRequest(path: string, body: Uint8Array, method = 'POST'): Promise<Uint8Array> {
  const sealed = await oblivious_encapsulate_export(vectors(utf8(method), utf8(path), body));
  if (sealed.length === 0) {
    if (!isDevelopmentBuild()) throw new Error('oblivious_http_unconfigured');
    return binaryRequest(path, body, method);
  }
  const reader = new Reader(sealed);
  const relay = new TextDecoder().decode(reader.vector(4096));
  const request = reader.vector(65_536 + 64);
  const key = reader.vector(4096);
  reader.finish();
  const answer = await binaryRequest('/v1/ohttp', request, 'POST', relay, { 'Content-Type': 'message/ohttp-req' });
  const opened = await oblivious_decapsulate_export(vectors(key, answer));
  const status = ((opened[0] ?? 0) << 8) | (opened[1] ?? 0);
  const payload = opened.slice(2);
  if (status < 200 || status >= 300) throw new ServerStatusError(status, payload);
  return payload;
}

// The same, never throwing: status 0 when nothing answered (the core-driven
// steps' convention).
async function obliviousPost(path: string, body: Uint8Array): Promise<{ status: number; body: Uint8Array }> {
  try {
    return { status: 200, body: await obliviousRequest(path, body) };
  } catch (error) {
    if (error instanceof ServerStatusError) return { status: error.status, body: error.body };
    return { status: 0, body: new Uint8Array() };
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

// 409: the name, or this device's place in the account, is someone else's now;
// 410: this device is out of its account, with the proof. Unlike an outage,
// neither passes on a retry.
export async function registerDirectory(databasePath: string): Promise<void> {
  // Anonymous directory requests leave Mesh already wrapped in proof of work.
  const entry = await register_request_export(utf8(databasePath));
  try {
    try {
      await binaryRequest('/v1/devices/register', entry, 'PUT');
    } catch (error) {
      // Sign-ups are busy: work harder, or skip the wait with credits.
      if (!(error instanceof ServerStatusError) || error.status !== 429 || !isSignupWork(error.body)) throw error;
      const busy = await creditHooks.busySignup(databasePath, error.body);
      try {
        await binaryRequest('/v1/devices/register', busy.body, 'PUT');
        await busy.settle?.(201);
      } catch (retried) {
        await busy.settle?.(retried instanceof ServerStatusError ? retried.status : 0);
        throw retried;
      }
    }
  } catch (error) {
    if (error instanceof ServerStatusError && error.status === 409) throw new Error('registration_refused');
    if (error instanceof ServerStatusError && error.status === 410) throw new RemovedFromAccount(error.body);
    throw error;
  }
  await synchronizePrekeys(databasePath);
}

// Only the device that created the account holds its key; a linked device gets
// no deletion statement and can erase only its own copy.
export async function holdsAccountKey(databasePath: string): Promise<boolean> {
  return (await account_deletion_export(utf8(databasePath))).length > 0;
}

export async function eraseAccount(databasePath: string): Promise<void> {
  await erase_account_export(utf8(databasePath));
}

// Erases this device only if the statement verifies against the keys it holds,
// and says which removal it proved.
export async function forgetOnProof(databasePath: string, statement: Uint8Array): Promise<Removal> {
  const removal = removals[(await forget_on_proof_export(vectors(utf8(databasePath), statement)))[0] ?? 0];
  if (!removal) throw new Error('invalid_removal_proof');
  return removal;
}

// The directory lets go before this device forgets: once the keys are erased,
// nothing could delete the account, free its name, or take this device out of
// it. A linked device holds no account key, so it leaves the account instead.
// Either answers 204 once nothing of this device's part is left there; 404 is a
// directory without the route.
export async function deleteAccount(databasePath: string): Promise<void> {
  const deletion = await account_deletion_export(utf8(databasePath));
  const [path, statement] = deletion.length > 0
    ? ['/v1/accounts/delete', deletion]
    : ['/v1/devices/leave', await device_departure_export(utf8(databasePath))];
  try {
    await binaryRequest(path, statement);
  } catch (error) {
    if (error instanceof ServerStatusError && error.status === 404) throw new Error('account_deletion_unsupported');
    // A stale statement: this device's clock is off by minutes.
    if (error instanceof ServerStatusError && error.status === 403) throw new Error('account_deletion_refused');
    throw error;
  }
  // Its backups go too, as far as they can be reached; the rest expire within days.
  try {
    const deletions = parseByteList(await backup_disable_export(vectors(utf8(databasePath))), 64, 68);
    await Promise.allSettled(deletions.map((control) => objectRequest('/v1/attachments/delete', control)));
  } catch { /* Nothing on this device can open them once it is erased. */ }
  await eraseAccount(databasePath);
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

// The witnesses sign a checkpoint seconds after the directory makes one (on a
// new account, or after four idle minutes). Until both signatures land its
// evidence cannot verify, so look again; unwitnessed evidence is never used.
const WITNESS_WAIT_MS = [1_000, 2_000, 3_000, 4_000, 5_000, 5_000];

// This device's own account moved through transitions it never saw, and the
// directory may have pruned their bytes (it keeps superseded entries 90 days).
// The core has taken on the account's current devices; the person is told and
// shown Linked devices.
const awayListeners = new Set<() => void>();

export function onAccountChangedWhileAway(listener: () => void): () => void {
  awayListeners.add(listener);
  return () => { awayListeners.delete(listener); };
}

export async function resolveDeviceSet(
  databasePath: string,
  username: string,
): Promise<Uint8Array> {
  return resolveTransparencyByDatabase(databasePath, async () => {
    let reported = false;
    for (let attempt = 0; ; attempt++) {
      const lookup = await resolve_request_export(
        batchRequest(databasePath, utf8(username)),
      );
      const evidence = await obliviousRequest('/v1/devices/resolve', lookup);
      try {
        return await verify_transparency_export(
          vectors(utf8(databasePath), utf8(username), evidence),
        );
      } catch (error) {
        if (!reported && String(error).includes('account_changed_while_away')) {
          reported = true;
          for (const listener of awayListeners) {
            try { listener(); } catch { /* Reporting is best effort. */ }
          }
          // The core stored the new set; a fresh lookup now verifies against it.
          continue;
        }
        const wait = WITNESS_WAIT_MS[attempt];
        if (wait === undefined || !String(error).includes('transparency_verification_failed')) throw error;
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
    }
  });
}

// A group's baseline or another device's key package can name a checkpoint
// this device never verified itself. Mesh lists each such anchor with the KTS
// v2 query (its first 21 bytes) that the directory answers with a consistency
// proof; Mesh checks each proof against its own view and remembers the anchor.
export async function supplyAnchorProofs(databasePath: string): Promise<number> {
  const requests = parseByteList(await transparency_anchor_requests_export(utf8(databasePath)), 16, 397);
  for (const request of requests) {
    const proof = await obliviousRequest('/v1/transparency/consistency', request.subarray(0, 21));
    await transparency_anchor_proof_export(vectors(utf8(databasePath), request, proof));
  }
  return requests.length;
}

// An operation that stopped for an anchor proof is tried once more after the
// proofs are in.
async function withAnchorProofs<T>(databasePath: string, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (!String(error).includes('transparency_anchor_proof_needed') || (await supplyAnchorProofs(databasePath)) === 0) {
      throw error;
    }
    return operation();
  }
}

// Settings -> Network and the safety number screen: the witness set this build
// pins, its profile, and whether a group needs a newer build.
export async function loadNetworkStatus(databasePath: string): Promise<NetworkStatus> {
  return parseNetworkStatus(await network_status_export(utf8(databasePath)));
}

// The phone's check against the public record (plan §6.7). Mesh decides every
// step; the app only carries its requests: JSON-RPC reads to the pinned RPC
// providers (never through Morse), the directory's consistency and leaf
// proofs, fork evidence to every pinned relay, and a finder address. The run
// goes back to Mesh with every exchange so far until Mesh says it is done.
const ANCHOR_ROUNDS = 24;

// "Collect fork bounties" arrives with the in-app wallet (plan §10): until then
// no finder address is named and the proof's finder field stays zero.
let finderAddress: () => Promise<Uint8Array | null> = async () => null;

export function setFinderAddressSource(source: () => Promise<Uint8Array | null>): void {
  finderAddress = source;
}

async function post(url: string, body: Uint8Array, contentType: string): Promise<{ status: number; body: Uint8Array }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(url, {
      method: 'POST',
      redirect: 'error',
      headers: { 'Content-Type': contentType },
      body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
      signal: controller.signal,
    });
    return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
  } catch {
    // No answer: Mesh treats status 0 as a provider that did not respond.
    return { status: 0, body: new Uint8Array() };
  } finally {
    clearTimeout(timeout);
  }
}

async function performAnchorRequest(request: AnchorRequest): Promise<Uint8Array> {
  let answer: { status: number; body: Uint8Array };
  if (request.kind === 4) {
    answer = { status: 200, body: (await finderAddress()) ?? new Uint8Array() };
  } else if (request.kind === 2) {
    if (!request.target.startsWith('/v1/transparency/')) throw new Error('invalid_anchor_request');
    answer = await obliviousPost(request.target, request.body);
  } else {
    // Pinned RPC providers (kind 1) and relays (kind 3) are HTTPS URLs from the config.
    answer = await post(serviceUrl(request.target), request.body, request.kind === 1 ? 'application/json' : 'application/octet-stream');
  }
  return encodeAnchorExchange(request, answer.status, answer.body);
}

// One run of core-driven steps (Mobile.AnchorSteps) to the end; says how many
// requests it carried.
async function runSteps(
  step: (request: Uint8Array) => Promise<Uint8Array>,
  databasePath: string,
  incomplete: string,
): Promise<number> {
  const exchanges: Uint8Array[] = [];
  for (let round = 0; round < ANCHOR_ROUNDS; round += 1) {
    const parsed = parseAnchorStep(await step(vectors(utf8(databasePath), encodeAnchorExchanges(exchanges))));
    if (parsed.done) return exchanges.length;
    exchanges.push(...await Promise.all(parsed.requests.map(performAnchorRequest)));
  }
  throw new Error(incomplete);
}

function publicRecordChanged(): void {
  for (const listener of publicRecordListeners) {
    try { listener(); } catch { /* Reporting is best effort. */ }
  }
}

async function checkPublicRecordOnce(databasePath: string): Promise<void> {
  await runSteps(anchor_check_export, databasePath, 'anchor_check_incomplete');
  publicRecordChanged();
}

export function checkPublicRecord(databasePath: string): Promise<void> {
  return checkPublicRecordByDatabase(databasePath, () => checkPublicRecordOnce(databasePath));
}

const publicRecordListeners = new Set<() => void>();

// Told after every finished check, so Settings and the banners reload.
export function onPublicRecordChecked(listener: () => void): () => void {
  publicRecordListeners.add(listener);
  return () => { publicRecordListeners.delete(listener); };
}

// Checkpoint gossip (plan §6.16), after each pass over the mailbox: Mesh
// settles what contacts' messages said about the key log through the same
// steps as the check above (the directory's consistency and leaf proofs, a
// finder address and the relays for a proof it built), and queues the
// encrypted checkpoint requests and answers it sends in the outbox. A run that
// raised "A contact's phone was shown a different key log" reloads the banners
// and checks the public record, which tells which phone was shown the other
// version; the check stays at most hourly.
export function exchangeCheckpoints(databasePath: string): Promise<void> {
  return exchangeCheckpointsByDatabase(databasePath, async () => {
    if ((await runSteps(gossip_check_export, databasePath, 'gossip_check_incomplete')) === 0) return;
    publicRecordChanged();
    if ((await loadNetworkStatus(databasePath)).alarm?.kind === 'contact_fork') {
      await schedulePublicRecordCheck(databasePath, 'key-change');
    }
  });
}

// Runs the check when it is due: daily, after a contact's keys change at most
// hourly, and when Settings -> Network opens with a stale reading.
export async function schedulePublicRecordCheck(databasePath: string, reason: CheckReason): Promise<boolean> {
  const status = await loadNetworkStatus(databasePath);
  if (!anchorCheckDue(status.anchor, reason, Date.now())) return false;
  await checkPublicRecord(databasePath);
  return true;
}

// "Details": the evidence, where each proof was filed and where it landed.
export async function loadTrustDetails(databasePath: string): Promise<TrustDetails[]> {
  return parseTrustDetails(await trust_alarm_details_export(utf8(databasePath)));
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
  const summary = await inspectDeviceSet(databasePath, wire);
  await renewDevices(databasePath, wire);
  return { wire, summary };
}

// Credentials, signed prekeys and ML-KEM prekeys are renewed through the
// directory well before they expire; on the device holding the account key
// that includes answering linked devices that asked. The core decides from the
// verified set, taking on first whatever the set shows of this device. Each
// registration is the next transition of the set, so they go in order, and a
// refusal or an outage ends the pass: the next pass starts again from the set
// the directory shows then.
export async function renewDevices(databasePath: string, deviceSet: Uint8Array): Promise<void> {
  const registrations = parseByteList(
    await renew_devices_export(vectors(utf8(databasePath), deviceSet)),
    8,
    65_536,
  );
  for (const registration of registrations) {
    try {
      await binaryRequest('/v1/devices/register', registration, 'PUT');
    } catch (error) {
      if (error instanceof ServerStatusError && error.status === 410) throw new RemovedFromAccount(error.body);
      if (error instanceof ServerStatusError) return;
      throw error;
    }
  }
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
  // A priced inbox hands its contact address to new group members first.
  await creditHooks.beforeDrain(databasePath).catch(() => {});
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
        // A priced inbox (402 with its signed price): pay it, or give up on
        // this envelope if the person said no.
        if (error instanceof ServerStatusError && error.status === 402) {
          const postage = await creditHooks.postage(databasePath, envelope, error.body);
          if (postage === 'paid') {
            await outbox_ack_export(batchRequest(databasePath, envelope));
            continue;
          }
          if (postage === 'declined') {
            await outbox_fail_export(batchRequest(databasePath, envelope));
            for (const listener of undeliverableListeners) {
              try { listener({ status: 402, queuedAt: envelopeQueuedAt(envelope) }); } catch { /* Reporting is best effort. */ }
            }
            continue;
          }
        } else if (!(error instanceof ServerStatusError) || error.status !== 429) {
          throw error;
        }
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
  const keyPackage = await withAnchorProofs(databasePath, () => group_key_package_export(utf8(databasePath)));
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
  await withAnchorProofs(databasePath, () => group_add_export(vectors(utf8(databasePath), groupId, deviceSet, keyPackage)));
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

export async function sendGroupViewOnce(
  databasePath: string,
  groupId: Uint8Array,
  body: string,
  attachment?: Uint8Array,
): Promise<void> {
  await refreshGroupAuthorizations(databasePath, groupId);
  await group_send_view_once_export(vectors(utf8(databasePath), groupId, utf8(body), ...(attachment ? [attachment] : [])));
  await drainOutbox(databasePath);
}

// Every member applies the group's disappearing-message timer (Mobile.GroupTimer).
export async function setGroupTimer(databasePath: string, groupId: Uint8Array, seconds: number): Promise<void> {
  await refreshGroupAuthorizations(databasePath, groupId);
  await group_timer_export(vectors(utf8(databasePath), groupId, writeU32(seconds)));
  await drainOutbox(databasePath);
}

export type OutgoingAttachment = {
  filename: string;
  mimeType: string;
  size: number;
  // Up to `length` of the file's bytes from `offset`: files are uploaded one
  // 64 KiB chunk at a time, so a large one is never held whole.
  read: (offset: number, length: number) => Promise<Uint8Array>;
  // Small files are also kept whole, for previews and to reopen once sent.
  bytes?: Uint8Array;
  // Lets go of what the picker kept for reading the file later.
  release?: () => void;
};

// The device's credits pay for files over 16 MB. Whatever holds them installs
// the source; until then the device has none. A take is settled once the store
// has answered: spent, returned (false), or unknown (undefined: the store may
// have redeemed them before the answer was lost).
export type CreditTokens = { tokens: Uint8Array; settle: (spent: boolean | undefined) => Promise<void> };
export type CreditSource = { balance: () => Promise<number>; take: (count: number) => Promise<CreditTokens> };
let creditSource: CreditSource = {
  balance: async () => 0,
  take: async (count) => { throw new Error(creditShortfall(count, 0)); },
};

export function setCreditSource(source: CreditSource): void {
  creditSource = source;
}

// The device's credits for everything else (credits.ts installs them): the
// postage a priced inbox asks, the price a first message will cost, a busy
// sign-up, and handing a priced inbox's contact address to its groups.
export type CreditHooks = {
  // A 402 from the edge with the recipient's signed price: sent with credits,
  // refused by the person, or left waiting.
  postage: (databasePath: string, envelope: Uint8Array, policy: Uint8Array) => Promise<'paid' | 'declined' | 'waiting'>;
  // Devices of a first contact ask a price (Mobile.CreditsSpend's quote frame):
  // false stops the send.
  firstContact: (databasePath: string, username: string, priced: Uint8Array) => Promise<boolean>;
  // A registration answered 429 with WRK: what to send instead, and how the
  // answer settles any credits it carries.
  busySignup: (databasePath: string, work: Uint8Array) => Promise<{ body: Uint8Array; settle?: (status: number) => Promise<void> }>;
  beforeDrain: (databasePath: string) => Promise<void>;
};
let creditHooks: CreditHooks = {
  postage: async () => 'waiting',
  firstContact: async () => true,
  // The free way past a busy sign-up: the same registration, worked at the difficulty asked.
  busySignup: async (databasePath, work) =>
    ({ body: await credits_register_at_export(vectors(utf8(databasePath), work.subarray(4, 5))) }),
  beforeDrain: async () => {},
};

export function setCreditHooks(hooks: Partial<CreditHooks>): void {
  creditHooks = { ...creditHooks, ...hooks };
}

// Registration's 429 names the difficulty needed now: u8 1 || "WRK" || u8 difficulty || u8 credits.
const isSignupWork = (body: Uint8Array): boolean =>
  body.length === 6 && body[0] === 1 && body[1] === 0x57 && body[2] === 0x52 && body[3] === 0x4b;

export const creditBalance = (): Promise<number> => creditSource.balance();

// What a paid grant's answer means for its tokens, and for the person.
function paidGrantFailure(error: unknown): { spent: boolean | undefined; message?: string } {
  const status = error instanceof ServerStatusError ? error.status : 0;
  if (status === 409) return { spent: true, message: 'Those credits were already used. Send the file again.' };
  if (status === 422) return { spent: true, message: 'Those credits were not accepted. Send the file again.' };
  if (status === 402) return { spent: false, message: 'This file needs more credits than were sent with it.' };
  if (status === 403) return { spent: false, message: 'This server does not take files over 16 MB yet.' };
  if (status === 400 || status === 429) return { spent: false };
  return { spent: undefined };
}

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
export function objectWorkDifficulty(): number {
  const configured = process.env.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY || '16';
  const value = Number(configured);
  if (!/^\d+$/.test(configured) || value < 1 || value > 24) {
    throw new Error('EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY must be between 1 and 24');
  }
  return value;
}

export const objectRequest = (path: string, body: Uint8Array, method = 'POST', capability?: Uint8Array): Promise<Uint8Array> =>
  binaryRequest(path, body, method, objectUrl, capability ? { 'X-Object-Capability': hex(capability) } : {});

export function describeAttachmentLimit(size: number): string | undefined {
  return attachmentSelectionError([size]);
}

// Encrypts and uploads one file: the sealed manifest is part 0 and each 64 KiB
// chunk follows, read from the file as it goes. The core pads the file to a size
// bucket, so the last chunks may hold only padding and are sealed from nothing.
// A file over 16 MB brings the credits its bucket costs in its grant. The object
// is completed only once every part is stored.
export async function uploadAttachment(
  databasePath: string,
  file: OutgoingAttachment,
  onProgress?: TransferProgress,
): Promise<UploadedAttachment> {
  const limit = describeAttachmentLimit(file.size);
  if (limit) throw new Error(limit);
  const cost = attachmentCreditCost(file.size);
  const credits = cost ? await creditSource.take(cost) : undefined;
  let prepared: Uint8Array[];
  try {
    prepared = parseByteList(
      await attachment_prepare_export(vectors(
        utf8(databasePath), utf8(file.filename), utf8(file.mimeType), writeU32(file.size), writeU32(objectWorkDifficulty()),
        ...(credits ? [credits.tokens] : []),
      )),
      8,
      // A paid grant carries up to 31 tokens of 354 bytes.
      16_384,
    );
  } catch (error) {
    await credits?.settle(false);
    throw error;
  }
  const [reference, objectId, uploadCapability, grant, complete, remove, manifest, chunks] = prepared;
  const chunkCount = chunks?.length === 4 ? new DataView(chunks.buffer, chunks.byteOffset, 4).getUint32(0) : 0;
  if (!reference || !objectId || !uploadCapability || !grant || !complete || !remove || !manifest ||
    objectId.length !== 32 || uploadCapability.length !== 32 ||
    chunkCount < Math.ceil(file.size / ATTACHMENT_CHUNK_SIZE) || chunkCount > MAXIMUM_ATTACHMENT_SIZE / ATTACHMENT_CHUNK_SIZE) {
    await credits?.settle(false);
    throw new Error('Mesh returned an invalid attachment');
  }
  const discard = async (): Promise<void> => { await objectRequest('/v1/attachments/delete', remove); };
  const parts = `/v1/objects/${hex(objectId)}/parts/`;
  try {
    await objectRequest('/v1/attachments/grant', grant);
  } catch (error) {
    if (!credits) throw error;
    const failure = paidGrantFailure(error);
    await credits.settle(failure.spent);
    throw failure.message ? new Error(failure.message) : error;
  }
  await credits?.settle(true);
  try {
    await objectRequest(`${parts}0`, manifest, 'PUT', uploadCapability);
    for (let index = 0; index < chunkCount; index += 1) {
      const offset = index * ATTACHMENT_CHUNK_SIZE;
      const chunk = offset < file.size ? await file.read(offset, Math.min(ATTACHMENT_CHUNK_SIZE, file.size - offset)) : new Uint8Array();
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
  const error = attachmentSelectionError(files.map((file) => file.size));
  if (error) throw new Error(error);
  // Every file's credits are there before the first one uploads.
  const cost = files.reduce((total, file) => total + attachmentCreditCost(file.size), 0);
  const shortfall = cost ? creditShortfall(cost, await creditBalance()) : undefined;
  if (shortfall) throw new Error(shortfall);
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

// Fetches and decrypts every chunk of a received attachment in order, handing
// each to `write` as it opens, so a large file never has to be held whole.
export async function streamAttachment(
  databasePath: string,
  attachment: AttachmentSummary,
  write: (chunk: Uint8Array) => void | Promise<void>,
  onProgress?: TransferProgress,
): Promise<void> {
  const parts = `/v1/objects/${hex(attachment.objectId)}/parts/`;
  let offset = 0;
  for (let index = 0; index < attachment.chunkCount; index += 1) {
    const sealed = await objectRequest(`${parts}${index + 1}`, new Uint8Array(), 'GET', attachment.downloadCapability);
    const chunk = await attachment_open_chunk_export(vectors(utf8(databasePath), attachment.reference, writeU32(index), sealed));
    if (offset + chunk.length > attachment.size) throw new Error('The attachment does not match its manifest');
    await write(chunk);
    offset += chunk.length;
    onProgress?.(index + 1, attachment.chunkCount);
  }
  if (offset !== attachment.size) throw new Error('The attachment does not match its manifest');
}

// The same, into one buffer.
export async function downloadAttachment(
  databasePath: string,
  attachment: AttachmentSummary,
  onProgress?: TransferProgress,
): Promise<Uint8Array> {
  const output = new Uint8Array(attachment.size);
  let offset = 0;
  await streamAttachment(databasePath, attachment, (chunk) => { output.set(chunk, offset); offset += chunk.length; }, onProgress);
  return output;
}

// Forgets a group on this device alone: its state, keys, history and records.
export async function forgetGroup(databasePath: string, groupId: Uint8Array): Promise<void> {
  await group_forget_export(vectors(utf8(databasePath), groupId));
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
    // Devices that ask a price for message requests say so in their claim
    // answer. Asking first is a courtesy: the edge's 402 is what enforces a
    // price, so a core that can't answer here doesn't hold the send up.
    const priced = await credits_postage_quote_export(vectors(utf8(databasePath), peerSet))
      .catch(() => Uint8Array.of(0));
    if (priced[0] && !(await creditHooks.firstContact(databasePath, peerUsername, priced))) {
      throw new Error('postage_declined');
    }
    await withAnchorProofs(databasePath, () => send(
      vectors(
        utf8(databasePath),
        peerSet,
        localSet,
        body,
        ...(attachment ? [attachment] : []),
      ),
    ));
    await drainOutbox(databasePath);
    // A contact's keys changed: check the public record (at most hourly).
    if (peerSummary.changed) void schedulePublicRecordCheck(databasePath, 'key-change').catch(() => {});
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

// A view-once message (Mobile.ViewOnce): it goes to the peer's devices only, and
// this device keeps a stub without its content.
export function sendViewOnce(
  databasePath: string,
  username: string,
  body: string,
  expectedAccountId?: Uint8Array,
  attachment?: Uint8Array,
): Promise<boolean> {
  return sendWithDevices(databasePath, username, utf8(body), send_view_once_export, expectedAccountId, attachment);
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
        await withAnchorProofs(databasePath, () =>
          group_invitation_complete_export(vectors(utf8(databasePath), devices, invitation.reference)));
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
  if (!(await receiveMailboxPass(databasePath))) return;
  // A group welcome can wait on a group anchor this device has not proven yet:
  // fetch those proofs and take one more pass.
  if ((await supplyAnchorProofs(databasePath)) > 0 && !(await receiveMailboxPass(databasePath))) return;
  throw new Error('Message processing is pending. Retrying…');
}

// Says whether Mesh set anything aside for later.
async function receiveMailboxPass(databasePath: string): Promise<boolean> {
  let setAside = false;
  let asked: string | undefined;
  // 1,024 batches is twice what the largest mailbox holds.
  for (let batches = 0; batches < 1_024; batches += 1) {
    const fetchRequest = await mailbox_fetch_export(utf8(databasePath));
    const batch = await obliviousRequest('/v1/mailbox/fetch', fetchRequest);
    const acknowledgement = await process_delivery_batch_export(batchRequest(databasePath, batch));
    if (acknowledgement.length > 0) await obliviousRequest('/v1/mailbox/ack', acknowledgement);
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
  return setAside;
}

export function synchronizeMailbox(databasePath: string): Promise<void> {
  return synchronizeMailboxByDatabase(databasePath, async () => {
    // A failed submission must not prevent receiving already-delivered messages.
    const results = await Promise.allSettled([
      receiveMailbox(databasePath), drainOutbox(databasePath), synchronizePrekeys(databasePath),
    ]);
    results.push(...await Promise.allSettled([
      completeGroupInvitations(databasePath),
      // Gossip only adds evidence: it never holds up the mailbox.
      exchangeCheckpoints(databasePath).catch(() => {}).then(() => drainOutbox(databasePath)),
    ]));
    const failure = results.find((result) => result.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
  });
}
