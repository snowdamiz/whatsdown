import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import {
  credit_postage_candidate_export, credit_postage_preview_export, credit_postage_prepare_export,
  credit_postage_recover_export, credit_postage_continue_export, credit_postage_inventory_export,
  postage_policy_view_export, postage_policy_prepare_export, postage_policy_publish_export,
} from '../modules/mesh-messenger';
import { resolveDeviceSet } from './network';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((n, i) => n === b[i]);
const hex = (bytes: Uint8Array) => Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
const key = (bytes: Uint8Array, length = 32) => bytes.length === length && bytes.some(n => n !== 0);
function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}
function packet(...values: Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(4 + values.reduce((n, value) => n + 4 + value.length, 0));
  bytes.set(u32(values.length));
  let at = 4;
  for (const value of values) {
    bytes.set(u32(value.length), at); at += 4;
    bytes.set(value, at); at += value.length;
  }
  return bytes;
}
const request = (database: string, ...values: Uint8Array[]) => packet(encoder.encode(database), ...values);
function fields(input: Uint8Array, maximum: number): Uint8Array[] {
  if (input.length < 4 || input.length > 800_000) throw Error('invalid_postage_response');
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const count = view.getUint32(0);
  if (count > maximum) throw Error('invalid_postage_response');
  const values: Uint8Array[] = [];
  let at = 4;
  for (let i = 0; i < count; i++) {
    if (at + 4 > input.length) throw Error('invalid_postage_response');
    const size = view.getUint32(at); at += 4;
    if (size > input.length - at) throw Error('invalid_postage_response');
    values.push(input.slice(at, at + size)); at += size;
  }
  if (at !== input.length) throw Error('invalid_postage_response');
  return values;
}
function number(value: Uint8Array, size: number): number {
  if (value.length !== size) throw Error('invalid_postage_response');
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  return size === 1 ? value[0]! : size === 2 ? view.getUint16(0) : view.getUint32(0);
}
function wide(value: Uint8Array): bigint {
  if (value.length !== 8) throw Error('invalid_postage_response');
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(0);
}
function username(value: Uint8Array): string {
  const name = decoder.decode(value);
  if (!/^[a-z0-9._-]{1,64}$/.test(name)) throw Error('invalid_postage_response');
  return name;
}
function ids(value: Uint8Array): Uint8Array[] {
  const list = fields(value, 8);
  if (!list.length || list.some(id => !key(id, 16)) || new Set(list.map(hex)).size !== list.length)
    throw Error('invalid_postage_response');
  return list;
}
function origin(value: Uint8Array): string {
  const host = decoder.decode(value), url = new URL(host);
  if (url.protocol !== 'https:' || url.origin !== host) throw Error('invalid_postage_response');
  return host;
}
function credits(value: Uint8Array, bytes = 2): number {
  const count = number(value, bytes);
  if (![0, 1, 5, 25].includes(count)) throw Error('invalid_postage_response');
  return count;
}
function purpose(value: Uint8Array): 'live' | 'test' {
  const selected = number(value, 1);
  if (selected > 1) throw Error('invalid_postage_response');
  return selected === 0 ? 'live' : 'test';
}
export type PostageCandidate = {
  accountId: Uint8Array;
  username: string;
  messageId: Uint8Array;
  triggerId: Uint8Array;
};
export type PostagePreview = PostageCandidate & {
  nonce: Uint8Array;
  ids: Uint8Array[];
  policyRevision: bigint;
  deviceSetRevision: bigint;
  credits: number;
  purpose: 'live' | 'test';
  available: number;
  reserved: number;
  witnessedDeviceSet: Uint8Array;
};
export type PostagePlan = {
  nonce: Uint8Array;
  operationId: Uint8Array;
  status: 0 | 1 | 2;
  credits: number;
  revision: bigint;
  origin: string;
  path: string;
  body: Uint8Array;
};
function plan(input: Uint8Array): PostagePlan {
  const f = fields(input, 9);
  if (f.length !== 9 || decoder.decode(f[0]) !== '\u0001MPS' || !key(f[1]!) || !key(f[2]!))
    throw Error('invalid_postage_response');
  const status = number(f[3]!, 1), path = decoder.decode(f[7]), body = f[8]!;
  if (status > 2 || (status === 0 ? !['/v1/credits/postage', '/v1/credits/postage/reconcile'].includes(path) || !body.length : path !== '' || body.length !== 0))
    throw Error('invalid_postage_response');
  const count = credits(f[4]!);
  if (count === 0)
    throw Error('invalid_postage_response');
  return { nonce: f[1]!, operationId: f[2]!, status: status as 0 | 1 | 2, credits: count, revision: wide(f[5]!), origin: origin(f[6]!), path, body };
}
export type PostageRecord = {
  nonce: Uint8Array;
  messageId: Uint8Array;
  accountId: Uint8Array;
  username: string;
  operationId: Uint8Array;
  status: 0 | 1 | 2 | 3;
  credits: number;
  expiresAt: bigint;
  ids: Uint8Array[];
};
export type PostagePolicy = {
  accountId: Uint8Array;
  revision: bigint;
  deviceSetRevision: bigint;
  credits: number;
  pending?: PostagePolicyPlan;
};
export type PostagePolicyPlan = Pick<PostagePolicy, 'accountId' | 'revision' | 'deviceSetRevision' | 'credits'> & {
  origin: string;
  path: string;
  body: Uint8Array;
};
function policyPlan(input: Uint8Array): PostagePolicyPlan {
  const f = fields(input, 8);
  if (f.length !== 8 || decoder.decode(f[0]) !== '\u0001MPP' || !key(f[1]!) || decoder.decode(f[6]) !== '/v1/credits/postage-policy' || !f[7]!.length || f[7]!.length > 512)
    throw Error('invalid_postage_response');
  return { accountId: f[1]!, revision: wide(f[2]!), deviceSetRevision: wide(f[3]!), credits: credits(f[4]!, 1), origin: origin(f[5]!), path: decoder.decode(f[6]), body: f[7]! };
}
export function createPostageServices(deps: Pick<ScopedClient, 'runPrivate' | 'credit_postage_candidate_export' | 'credit_postage_continue_export' | 'credit_postage_inventory_export' | 'credit_postage_prepare_export' | 'credit_postage_preview_export' | 'credit_postage_recover_export' | 'onDispose' | 'postage_policy_prepare_export' | 'postage_policy_publish_export' | 'postage_policy_view_export'> & { resolveDeviceSet: typeof resolveDeviceSet }) {
const { credit_postage_candidate_export, credit_postage_preview_export, credit_postage_prepare_export, credit_postage_recover_export, credit_postage_continue_export, credit_postage_inventory_export, postage_policy_view_export, postage_policy_prepare_export, postage_policy_publish_export, resolveDeviceSet } = deps;
async function readPostageCandidate(database: string, trigger: Uint8Array): Promise<PostageCandidate> {
  if (!key(trigger, 16))
    throw Error('invalid_postage_request');
  const f = fields(await credit_postage_candidate_export(request(database, trigger)), 5);
  if (f.length !== 5 || decoder.decode(f[0]) !== '\u0001MPC' || !key(f[1]!) || !key(f[3]!, 16) || !equal(f[4]!, trigger))
    throw Error('invalid_postage_response');
  return { accountId: f[1]!, username: username(f[2]!), messageId: f[3]!, triggerId: f[4]! };
}
async function previewPostage(database: string, trigger: Uint8Array): Promise<PostagePreview> {
  const candidate = await readPostageCandidate(database, trigger);
  const witnessedDeviceSet = await resolveDeviceSet(database, '@' + hex(candidate.accountId));
  const f = fields(await credit_postage_preview_export(request(database, witnessedDeviceSet, trigger)), 13);
  if (f.length !== 13 || decoder.decode(f[0]) !== '\u0001MPB' || !key(f[1]!) || !equal(f[2]!, candidate.accountId) || username(f[3]!) !== candidate.username || !equal(f[4]!, candidate.messageId) || !equal(f[5]!, trigger))
    throw Error('invalid_postage_response');
  const count = credits(f[9]!);
  if (count === 0)
    throw Error('invalid_postage_response');
  const selected = ids(f[6]!);
  if (!selected.some(id => equal(id, trigger)))
    throw Error('invalid_postage_response');
  return { ...candidate, nonce: f[1]!, ids: selected, policyRevision: wide(f[7]!), deviceSetRevision: wide(f[8]!), credits: count, purpose: purpose(f[10]!), available: number(f[11]!, 4), reserved: number(f[12]!, 4), witnessedDeviceSet };
}
async function preparePostage(database: string, preview: PostagePreview) {
  const value = plan(await credit_postage_prepare_export(request(database, preview.nonce, preview.witnessedDeviceSet, packet(...preview.ids))));
  if (!equal(value.nonce, preview.nonce) || value.credits !== preview.credits)
    throw Error('invalid_postage_response');
  return value;
}
async function recoverPostage(database: string, nonce: Uint8Array) {
  if (!key(nonce))
    throw Error('invalid_postage_request');
  const value = plan(await credit_postage_recover_export(request(database, nonce)));
  if (!equal(value.nonce, nonce))
    throw Error('invalid_postage_response');
  return value;
}
async function continuePostage(database: string, nonce: Uint8Array) {
  if (!key(nonce)) throw Error('invalid_postage_request');
  const after = plan(await credit_postage_continue_export(request(database, nonce)));
  if (!equal(after.nonce, nonce) || after.status === 0) throw Error('invalid_postage_response');
  return after;
}
async function readPostages(database: string) {
  const f = fields(await credit_postage_inventory_export(request(database)), 147);
  if (f.length < 3 || decoder.decode(f[0]) !== '\u0001MPI')
    throw Error('invalid_postage_response');
  const items = f.slice(3).map(bytes => { const r = fields(bytes, 9); if (r.length !== 9 || !key(r[0]!) || !key(r[1]!, 16) || !key(r[2]!) || !key(r[4]!))
    throw Error('invalid_postage_response'); const status = number(r[5]!, 1), count = credits(r[6]!); if (status > 3 || count === 0)
    throw Error('invalid_postage_response'); return { nonce: r[0]!, messageId: r[1]!, accountId: r[2]!, username: username(r[3]!), operationId: r[4]!, status: status as 0 | 1 | 2 | 3, credits: count, expiresAt: wide(r[7]!), ids: ids(r[8]!) }; });
  if (new Set(items.map(item => hex(item.nonce))).size !== items.length)
    throw Error('invalid_postage_response');
  return { revision: wide(f[1]!), purpose: purpose(f[2]!), items };
}
async function readPostagePolicy(database: string, account: Uint8Array): Promise<PostagePolicy> {
  if (!key(account))
    throw Error('invalid_postage_request');
  await resolveDeviceSet(database, '@' + hex(account));
  const f = fields(await postage_policy_view_export(request(database, account)), 6);
  const tag = decoder.decode(f[0]);
  if (!((f.length === 5 && tag === '\u0001MPV') || (f.length === 6 && tag === '\u0002MPV')) || !equal(f[1]!, account))
    throw Error('invalid_postage_response');
  const value = { accountId: account, revision: wide(f[2]!), deviceSetRevision: wide(f[3]!), credits: credits(f[4]!, 1) };
  const pending = f[5]?.length ? policyPlan(f[5]) : undefined;
  if (pending && (!equal(pending.accountId, account) || pending.revision <= value.revision || pending.deviceSetRevision !== value.deviceSetRevision)) throw Error('invalid_postage_response');
  return { ...value, pending };
}
async function preparePostagePolicy(database: string, level: number): Promise<PostagePolicyPlan> {
  if (![0, 1, 5, 25].includes(level)) throw Error('invalid_postage_request');
  const value = policyPlan(await postage_policy_prepare_export(request(database, Uint8Array.of(level))));
  if (value.credits !== level) throw Error('invalid_postage_response');
  return value;
}
async function publishPostagePolicy(database: string, value: PostagePolicyPlan) {
  if (![0, 1, 5, 25].includes(value.credits) || value.revision < 1n || value.revision > 0xffffffffffffffffn || value.deviceSetRevision < 0n || value.deviceSetRevision > 0xffffffffffffffffn)
    throw Error('invalid_postage_request');
  const revision = new Uint8Array(8), deviceRevision = new Uint8Array(8);
  new DataView(revision.buffer).setBigUint64(0, value.revision);
  new DataView(deviceRevision.buffer).setBigUint64(0, value.deviceSetRevision);
  await postage_policy_publish_export(request(database, revision, deviceRevision, Uint8Array.of(value.credits)));
  const admitted = await readPostagePolicy(database, value.accountId);
  if (admitted.revision < value.revision || admitted.deviceSetRevision <= value.deviceSetRevision || admitted.credits !== value.credits)
    throw Error('postage_policy_not_witnessed');
  return admitted;
}
return Object.freeze({
  readPostageCandidate: (...args: Parameters<typeof readPostageCandidate>) => deps.runPrivate(() => readPostageCandidate(...args)),
  previewPostage: (...args: Parameters<typeof previewPostage>) => deps.runPrivate(() => previewPostage(...args)),
  preparePostage: (...args: Parameters<typeof preparePostage>) => deps.runPrivate(() => preparePostage(...args)),
  recoverPostage: (...args: Parameters<typeof recoverPostage>) => deps.runPrivate(() => recoverPostage(...args)),
  continuePostage: (...args: Parameters<typeof continuePostage>) => deps.runPrivate(() => continuePostage(...args)),
  readPostages: (...args: Parameters<typeof readPostages>) => deps.runPrivate(() => readPostages(...args)),
  readPostagePolicy: (...args: Parameters<typeof readPostagePolicy>) => deps.runPrivate(() => readPostagePolicy(...args)),
  preparePostagePolicy: (...args: Parameters<typeof preparePostagePolicy>) => deps.runPrivate(() => preparePostagePolicy(...args)),
  publishPostagePolicy: (...args: Parameters<typeof publishPostagePolicy>) => deps.runPrivate(() => publishPostagePolicy(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createPostageServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createPostageServices({ runPrivate: operation => operation(), onDispose: () => () => {}, credit_postage_candidate_export, credit_postage_preview_export, credit_postage_prepare_export, credit_postage_recover_export, credit_postage_continue_export, credit_postage_inventory_export, postage_policy_view_export, postage_policy_prepare_export, postage_policy_publish_export, resolveDeviceSet });
}
export const readPostageCandidate: ReturnType<typeof createPostageServices>['readPostageCandidate'] = (...args) => desktopCompatibility().readPostageCandidate(...args);
export const previewPostage: ReturnType<typeof createPostageServices>['previewPostage'] = (...args) => desktopCompatibility().previewPostage(...args);
export const preparePostage: ReturnType<typeof createPostageServices>['preparePostage'] = (...args) => desktopCompatibility().preparePostage(...args);
export const recoverPostage: ReturnType<typeof createPostageServices>['recoverPostage'] = (...args) => desktopCompatibility().recoverPostage(...args);
export const continuePostage: ReturnType<typeof createPostageServices>['continuePostage'] = (...args) => desktopCompatibility().continuePostage(...args);
export const readPostages: ReturnType<typeof createPostageServices>['readPostages'] = (...args) => desktopCompatibility().readPostages(...args);
export const readPostagePolicy: ReturnType<typeof createPostageServices>['readPostagePolicy'] = (...args) => desktopCompatibility().readPostagePolicy(...args);
export const preparePostagePolicy: ReturnType<typeof createPostageServices>['preparePostagePolicy'] = (...args) => desktopCompatibility().preparePostagePolicy(...args);
export const publishPostagePolicy: ReturnType<typeof createPostageServices>['publishPostagePolicy'] = (...args) => desktopCompatibility().publishPostagePolicy(...args);
